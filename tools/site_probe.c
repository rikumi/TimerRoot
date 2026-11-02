/* site_probe.c -- dump the runtime call sites the kernel records in tracefs.
 *
 * calibrate_base() compares only the low 21 bits of a conf's timer_site, and
 * fake mode needs the full link-time value because g_slide = site0 -
 * timer_site feeds every symbol address.  When a profile is being ported this
 * prints the raw call_site values (call site = bl + 4) so the low 21 bits can
 * be read off directly, and the distance between two known sites can be used
 * as a cross-check.
 *
 * It forks a few children to make copy_process run, reads tracefs and prints
 * the observed sites.  It never triggers the UAF, so it is safe to run
 * repeatedly and needs no reboot afterwards.
 *
 * Build (NDK r27):
 *   NDK=~/Library/Android/sdk/ndk/27.2.12479018
 *   $NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang \
 *       --target=aarch64-linux-android30 -O2 -static -o site_probe site_probe.c
 *
 * Run:
 *   adb push site_probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/site_probe
 *   adb shell /data/local/tmp/site_probe
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#define TR "/sys/kernel/tracing"
#define PAGE 4096UL

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static unsigned u32(const unsigned char *b, size_t o){ unsigned v; memcpy(&v,b+o,4); return v; }
static unsigned long long u64(const unsigned char *b, size_t o){ unsigned long long v; memcpy(&v,b+o,8); return v; }
static int is_kp(unsigned long long v){ return (v >> 48) == 0xffffULL; }

static void drain(int cpu)
{
    unsigned char tmp[65536]; char p[128];
    snprintf(p,sizeof(p),TR "/per_cpu/cpu%d/trace_pipe_raw",cpu);
    int fd = open(p, O_RDONLY|O_NONBLOCK);
    if (fd<0) return;
    while (read(fd,tmp,sizeof(tmp))>0);
    close(fd);
}
static long rd(int cpu, unsigned char *b, size_t cap)
{
    char p[128]; size_t tot=0;
    snprintf(p,sizeof(p),TR "/per_cpu/cpu%d/trace_pipe_raw",cpu);
    int fd = open(p, O_RDONLY|O_NONBLOCK);
    if (fd<0) return -1;
    while (tot<cap){ ssize_t r=read(fd,b+tot,cap-tot); if(r<=0) break; tot+=r; }
    close(fd);
    return (long)tot;
}

int main(void)
{
    unsigned char *raw = malloc(32u<<20);
    setvbuf(stdout,NULL,_IONBF,0);

    wr(TR "/tracing_on","0");
    wr(TR "/trace","\n");
    for (int c=0;c<8;c++) drain(c);
    wr(TR "/events/kmem/rss_stat/trigger","enable_event:kmem:kmem_cache_alloc\n");
    wr(TR "/tracing_on","1");

    /* 触发 copy_process 相关分配 */
    for (int i=0;i<40;i++){
        pid_t p = fork();
        if (p==0){ _exit(0); }
        int st; waitpid(p,&st,0);
    }
    usleep(50000);
    wr(TR "/tracing_on","0");

    /* 打印所有出现的 call site 及其计数(全部 CPU) */
    struct { unsigned long long site; int cnt; } seen[512];
    int ns=0;
    for (int cpu=0;cpu<8;cpu++){
        long n = rd(cpu, raw, 32u<<20);
        if (n<=0) continue;
        for (size_t i=8;i+32<=(size_t)n;i+=4){
            if (u32(raw,i-4)!=(unsigned)getpid()) continue;
            unsigned long long site=u64(raw,i), ptr=u64(raw,i+8);
            if (!is_kp(ptr)) continue;
            int f=0;
            for (int k=0;k<ns;k++) if (seen[k].site==site){ seen[k].cnt++; f=1; break; }
            if (!f && ns<512){ seen[ns].site=site; seen[ns].cnt=1; ns++; }
        }
    }
    printf("=== 本进程 kmem_cache_alloc call sites (运行时地址) ===\n");
    for (int k=0;k<ns;k++)
        printf("  site=%#llx low21=%#llx cnt=%d\n", seen[k].site,
               seen[k].site & 0x1fffffULL, seen[k].cnt);

    /* 也打印所有 pid 的, 便于识别 copy_process / do_timer_create */
    ns=0;
    for (int cpu=0;cpu<8;cpu++){
        long n = rd(cpu, raw, 32u<<20);
        if (n<=0) continue;
        for (size_t i=8;i+32<=(size_t)n;i+=4){
            unsigned long long site=u64(raw,i), ptr=u64(raw,i+8);
            if (!is_kp(ptr)) continue;
            int f=0;
            for (int k=0;k<ns;k++) if (seen[k].site==site){ seen[k].cnt++; f=1; break; }
            if (!f && ns<512){ seen[ns].site=site; seen[ns].cnt=1; ns++; }
        }
    }
    printf("=== 所有 pid 的 call sites ===\n");
    for (int k=0;k<ns;k++)
        printf("  site=%#llx low21=%#llx cnt=%d\n", seen[k].site,
               seen[k].site & 0x1fffffULL, seen[k].cnt);
    return 0;
}
