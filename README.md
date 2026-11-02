# TimerRoot
<img width="1216" height="2640" alt="1000008015" src="https://github.com/user-attachments/assets/22767c69-ab6d-4b14-b8ab-add3447c3ef2" />

Android front end for **CVE-2026-98260** (POSIX CPU timer use-after-free), the
same class of bug as CVE-2026-64560. One tap gives you a root shell and then
late-loads **KernelSU** (`u:r:ksu:s0`).

The exploit source is included (`native/timer.c`, conf-driven) and compiled to
`app/src/main/assets/timer`. This repository is the app shell around it: UI,
state detection and the Shizuku plumbing needed to run a shell-domain exploit
from an ordinary app. The device constants live in per-kernel HOCON conf files
(`conf/*.conf`), selected at runtime by `uname -r`.

## Why the app needs Shizuku

An app runs as `untrusted_app` and cannot read `/sys/kernel/tracing`, which the
exploit needs for its leak and trigger. TimerRoot therefore starts a **Shizuku
user service**, which Shizuku runs as the shell user (`uid 2000`,
`u:r:shell:s0`). The exploit binary executes inside that process, so it gets
the same environment it would have from `adb shell`.

```
MainActivity (untrusted_app)
  └─ Shizuku user service (uid 2000, u:r:shell:s0)
       ├─ extracts assets/timer to /data/local/tmp/timer
       └─ runs it; on success keeps /system/bin/sh alive
```

## Requirements

- Android 12+ (`minSdk 30`), arm64
- [Shizuku](https://shizuku.rikka.app/) running (start it from the Shizuku app
  via wireless debugging, or over ADB)
- [KernelSU](https://github.com/tiann/KernelSU) manager installed, for the
  `Load KernelSU` path
- A supported kernel build (exact `uname -r` match):
  `6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`,
  `6.12.69-android16-6-g242e1a07f878-ab15865446-4k`, or
  `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`. See `conf/`.

## Native and conf

The exploit is a single-file C program (`native/timer.c`) that reads a HOCON
conf (`conf/*.conf`) for the device constants. Rebuild it with the NDK:

```bash
ANDROID_NDK_HOME=/path/to/ndk make -C native
cp native/timer app/src/main/assets/timer
```

`app/src/main/assets/timer` and `app/src/main/assets/conf/*.conf` are already
committed, so a fresh clone builds the APK without extra steps.

The binary is MIT licensed by its authors; only use it on hardware you own, and
only when your kernel matches the build it was ported to.

## Build

### Android Studio / Gradle

Open the project and build, or:

```bash
./gradlew assembleDebug
```

The project needs the Android SDK with platform 36 and build-tools 36. The
Shizuku API is pulled from Maven (`dev.rikka.shizuku:api`).

### Without Gradle

`scripts/build.ps1` builds and signs an APK with just the SDK, `javac`, `d8`,
`aapt2` and `apksigner`. It vendors nothing: it compiles the app together with
the Shizuku API sources, so clone those first:

```powershell
git clone https://github.com/RikkaApps/Shizuku-API
scripts/build.ps1 -Sdk "C:\Users\<you>\AppData\Local\Android\Sdk"
```

## Usage

### 1. Start Shizuku

Shizuku has to be running before TimerRoot can do anything: it is the process
that provides the shell user the exploit needs. Shizuku stops on every reboot,
so this is the first step each time.

**Wireless debugging (no PC after the first pairing)**

1. Enable developer options: Settings -> About device -> tap *Build number* 7x.
2. Settings -> System -> Developer options -> **Wireless debugging** -> on.
3. Open the Shizuku app -> **Start** -> *Start via wireless debugging*.
4. Allow the notification, then in *Pair device with pairing code* enter the
   6-digit code shown on the phone.
5. Shizuku reports "Shizuku is running" (the notification says the server is up).

**Over USB**

With the phone connected and USB debugging authorised:

```bash
adb shell sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh
```

Newer Shizuku releases may not ship that script any more; if it is missing, use
the wireless debugging route above.

Check that the server is up:

```bash
adb shell ps -A | grep shizuku_server
# shell  12345  1  ...  shizuku_server
```

`ps` showing only `moe.shizuku.privileged.api` means the manager app is open but
the server is **not** running; the exploit cannot start until it is.

### 2. First launch

1. Open TimerRoot.
2. When Shizuku asks *Allow TimerRoot to access Shizuku?*, choose
   **Allow all the time**.
3. The card turns **Ready** (Shizuku connected, no root yet). If it still says
   `Not connected`, press `Shizuku` in the tools row to request again.

### 3. Execute Root

Tap **Execute Root**. The app opens a live log sheet and automatically prepares
its binary and kernel configuration, acquires a root shell, then loads KernelSU.
The home screen shows only device, kernel and KernelSU status above this button.

Root-shell and KernelSU output is appended while the operation runs. Stages
without new output show elapsed waiting time every second. The sheet can be
closed and reopened from **Log** without interrupting execution; use its copy
button to copy the session log.

If Root fails, the log sheet stays open and cannot be dismissed. A primary
**Reboot device to retry** button appears below the log.

A root shell is accepted only after the service reports `uid=0(root)`.
KernelSU loading completes when the log reports `KSU_LOADED`; the status card
also checks `su -c id`. On failure, inspect the log and reboot before retrying.

### 4. Reboot

Use the `Reboot` pill. It goes through the service (`svc power reboot`), so it
works even when no root shell is open yet. Rebooting is also the only clean way
to remove parked processes and to unload KernelSU.

After rebooting, start again from step 1: Shizuku is stopped and KernelSU is
gone.

The status card reflects what is actually live, detected by running
`su -c id` and checking for `u:r:ksu:s0`:

| card | meaning |
|---|---|
| Not connected | Shizuku is not running / not bound |
| Ready | Shizuku connected, no root yet |
| Root shell | `uid=0`, `u:r:shell:s0` |
| Jailbreak mode | KernelSU loaded, `su` works in `u:r:ksu:s0` |


## Safety

This is a kernel exploit. Read this before pressing anything.

- **Do not kill a parked process.** The exploit keeps a process alive with the
  fake credential page pinned in socket buffers. Reaping it can panic the
  kernel. Reboot is the only clean way to remove it.
- **A reboot clears everything**: KernelSU, the root shell and the parked
  processes. That is the intended way to stop.
- **SELinux is left permissive** until the next reboot.
- A failed attempt leaves a stale timerqueue node; other apps may crash until
  you reboot.
- Only use this on a device you own or are explicitly allowed to modify.

## Layout

```
app/src/main/java/com/kpgc/timerroot/MainActivity.java   UI and state
app/src/main/java/com/kpgc/timerroot/UserService.java    runs as the shell user
app/src/main/aidl/com/kpgc/timerroot/IUserService.aidl   service interface
app/src/main/assets/timer                                exploit binary (not in git)
scripts/build.ps1                                        Gradle-free build
```

## Credits

- Exploit: [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
  (MIT), based on work by woshigenm and the other 98260 ports.
- [Shizuku](https://github.com/RikkaApps/Shizuku) and
  [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) (Apache-2.0) by Rikka.
- KernelSU (GPL-2.0) for the late-load path.

## License

MIT for the app code in this repository. The exploit binary and the Shizuku API
keep their own licenses.
