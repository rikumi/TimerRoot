# TimerUAF native build (Android NDK, aarch64 static).
#
#   ANDROID_NDK_HOME=/path/to/ndk make        # build `timer`
#   make clean
#
# The binary is a conf-driven CVE-2026-98260 exploit. It reads a HOCON conf
# (see ../conf/*.conf) and runs one of: ids / leak / shell / fake.

NDK ?= $(ANDROID_NDK_HOME)
ifeq ($(strip $(NDK)),)
  NDK := $(HOME)/Library/Android/sdk/ndk/27.2.12479018
endif

TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt
ifeq ($(shell uname -s),Darwin)
  HOST := darwin-x86_64
else
  HOST := linux-x86_64
endif
CC := $(TOOLCHAIN)/$(HOST)/bin/aarch64-linux-android35-clang

CFLAGS := -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -I.
LDFLAGS := -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,norelro -pthread

timer: timer.c
	$(CC) $(CFLAGS) -ffunction-sections -fdata-sections timer.c -o timer $(LDFLAGS)

.PHONY: clean
clean:
	rm -f timer
