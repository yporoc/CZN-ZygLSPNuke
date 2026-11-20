#!/bin/bash
# Build ZygNuke (Zygisk arm64 module).
# Requires Android NDK r25+ with aarch64-linux-android24-clang++.
# Usage: NDK_BIN=/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin sh build.sh
set -e
cd "$(dirname "$0")"
NDK_BIN="${NDK_BIN:-$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin}"
if [ ! -d "$NDK_BIN" ]; then
  echo "[!] Set NDK_BIN or ANDROID_NDK_HOME to your Android NDK toolchain bin dir" >&2
  exit 1
fi
CXX="aarch64-linux-android24-clang++"
"$NDK_BIN/$CXX" -shared -O2 -std=c++17 \
  -fno-exceptions -fno-rtti -fvisibility=hidden -fno-stack-protector \
  -mno-outline-atomics -nostdlib++ \
  -Wall -Wextra -Wno-unused-parameter \
  src/com/zygnuke/zygnuke.cpp -o zygisk/arm64-v8a.so \
  -llog -ldl -lm
echo "[+] built zygisk/arm64-v8a.so"
"$NDK_BIN/llvm-nm" -D --defined-only zygisk/arm64-v8a.so 2>/dev/null \
  | grep -E 'zygisk_module_entry|c_net_' || true
