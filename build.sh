#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

TC_DIR="$HOME/toolchains/ZyC-clang-22.0.0"
CLANG="$TC_DIR/bin/clang"
LD="$TC_DIR/bin/ld.lld"
if [[ ! -x "$CLANG" ]]; then
    echo "error: pinned compiler not found: $CLANG" >&2
    echo "no toolchain download was attempted" >&2
    exit 1
fi
if [[ ! -x "$LD" ]]; then
    echo "error: pinned linker not found: $LD" >&2
    exit 1
fi
CLANG_VERSION=$("$CLANG" --version)
LD_VERSION=$("$LD" --version)
if [[ "$CLANG_VERSION" != *"22.0.0"* || "$LD_VERSION" != *"22.0.0"* ]]; then
    echo "error: expected ZyC clang/LLD 22.0.0" >&2
    echo "clang: $CLANG_VERSION" >&2
    echo "lld: $LD_VERSION" >&2
    exit 1
fi

export PATH="$TC_DIR/bin:$PATH"
if ! command -v ccache >/dev/null 2>&1; then
    echo "error: ccache not found" >&2
    exit 1
fi
export CCACHE_DIR="${CCACHE_DIR:-$HOME/.cache/evergo-kernel/ccache}"
mkdir -p "$CCACHE_DIR"
export CC="ccache $CLANG"
export HOSTCC="ccache $CLANG"
export LD

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-@$SOURCE_DATE_EPOCH}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-github-actions}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-self-hosted}"

# The embedded helper needs a target libc, not the host compiler's headers.
if [[ -z "${BPFILTER_CC:-}" ]]; then
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        BPFILTER_CC=aarch64-linux-gnu-gcc
    else
        BPFILTER_CC="$HOME/toolchains/aarch64-linux-gnu/usr/bin/aarch64-linux-gnu-gcc"
    fi
fi
export BPFILTER_CC
# Android has no glibc ELF interpreter, including when bpfilter is a module.
export BPFILTER_LDFLAGS="${BPFILTER_LDFLAGS:--static}"

OUT_DIR="${OUT_DIR:-$ROOT_DIR/out}"
DEFCONFIG="everpal_defconfig"

DEFCONFIG_PATH="$ROOT_DIR/arch/arm64/configs/$DEFCONFIG"
DEFCONFIG_STAMP="$OUT_DIR/.ci-defconfig.sha256"
DEFCONFIG_HASH=$(sha256sum "$DEFCONFIG_PATH")
DEFCONFIG_HASH="${DEFCONFIG_HASH%% *}"
mkdir -p "$OUT_DIR"

if [[ ! -f "$OUT_DIR/.config" || ! -f "$DEFCONFIG_STAMP" ]] ||
    [[ "$(cat "$DEFCONFIG_STAMP")" != "$DEFCONFIG_HASH" ]]; then
    echo "Generating configuration from $DEFCONFIG"
    make O="$OUT_DIR" ARCH=arm64 CC="$CC" HOSTCC="$HOSTCC" LD="$LD" \
        LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- "$DEFCONFIG"
    printf '%s\n' "$DEFCONFIG_HASH" > "$DEFCONFIG_STAMP"
else
    echo "Using cached configuration: $OUT_DIR/.config"
fi

make O="$OUT_DIR" ARCH=arm64 CC="$CC" HOSTCC="$HOSTCC" LD="$LD" \
    LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig

if [[ -n "${JOBS:-}" ]]; then
    echo "Using explicit build parallelism: -j$JOBS"
else
    JOBS=$("$ROOT_DIR/scripts/build-jobs.sh")
    echo "Auto-selected -j$JOBS from CPU count + 1 with a 2 GiB/job memory cap"
fi
make -j"$JOBS" O="$OUT_DIR" \
    ARCH=arm64 \
    KSU_VERSION=40900 \
    CC="$CC" \
    HOSTCC="$HOSTCC" \
    LD="$LD" \
    LLVM=1 \
    LLVM_IAS=1 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    KCFLAGS="-Wno-error=default-const-init-var-unsafe" \
    vmlinux Image.gz dtbs modules

echo "Kernel build complete: $OUT_DIR/arch/arm64/boot/Image.gz"
