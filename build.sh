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
export CC="$CLANG"
export LD

OUT_DIR="$ROOT_DIR/out"
DEFCONFIG="everpal_defconfig"

if [[ ! -f "$OUT_DIR/.config" ]]; then
    mkdir -p "$OUT_DIR"
    make O="$OUT_DIR" ARCH=arm64 CC="$CLANG" LD="$LD" \
        LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- "$DEFCONFIG"
else
    echo "Using existing configuration: $OUT_DIR/.config"
fi

make O="$OUT_DIR" ARCH=arm64 CC="$CLANG" LD="$LD" \
    LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig

make -j"$(nproc --all)" O="$OUT_DIR" \
    ARCH=arm64 \
    KSU_VERSION=40900 \
    CC="$CLANG" \
    LD="$LD" \
    LLVM=1 \
    LLVM_IAS=1 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    KCFLAGS="-Wno-error=default-const-init-var-unsafe" \
    vmlinux Image.gz dtbs

echo "Kernel build complete: $OUT_DIR/arch/arm64/boot/Image.gz"
