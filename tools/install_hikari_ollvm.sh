#!/usr/bin/env bash
set -euo pipefail

ROOT="${ENKO_ROOT:-/opt/enko}"
TOOLCHAIN_ROOT="${ENKO_TOOLCHAIN_ROOT:-$ROOT/toolchains/hikari-llvm19}"
SRC_DIR="$TOOLCHAIN_ROOT/src"
BUILD_DIR="$TOOLCHAIN_ROOT/build"
INSTALL_DIR="$TOOLCHAIN_ROOT/install"
REPO_URL="${ENKO_HIKARI_REPO_URL:-https://github.com/Aethereux/Hikari-LLVM19.git}"
REPO_REF="${ENKO_HIKARI_REF:-Hikari-LLVM19}"
JOBS="${ENKO_OLLVM_JOBS:-1}"
TARGETS="${ENKO_OLLVM_TARGETS:-AArch64;ARM;X86}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[enko] Please run as root so dependencies and /opt/enko toolchains can be installed." >&2
  exit 1
fi

echo "[enko] Installing build dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential \
  ca-certificates \
  clang \
  cmake \
  git \
  lld \
  ninja-build \
  python3 \
  zlib1g-dev

mkdir -p "$TOOLCHAIN_ROOT"

if [[ ! -d "$SRC_DIR/.git" ]]; then
  echo "[enko] Cloning Hikari/LLVM 19 into $SRC_DIR"
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$SRC_DIR"
else
  echo "[enko] Updating existing Hikari/LLVM source"
  git -C "$SRC_DIR" fetch --depth 1 origin "$REPO_REF"
  git -C "$SRC_DIR" checkout FETCH_HEAD
fi

echo "[enko] Configuring Hikari/LLVM 19"
cmake -S "$SRC_DIR/llvm" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DLLVM_ENABLE_PROJECTS="clang" \
  -DLLVM_TARGETS_TO_BUILD="$TARGETS" \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_ENABLE_TERMINFO=OFF \
  -DLLVM_ENABLE_ZLIB=ON

echo "[enko] Building and installing. This can take a long time on small ECS instances."
cmake --build "$BUILD_DIR" --target install --parallel "$JOBS"

if [[ ! -x "$INSTALL_DIR/bin/clang" ]]; then
  echo "[enko] Build finished but clang was not found at $INSTALL_DIR/bin/clang" >&2
  exit 1
fi

"$INSTALL_DIR/bin/clang" --version

mkdir -p /etc/enko
cat >/etc/enko/ollvm.env <<EOF
ENKO_OLLVM_CLANG=$INSTALL_DIR/bin/clang
EOF

echo "[enko] Hikari/OLLVM clang installed at $INSTALL_DIR/bin/clang"
echo "[enko] Add this to /etc/enko/config.env if it is not already present:"
echo "ENKO_OLLVM_CLANG=$INSTALL_DIR/bin/clang"
