#!/usr/bin/env bash
set -euo pipefail

ROOT="${ENKO_ROOT:-/opt/enko}"
TOOLCHAIN_ROOT="${ENKO_TOOLCHAIN_ROOT:-$ROOT/toolchains/hikari-llvm19}"
SRC_DIR="$TOOLCHAIN_ROOT/src"
BUILD_DIR="$TOOLCHAIN_ROOT/build"
INSTALL_DIR="$TOOLCHAIN_ROOT/install"
REPO_URL="${ENKO_HIKARI_REPO_URL:-https://github.com/Aethereux/Hikari-LLVM19.git}"
REPO_REF="${ENKO_HIKARI_REF:-Hikari-LLVM19}"
ARCHIVE_URL="${ENKO_HIKARI_ARCHIVE_URL:-https://github.com/Aethereux/Hikari-LLVM19/archive/refs/tags/Hikari-LLVM19.tar.gz}"
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
  curl \
  git \
  lld \
  ninja-build \
  python3 \
  zlib1g-dev

mkdir -p "$TOOLCHAIN_ROOT"

fetch_source_archive() {
  local archive_file extract_dir extracted_dir
  archive_file="$TOOLCHAIN_ROOT/hikari-llvm19-source.tar.gz"
  extract_dir="$TOOLCHAIN_ROOT/archive-extract"

  echo "[enko] Falling back to source archive: $ARCHIVE_URL"
  rm -rf "$SRC_DIR" "$extract_dir"
  mkdir -p "$extract_dir"
  curl -L --fail --retry 10 --retry-delay 5 --connect-timeout 30 \
    -o "$archive_file" "$ARCHIVE_URL"
  tar -xzf "$archive_file" -C "$extract_dir"
  extracted_dir="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$extracted_dir" ]]; then
    echo "[enko] Could not find extracted Hikari/LLVM source directory." >&2
    exit 1
  fi
  mv "$extracted_dir" "$SRC_DIR"
  rm -rf "$extract_dir"
}

if [[ -d "$SRC_DIR/llvm" && ! -d "$SRC_DIR/.git" ]]; then
  echo "[enko] Using existing source tree at $SRC_DIR"
elif [[ ! -d "$SRC_DIR/.git" ]]; then
  echo "[enko] Cloning Hikari/LLVM 19 into $SRC_DIR"
  rm -rf "$SRC_DIR"
  if ! git -c http.version=HTTP/1.1 clone --depth 1 --single-branch --branch "$REPO_REF" "$REPO_URL" "$SRC_DIR"; then
    fetch_source_archive
  fi
else
  echo "[enko] Updating existing Hikari/LLVM source"
  if ! git -C "$SRC_DIR" -c http.version=HTTP/1.1 fetch --depth 1 origin "$REPO_REF"; then
    fetch_source_archive
  elif ! git -C "$SRC_DIR" checkout FETCH_HEAD; then
    fetch_source_archive
  fi
fi

if [[ ! -d "$SRC_DIR/llvm" ]]; then
  echo "[enko] LLVM source directory not found: $SRC_DIR/llvm" >&2
  exit 1
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
