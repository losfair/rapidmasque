#!/bin/sh
# Build rapidmasque natively inside an OpenBSD VM (cross-platform-actions).
# OpenBSD is a tier-3 Rust target with no prebuilt std to cross-compile
# against, so we use the OS's own rust package. Usage: build-openbsd.sh OUT
set -eux
out="$1"

sudo pkg_add -I rust cmake git go llvm%21
rustc --version
uname -a

# bindgen (boring-sys) needs libclang, which OpenBSD base does not ship.
libclang="$(find /usr/local -name 'libclang.so*' -type f | head -n 1)"
test -n "$libclang"
export LIBCLANG_PATH="$(dirname "$libclang")"
# OpenBSD's C++ runtime is LLVM libc++ (boring-sys assumes libstdc++).
export BORING_BSSL_RUST_CPPLIB=c++
# Keep the build tree out of the synced workspace.
export CARGO_TARGET_DIR="$HOME/target"
cargo build --release --locked

bin="$CARGO_TARGET_DIR/release/rapidmasque"
"$bin" --version
mkdir -p "$(dirname "$out")"
cp "$bin" "$out"
