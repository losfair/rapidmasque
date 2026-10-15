#!/bin/sh
# Build a fully static rapidmasque for Linux/musl. Runs inside an Alpine
# container on a native amd64 or arm64 runner:
#
#   docker run --rm -v "$PWD:/src" -w /src alpine:3.23 .github/scripts/build-musl.sh OUT
#
# Alpine's own Rust is used rather than rustup's musl toolchain: rustup's
# musl target links build scripts statically, so bindgen (run by boring-sys)
# cannot dlopen libclang. Here build scripts stay dynamic, and only the final
# binary gets `+crt-static` (RUSTFLAGS applies only to the explicit --target).
# With -static, the linker pulls in libstdc++.a for BoringSSL's C++ parts.
set -eux
out="$1"

apk add --no-cache rust cargo build-base cmake perl go git clang-dev linux-headers file
rustc --version

triple="$(uname -m)-alpine-linux-musl"
export RUSTFLAGS="-C target-feature=+crt-static"
export CARGO_TARGET_DIR=/tmp/target
cargo build --release --locked --target "$triple"

bin="$CARGO_TARGET_DIR/$triple/release/rapidmasque"
file "$bin"
# Must not need a dynamic loader.
file "$bin" | grep -Eq 'static(-pie)? linked'
"$bin" --version
mkdir -p "$(dirname "$out")"
cp "$bin" "$out"
