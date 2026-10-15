#!/bin/sh
# Cross-build rapidmasque for OpenBSD from Linux (no OpenBSD VM needed to
# compile). Usage: cross-openbsd.sh ARCH OUT   (ARCH: amd64 | arm64)
#
# - Rust: OpenBSD is a tier-3 target with no prebuilt std, so std is built
#   from source with nightly `-Zbuild-std` (pin via RUST_NIGHTLY).
# - Sysroot: libc/libc++/crt/headers come from the official OpenBSD base +
#   comp sets (cached in OPENBSD_SYSROOT_CACHE). OpenBSD ships only versioned
#   shared libs (libc.so.103.0, SONAME included), so unversioned symlinks let
#   `-lc` resolve; DT_NEEDED still records the versioned SONAME.
# - C/C++ (BoringSSL, ring): Linux clang targeting OpenBSD with the sysroot.
# - Linker: clang driving the nightly toolchain's rust-lld (system lld may be
#   too old for `-z nobtcfi`). The binary is marked PT_OPENBSD_NOBTCFI:
#   OpenBSD enforces IBT/BTI landing pads on capable CPUs, and Rust code (and
#   std) is not compiled with them here.
#
# Needs: clang (>= 20 for arm64: LLVM 18 crashes compiling ring for
# aarch64-unknown-openbsd; pick it with CLANG/CLANGXX), cmake, go, curl,
# rustup.
set -eu

arch="$1"
out="$2"
version="${OPENBSD_VERSION:-7.9}"
nightly="${RUST_NIGHTLY:-nightly}"
clang="${CLANG:-clang}"
clangxx="${CLANGXX:-clang++}"
cache="${OPENBSD_SYSROOT_CACHE:-$HOME/.cache/openbsd-sysroot}"

case "$arch" in
    amd64) triple=x86_64-unknown-openbsd; cpu=x86_64 ;;
    arm64) triple=aarch64-unknown-openbsd; cpu=aarch64 ;;
    *) echo "unknown arch $arch" >&2; exit 2 ;;
esac
tvar=$(echo "$triple" | tr 'a-z-' 'A-Z_')   # X86_64_UNKNOWN_OPENBSD
lvar=$(echo "$triple" | tr '-' '_')          # x86_64_unknown_openbsd

# --- sysroot -----------------------------------------------------------------
sysroot="$cache/$version-$arch"
if [ ! -f "$sysroot/.complete" ]; then
    rm -rf "$sysroot"
    mkdir -p "$sysroot"
    short=$(echo "$version" | tr -d .)
    mirror="${OPENBSD_MIRROR:-https://cdn.openbsd.org/pub/OpenBSD}/$version/$arch"
    curl -fsSL "$mirror/base$short.tgz" | tar -xzf - -C "$sysroot" ./usr/lib ./usr/libexec/ld.so
    curl -fsSL "$mirror/comp$short.tgz" | tar -xzf - -C "$sysroot" ./usr/include ./usr/lib
    (
        cd "$sysroot/usr/lib"
        for f in lib*.so.*; do
            base="${f%%.so.*}.so"
            [ -e "$base" ] || ln -s "$(ls "$base".* | sort -V | tail -n 1)" "$base"
        done
    )
    touch "$sysroot/.complete"
fi

# --- toolchain ---------------------------------------------------------------
rustup toolchain install "$nightly" --profile minimal --component rust-src
host=$(rustc +"$nightly" -vV | sed -n 's/^host: //p')
rust_lld="$(rustc +"$nightly" --print sysroot)/lib/rustlib/$host/bin/gcc-ld/ld.lld"
test -x "$rust_lld"

tools="$(mktemp -d)"
for tool in cc c++; do
    driver="$clang"
    [ "$tool" = c++ ] && driver="$clangxx"
    cat > "$tools/$triple-$tool" <<EOF
#!/bin/sh
exec $driver --target=$triple$version --sysroot=$sysroot -fuse-ld=lld --ld-path=$rust_lld "\$@"
EOF
    chmod +x "$tools/$triple-$tool"
done
cat > "$tools/toolchain.cmake" <<EOF
set(CMAKE_SYSTEM_NAME OpenBSD)
set(CMAKE_SYSTEM_PROCESSOR $cpu)
set(CMAKE_SYSROOT $sysroot)
set(CMAKE_C_COMPILER $tools/$triple-cc)
set(CMAKE_CXX_COMPILER $tools/$triple-c++)
set(CMAKE_ASM_COMPILER $tools/$triple-cc)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

export "CC_$lvar=$tools/$triple-cc"
export "CXX_$lvar=$tools/$triple-c++"
export "AR_$lvar=$(command -v llvm-ar || command -v ar)"
export "CARGO_TARGET_${tvar}_LINKER=$tools/$triple-cc"
export "CARGO_TARGET_${tvar}_RUSTFLAGS=-C link-arg=-Wl,-z,nobtcfi"
export "CMAKE_TOOLCHAIN_FILE_$lvar=$tools/toolchain.cmake"
# boring-sys 4's BoringSSL takes pthread_rwlock_t from <sys/types.h>, but
# OpenBSD only declares it in <pthread.h> (the native build fails the same
# way). Force-include it for C/C++, not for the assembly (which shares CFLAGS).
printf '#ifndef __ASSEMBLER__\n#include <pthread.h>\n#endif\n' > "$tools/openbsd-compat.h"
export "CFLAGS_$lvar=-include $tools/openbsd-compat.h"
export "CXXFLAGS_$lvar=-include $tools/openbsd-compat.h"
export "BINDGEN_EXTRA_CLANG_ARGS_$lvar=--target=$triple --sysroot=$sysroot -include $tools/openbsd-compat.h"
export "BORING_BSSL_RUST_CPPLIB_$lvar=c++"

cargo +"$nightly" build --release --locked --target "$triple" \
    -Zbuild-std=std,panic_abort

bin="${CARGO_TARGET_DIR:-target}/$triple/release/rapidmasque"
file "$bin" 2>/dev/null || true
mkdir -p "$(dirname "$out")"
cp "$bin" "$out"
