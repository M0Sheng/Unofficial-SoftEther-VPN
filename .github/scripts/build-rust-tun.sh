#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

readonly toolchain=1.91.1-x86_64-unknown-linux-gnu
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repo_root
readonly ndk_bin="${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK}/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin"
readonly crate_dir="$repo_root/rust-tun"
readonly target_dir="$crate_dir/target"
readonly library=libhomevpn_tun.so
readonly -a cargo_args=(--manifest-path "$crate_dir/Cargo.toml" --target-dir "$target_dir" --locked --offline)

if [[ ! -x "$ndk_bin/clang" ]]; then
    echo "Android NDK r28c for Linux x86_64 was not found at $ndk_bin." >&2
    exit 1
fi

rustup toolchain install "$toolchain" --profile minimal --no-self-update
rustup run "$toolchain" cargo test "${cargo_args[@]}" --target x86_64-unknown-linux-gnu

build_abi() {
    local abi=$1 rust_target=$2 clang_target=$3 expected_machine=$4
    local release_dir="$target_dir/$rust_target/release"
    local output="$release_dir/$library"
    local elf symbols method

    rustup target add --toolchain "$toolchain" "$rust_target"
    rustup run "$toolchain" cargo rustc "${cargo_args[@]}" --target "$rust_target" --release --lib -- \
        --remap-path-prefix "$repo_root=softether-vpn-client"
    "$ndk_bin/clang" --target="${clang_target}28" -shared -fPIC -fvisibility=hidden \
        -fstack-protector-strong -O2 "-ffile-prefix-map=$repo_root=softether-vpn-client" \
        -Wl,-z,relro,-z,now,-z,noexecstack,-z,max-page-size=16384,-z,common-page-size=16384 \
        "-Wl,--no-undefined,--exclude-libs,ALL,-soname,$library" \
        "$crate_dir/jni/tun_jni.c" "$release_dir/libsoftether_tun_forwarder.a" \
        -ldl -llog -lm -o "$output"
    "$ndk_bin/llvm-strip" --strip-unneeded "$output"

    elf=$("$ndk_bin/llvm-readelf" -h -lW "$output")
    if ! grep -Eq "^[[:space:]]*Machine:[[:space:]]+$expected_machine[[:space:]]*$" <<< "$elf"; then
        echo "Incorrect ELF machine for the $abi Rust TUN library." >&2
        return 1
    fi
    if ! awk '$1 == "LOAD" { found = 1; if ($NF != "0x4000") exit 1 } END { if (!found) exit 1 }' <<< "$elf"; then
        echo "Rust TUN library for $abi is missing 16 KiB ELF LOAD alignment." >&2
        return 1
    fi

    symbols=$("$ndk_bin/llvm-nm" --dynamic --defined-only --format=just-symbols "$output")
    for method in nativeCreate nativeStep nativeStop; do
        if ! grep -Fxq "Java_kittoku_mvc_control_RustTunEngine_$method" <<< "$symbols"; then
            echo "Missing JNI method $method in the $abi Rust TUN library." >&2
            return 1
        fi
    done

    install -D -m 0644 "$output" "$repo_root/app/src/main/jniLibs/$abi/$library"
    echo "Built $abi Rust TUN JNI library with 16 KiB ELF LOAD alignment."
}

build_abi armeabi-v7a armv7-linux-androideabi armv7a-linux-androideabi ARM
build_abi arm64-v8a aarch64-linux-android aarch64-linux-android AArch64
build_abi x86 i686-linux-android i686-linux-android "Intel 80386"
build_abi x86_64 x86_64-linux-android x86_64-linux-android "Advanced Micro Devices X86-64"
