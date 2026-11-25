#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
native_root="$project_root/native-core-source"
source_root="$native_root/SoftEtherVPN_Stable"
out_root="$native_root/out"
sdk_root=${ANDROID_HOME:-${ANDROID_SDK_ROOT:?Set ANDROID_HOME to the Android SDK}}
ndk_root="$sdk_root/ndk/28.2.13676358"
llvm="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
toolchain="$ndk_root/build/cmake/android.toolchain.cmake"
source_tag=v4.44-9807-rtm
source_commit=ed17437af9719ac66acab30faa29e375d613c35f
patch="$native_root/softether-android.patch"
openssl_version=3.5.9
openssl_sha256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
abis=(armeabi-v7a arm64-v8a x86 x86_64)
openssl_targets=(android-arm android-arm64 android-x86 android-x86_64)
machines=(ARM AArch64 'Intel 80386' 'Advanced Micro Devices X86-64')
jobs=$(nproc)
if (( jobs > 12 )); then jobs=12; fi

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ -f "$toolchain" && -x "$llvm/llvm-readelf" ]] || fail "Pinned Linux Android NDK missing: $ndk_root"
python3 "$project_root/.github/scripts/sourcepack.py"

if [[ ! -e "$source_root" ]]; then
  git -c core.autocrlf=false clone --depth 1 --branch "$source_tag" \
    https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git "$source_root"
fi
source_git=(git -C "$source_root" -c core.autocrlf=false)
[[ $("${source_git[@]}" rev-parse HEAD) == "$source_commit" ]] || fail 'SoftEther source commit differs from the pinned source.'
untracked=$("${source_git[@]}" ls-files --others --exclude-standard)
[[ -z "$untracked" ]] || fail 'Unexpected untracked files in the upstream source checkout.'
if "${source_git[@]}" diff --quiet HEAD --; then
  "${source_git[@]}" apply --check "$patch"
  "${source_git[@]}" apply "$patch"
fi
if ! "${source_git[@]}" diff --binary --no-ext-diff --no-color --abbrev=7 HEAD -- | cmp -s - "$patch"; then
  fail 'Working source changes differ from the frozen Android patch.'
fi

mkdir -p -- "$out_root"
build_root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/softether-native.XXXXXXXX")
trap 'rm -rf -- "$build_root"' EXIT
archive="openssl-$openssl_version.tar.gz"
curl --fail --location --retry 3 --connect-timeout 30 --silent --show-error \
  --output "$build_root/$archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/$archive"
printf '%s  %s\n' "$openssl_sha256" "$build_root/$archive" | sha256sum --check --status ||
  fail 'Pinned OpenSSL source SHA-256 mismatch.'
tar -xzf "$build_root/$archive" -C "$build_root"
openssl_source="$build_root/openssl-$openssl_version"

artifacts=()
for index in "${!abis[@]}"; do
  abi=${abis[index]}
  openssl_build="$build_root/openssl-$abi"
  mkdir -p -- "$openssl_build"
  printf 'Building OpenSSL and SoftEther for %s.\n' "$abi"
  (
    cd -- "$openssl_build"
    export ANDROID_NDK_ROOT="$ndk_root" PATH="$llvm:$PATH"
    # OpenSSL records Configure arguments in its build information.
    source_relative=$(realpath --relative-to=. "$openssl_source")
    perl "$source_relative/Configure" "${openssl_targets[index]}" -D__ANDROID_API__=28 \
      no-shared no-module no-tests no-apps no-docs no-asm -Wno-macro-redefined
    make -s -j"$jobs" build_libs
  )
  providers=$("$llvm/llvm-nm" --defined-only --extern-only --format=just-symbols "$openssl_build/libcrypto.a")
  grep -Fxq ossl_default_provider_init <<< "$providers" &&
    grep -Fxq ossl_legacy_provider_init <<< "$providers" ||
    fail "OpenSSL default and legacy static providers are required for $abi."

  abi_build="$build_root/softether-$abi"
  cmake -S "$native_root" -B "$abi_build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" -DANDROID_ABI="$abi" \
    -DANDROID_PLATFORM=android-28 -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_SOURCE_ROOT="$openssl_source" -DOPENSSL_BUILD_ROOT="$openssl_build"
  cmake --build "$abi_build" --parallel "$jobs"

  jni="$project_root/app/src/main/jniLibs/$abi"
  mkdir -p -- "$jni"
  for program in vpnclient vpncmd; do
    name="libhomevpn_$program.so"
    binary="$out_root/$abi/$name"
    "$llvm/llvm-strip" --strip-unneeded "$binary"
    elf=$("$llvm/llvm-readelf" --file-header --program-headers --wide "$binary")
    grep -Eq "Machine:[[:space:]]+${machines[index]}$" <<< "$elf" &&
      grep -Eq 'Type:[[:space:]]+DYN[[:space:]]' <<< "$elf" &&
      awk '$1 == "INTERP" { interpreter = 1 } $1 == "LOAD" { ++loads; if ($NF != "0x4000") invalid = 1 } END { exit !interpreter || !loads || invalid }' <<< "$elf" ||
      fail "Invalid machine, PIE type or LOAD alignment: $abi/$name"
    cp -- "$binary" "$jni/$name"
    artifacts+=("$jni/$name")
  done
done

hamcore="$project_root/app/src/main/assets/native-core/hamcore.se2"
java "$native_root/BuildHamcore.java" "$source_root/src/bin/hamcore" "$hamcore"
artifacts+=("$hamcore")
python3 - "$project_root" "$out_root/artifacts.json" "${artifacts[@]}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root, manifest, *artifacts = map(Path, sys.argv[1:])
entries = []
for path in artifacts:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    entries.append({
        "path": path.relative_to(root).as_posix(),
        "size": path.stat().st_size,
        "sha256": digest,
    })
manifest.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
PY
printf 'Built and staged SoftEther PIE executables for all four Android ABIs. HamCore read-back passed.\n'
