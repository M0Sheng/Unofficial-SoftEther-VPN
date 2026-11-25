#!/usr/bin/env python3
"""Verify native input hashes and the Android binaries inside a package."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
from zipfile import ZipFile


ABI_ELF = {
    "armeabi-v7a": (1, 40),
    "arm64-v8a": (2, 183),
    "x86": (1, 3),
    "x86_64": (2, 62),
}
CORE_LIBRARIES = ("libhomevpn_vpnclient.so", "libhomevpn_vpncmd.so")
ALL_LIBRARIES = (*CORE_LIBRARIES, "libhomevpn_tun.so")


def verify_native_inputs():
    expected = {
        f"app/src/main/jniLibs/{abi}/{library}"
        for abi in ABI_ELF
        for library in CORE_LIBRARIES
    }
    expected.add("app/src/main/assets/native-core/hamcore.se2")
    records = json.loads(Path("native-core-source/out/artifacts.json").read_text())
    if len(records) != len(expected) or {item["path"] for item in records} != expected:
        raise ValueError("Native manifest must list all eight SoftEther binaries and HamCore.")
    for item in records:
        path = Path(item["path"])
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != item["sha256"] or path.stat().st_size != item["size"]:
            raise ValueError(f"Native artifact size or SHA-256 mismatch: {path}")
    print("Verified 9 staged SoftEther artifacts.")


def verify_elf(data, entry, elf_class, machine):
    if data[:6] != b"\x7fELF" + bytes((elf_class, 1)):
        raise ValueError(f"Invalid ELF class or byte order: {entry}")
    if struct.unpack_from("<HH", data, 16) != (3, machine):
        raise ValueError(f"Invalid ELF type or architecture: {entry}")
    if elf_class == 1:
        offset = struct.unpack_from("<I", data, 28)[0]
        entry_size, count = struct.unpack_from("<HH", data, 42)
        header = struct.Struct("<8I")
    else:
        offset = struct.unpack_from("<Q", data, 32)[0]
        entry_size, count = struct.unpack_from("<HH", data, 54)
        header = struct.Struct("<II6Q")
    if entry_size != header.size or offset + count * entry_size > len(data):
        raise ValueError(f"Invalid ELF program header table: {entry}")
    load_alignments = []
    for index in range(count):
        fields = header.unpack_from(data, offset + index * entry_size)
        if fields[0] == 1:
            load_alignments.append(fields[-1])
    if not load_alignments or any(alignment != 16_384 for alignment in load_alignments):
        raise ValueError(f"ELF LOAD segments lack 16 KiB alignment: {entry}")


def verify_package(path, library_prefix, selected_abi=None):
    expected_abis = {selected_abi} if selected_abi else set(ABI_ELF)
    prefix = f"{library_prefix}/"
    with ZipFile(path) as package:
        names = package.namelist()
        actual_abis = {
            name[len(prefix):].split("/", 1)[0]
            for name in names
            if name.startswith(prefix) and name != prefix
        }
        if actual_abis != expected_abis:
            raise ValueError(
                f"Unexpected ABIs in {path}: expected {sorted(expected_abis)}, "
                f"found {sorted(actual_abis)}"
            )
        for abi in sorted(expected_abis):
            elf_class, machine = ABI_ELF[abi]
            for library in ALL_LIBRARIES:
                entry = f"{prefix}{abi}/{library}"
                if names.count(entry) != 1:
                    raise ValueError(f"Expected one copy of {entry} in {path}")
                verify_elf(package.read(entry), entry, elf_class, machine)
    count = len(expected_abis) * len(ALL_LIBRARIES)
    print(f"Verified architecture and 16 KiB ELF alignment for all {count} binaries in {path}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("native")
    apk = commands.add_parser("apk")
    apk.add_argument("path", type=Path)
    apk.add_argument("--abi", choices=ABI_ELF, help="verify one ABI instead of all four")
    commands.add_parser("aab").add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "native":
        verify_native_inputs()
    elif args.command == "apk":
        verify_package(args.path, "lib", args.abi)
    else:
        verify_package(args.path, "base/lib")


if __name__ == "__main__":
    main()
