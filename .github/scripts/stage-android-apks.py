#!/usr/bin/env python3
"""Select the universal and ABI-specific APKs from AGP output metadata."""

import argparse
import json
from pathlib import Path
import re
import shutil


EXPECTED_OUTPUTS = {"universal", "armeabi-v7a", "arm64-v8a", "x86", "x86_64"}


def stage_apks(source, destination, version, variant):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError(f"Invalid APK version: {version}")
    metadata = json.loads((source / "output-metadata.json").read_text(encoding="utf-8"))
    if metadata["artifactType"]["type"] != "APK" or metadata["variantName"] != variant:
        raise ValueError(f"Expected {variant} APK output metadata in {source}")

    files = {}
    for output in metadata["elements"]:
        filters = output["filters"]
        if not filters:
            abi = "universal"
        elif len(filters) == 1 and filters[0]["filterType"] == "ABI":
            abi = filters[0]["value"]
        else:
            raise ValueError(f"Unsupported APK output filters: {filters}")
        if abi not in EXPECTED_OUTPUTS or abi in files:
            raise ValueError(f"Unexpected or duplicate APK output: {abi}")
        filename = output["outputFile"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.apk", filename):
            raise ValueError(f"Invalid APK output filename: {filename!r}")
        file = source / filename
        if not file.is_file() or file.is_symlink() or file in files.values():
            raise ValueError(f"Missing, linked, or duplicate APK output file: {file}")
        files[abi] = file

    if files.keys() != EXPECTED_OUTPUTS:
        raise ValueError(f"Missing APK outputs: {', '.join(sorted(EXPECTED_OUTPUTS - files.keys()))}")
    destination.mkdir(parents=True, exist_ok=True)
    suffix = "-debug" if variant == "debug" else ""
    for abi, file in files.items():
        name = f"Unofficial-SoftEther-VPN-{version}-{abi}{suffix}.apk"
        shutil.copyfile(file, destination / name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("version")
    parser.add_argument("variant", choices=("release", "debug"))
    args = parser.parse_args()
    stage_apks(args.source, args.destination, args.version, args.variant)
