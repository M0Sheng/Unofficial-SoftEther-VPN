"""Verify or refresh hashes for the committed native source package."""

from argparse import ArgumentParser
import hashlib
import json
import os
from pathlib import Path

NATIVE_ROOT = Path(__file__).resolve().parents[2] / "native-core-source"
MANIFEST = NATIVE_ROOT / "sourcepack-manifest.json"


def sourcepack_entries():
    entries = []
    for directory, subdirectories, files in os.walk(NATIVE_ROOT):
        directory = Path(directory)
        if directory == NATIVE_ROOT:
            subdirectories[:] = [
                name for name in subdirectories if name not in {"SoftEtherVPN_Stable", "build", "out"}
            ]
        for filename in files:
            path = directory / filename
            relative = path.relative_to(NATIVE_ROOT)
            if path == MANIFEST or (relative.parts[0] == "tests" and path.suffix in {".obj", ".exe"}):
                continue
            if not path.is_file() or path.is_symlink():
                raise SystemExit(f"Unexpected sourcepack input: {relative.as_posix()}")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            entries.append({"path": relative.as_posix(), "size": path.stat().st_size, "sha256": digest})
    return sorted(entries, key=lambda entry: entry["path"].casefold())


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="refresh the manifest after reviewed source changes")
    options = parser.parse_args()
    actual = sourcepack_entries()
    if options.write:
        MANIFEST.write_text(json.dumps(actual, indent=4, separators=(",", ":  ")) + "\n", encoding="utf-8", newline="\r\n")
        print(f"Recorded {len(actual)} native sourcepack inputs.")
        return
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if sorted(expected, key=lambda entry: entry["path"].casefold()) != actual:
        expected_by_path = {entry["path"]: entry for entry in expected}
        actual_by_path = {entry["path"]: entry for entry in actual}
        changed = [
            path for path in sorted(expected_by_path.keys() | actual_by_path.keys())
            if expected_by_path.get(path) != actual_by_path.get(path)
        ]
        raise SystemExit("Unexpected native sourcepack files or hashes: " + ", ".join(changed))
    print(f"Verified {len(actual)} native sourcepack inputs.")


if __name__ == "__main__":
    main()
