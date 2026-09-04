#!/usr/bin/env python3
"""Collect split/universal Android APKs and require every current ABI."""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import zipfile
from pathlib import Path

REQUIRED_ABIS = ("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
# AGP split names appear in the filename (armeabi-v7a, arm64-v8a, x86, x86_64, universal).
ABI_TOKEN = re.compile(
    r"(armeabi-v7a|arm64-v8a|x86_64|x86|universal)",
    re.IGNORECASE,
)


def classify(name: str) -> str | None:
    if name.endswith("-unsigned.apk"):
        return None
    match = ABI_TOKEN.search(name)
    return match.group(1).lower() if match else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, type=Path)
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--require-abis", action="store_true")
    parser.add_argument(
        "--verify-natives",
        action="store_true",
        help="Require lib/<abi>/*.so in each split and no desktop JNI leftovers",
    )
    args = parser.parse_args()

    if not args.src.is_dir():
        print(f"APK output dir missing: {args.src}", file=sys.stderr)
        return 1

    apks = sorted(p for p in args.src.glob("*.apk") if p.is_file())
    if not apks:
        print(f"No APKs under {args.src}", file=sys.stderr)
        return 1

    found: dict[str, Path] = {}
    leftover: list[Path] = []
    for apk in apks:
        abi = classify(apk.name)
        if abi is None:
            leftover.append(apk)
            continue
        found[abi] = apk

    args.dest.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for abi, src in sorted(found.items()):
        dest = args.dest / f"{args.prefix}-{abi}.apk"
        shutil.copy2(src, dest)
        copied.append(str(dest))
        print(f"copied {src.name} -> {dest.name}")

    if leftover and not found:
        # Single fat APK (no splits): treat as universal only.
        src = leftover[0]
        dest = args.dest / f"{args.prefix}-universal.apk"
        shutil.copy2(src, dest)
        copied.append(str(dest))
        print(f"copied fat {src.name} -> {dest.name}")
        found["universal"] = src

    missing = [abi for abi in REQUIRED_ABIS if abi not in found]
    if args.require_abis and missing:
        print("Missing ABI APKs: " + ", ".join(missing), file=sys.stderr)
        print("Found: " + ", ".join(sorted(found)) if found else "Found: (none)", file=sys.stderr)
        print("Inputs: " + ", ".join(p.name for p in apks), file=sys.stderr)
        return 1

    if "universal" not in found and args.require_abis:
        print("Missing universal APK (all-ABI bundle)", file=sys.stderr)
        return 1

    if args.verify_natives:
        errors = []
        for abi, dest_name in (
            (abi, f"{args.prefix}-{abi}.apk") for abi in list(REQUIRED_ABIS) + ["universal"]
        ):
            dest = args.dest / dest_name
            if not dest.is_file():
                continue
            errors.extend(verify_android_natives(dest, abi))
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1

    print("ABIs: " + ", ".join(sorted(found)))
    return 0


DESKTOP_NATIVE_PREFIXES = ("win/", "linux/", "darwin/", "freebsd/", "META-INF/native/")


def verify_android_natives(apk: Path, abi: str) -> list[str]:
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
    errors: list[str] = []
    abis = REQUIRED_ABIS if abi == "universal" else (abi,)
    for wanted in abis:
        prefix = f"lib/{wanted}/"
        if not any(name.startswith(prefix) and name.endswith(".so") for name in names):
            errors.append(f"{apk.name}: missing {prefix}*.so")
    leaked = [name for name in names if name.startswith(DESKTOP_NATIVE_PREFIXES)]
    if leaked:
        preview = ", ".join(leaked[:6])
        extra = f" (+{len(leaked) - 6} more)" if len(leaked) > 6 else ""
        errors.append(f"{apk.name}: desktop natives leaked: {preview}{extra}")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
