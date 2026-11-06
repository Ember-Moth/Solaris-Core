#!/usr/bin/env python3
"""Use the pinned vendor's object-format-aware prefix audit on private archives."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--prefix", default="solaris_bssl")
    parser.add_argument("archives", nargs="+")
    args = parser.parse_args()
    result = subprocess.run([args.go, "run", "./util/audit_symbols.go",
                             "-ignore-symbols-with", args.prefix,
                             *(str(Path(p).resolve()) for p in args.archives)],
                            cwd=args.source, text=True, capture_output=True)
    # AppleClang emits this weak, compiler-owned helper. The pinned upstream
    # allowlist already excludes other compiler/runtime helpers; do not allow
    # unprefixed strong symbols or arbitrary C++ names here.
    allowed = 'Found weak symbol without "solaris_bssl": __clang_call_terminate' if args.prefix == "solaris_bssl" else None
    unexpected = [line for line in result.stdout.splitlines() if line != allowed]
    if unexpected or result.returncode not in (0, 1) or (
            result.returncode and not result.stdout.strip()):
        raise SystemExit(f"private crypto symbol audit failed:\n{result.stdout}{result.stderr}")
    print(f"Verified private symbol isolation: {args.prefix}")


if __name__ == "__main__":
    main()
