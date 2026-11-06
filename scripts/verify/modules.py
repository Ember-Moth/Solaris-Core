#!/usr/bin/env python3
"""Verify explicit module inclusion/removal in a static archive or executable."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--enabled", nargs="*", default=[])
    args = parser.parse_args()
    with open(args.manifest, encoding="utf-8") as source:
        modules = json.load(source)["modules"]
    result = subprocess.run([args.nm, "-g", args.library], check=True, capture_output=True, text=True)
    defined = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and len(parts[-2]) == 1 and parts[-2].upper() != "U":
            defined.add(parts[-1].removeprefix("_"))
    for module in modules:
        descriptor = module.get("descriptor")
        if descriptor is None:
            continue
        expected = module["name"] in args.enabled
        if (descriptor in defined) != expected:
            raise SystemExit(f"{descriptor}: expected {'present' if expected else 'absent'} in {args.library}")
    print("static module symbols match enabled manifest entries")


if __name__ == "__main__":
    main()
