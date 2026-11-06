#!/usr/bin/env python3
"""Compare the shared SDK's defined exports with the generated allowlist."""
import argparse
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--linker", default="link")
    args = parser.parse_args()
    expected = set(Path(args.expected).read_text().splitlines())
    if sys.platform == "win32":
        output = subprocess.check_output(
            [args.linker, "/dump", "/exports", args.library], text=True
        )
        actual = set(re.findall(
            r"^\s+\d+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+(\S+)", output, re.M
        ))
    elif sys.platform == "darwin":
        output = subprocess.check_output(
            [args.nm, "-gU", "-j", args.library], text=True
        )
        actual = {line.removeprefix("_") for line in output.splitlines() if line}
    else:
        output = subprocess.check_output(
            [args.nm, "-D", "--defined-only", args.library], text=True
        )
        actual = {line.split()[-1].split("@")[0]
                  for line in output.splitlines() if line.split()}
    if actual != expected:
        raise SystemExit(f"missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}")
    print(f"Verified {len(expected)} Solaris SDK exports")


if __name__ == "__main__":
    main()
