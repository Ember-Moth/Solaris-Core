#!/usr/bin/env python3
"""Ensure a C dependency archive exposes only its assigned private namespace."""
import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nm', required=True)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('archive')
    args = parser.parse_args()
    result = subprocess.run([args.nm, '-g', args.archive], check=True, capture_output=True, text=True)
    symbols = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[-2] in {'T', 'D', 'S', 'B', 'C', 'R'}:
            symbols.add(parts[-1].removeprefix('_'))
    if not symbols:
        raise SystemExit('No defined C globals found in dependency archive')
    unexpected = sorted(symbol for symbol in symbols if not symbol.startswith(args.prefix + '_'))
    if unexpected:
        raise SystemExit('Unprefixed dependency globals: ' + ', '.join(unexpected))
    print(f'{len(symbols)} dependency globals use {args.prefix}_')


if __name__ == '__main__':
    main()
