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
    # Clang's ASan archive bookkeeping is compiler-generated, not a vendor API.
    # Mach-O emits this with an extra ABI underscore; normalize only this
    # exact compiler symbol so dependency functions still require a prefix.
    instrumentation = 'asan_globals_registered'
    unexpected = sorted(symbol for symbol in symbols
                        if not symbol.startswith(args.prefix + '_') and symbol.lstrip('_') != instrumentation)
    if unexpected:
        raise SystemExit('Unprefixed dependency globals: ' + ', '.join(unexpected))
    count = sum(symbol.startswith(args.prefix + '_') for symbol in symbols)
    print(f'{count} dependency globals use {args.prefix}_')


if __name__ == '__main__':
    main()
