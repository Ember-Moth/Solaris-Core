#!/usr/bin/env python3
"""Differential fixtures against yaml/v3 3.0.5 used by mihomo 9f121787.
The Go helper only decodes the fixed RawConfig subset; it isn't a running proxy.
"""
import argparse
import json
import subprocess

CASES = [
    ('defaults', '{}', None),
    ('null-defaults', 'mode: null\nport: null\n', None),
    ('port-zero', 'port: 0\nsocks-port: 0\nmixed-port: 0', None),
    ('octal', 'port: 010', None),
    ('decimal-eight', 'port: 08', None),
    ('quoted-integer', 'port: "7890"', None),
    ('explicit-string-integer', 'port: !!str 7890', None),
    ('duplicate-key', 'port: 7890\nport: 7891', None),
    ('merge-override', 'x-a: &a {mixed-port: 7890}\n<<: *a\nmixed-port: 7891', None),
    ('merge-first-wins', 'x-a: &a {port: 7890}\nx-b: &b {port: 7891}\n<<: [*a,*b]', None),
    ('explicit-merge', 'x-a: &a {port: 7890}\n!!merge <<: *a', None),
    ('quoted-merge-key', 'x-a: &a {port: 7890}\n!!str <<: *a', None),
    ('boolean-old', 'allow-lan: yes\nport: 7890', None),
    ('quoted-boolean-old', 'allow-lan: "yes"\nport: 7890', None),
    ('quoted-boolean-new', 'allow-lan: "true"\nport: 7890', None),
    ('undefined-alias', 'proxies: *missing', None),
    ('cycle', 'proxies: &a [*a]', None),
    # Deliberate fail-closed subset: do not truncate numeric values or accept
    # mismatched collection tags just because a typed decoder coerces them.
    ('fractional-port', 'port: 1.5', False),
    ('tag-kind-mismatch', 'mode: !!seq direct', False),
    ('non-string-key', '123: value', False),
]


def run(binary, *args, source):
    completed = subprocess.run([binary, *args], input=source, text=True, capture_output=True, check=True, timeout=5)
    return json.loads(completed.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('compiler')
    parser.add_argument('reference')
    args = parser.parse_args()
    for name, source, intentional in CASES:
        actual = run(args.compiler, '--probe', source=source)
        reference = run(args.reference, source=source)
        expected = reference['ok'] if intentional is None else intentional
        if expected and reference['ok'] and any(reference['value'][key] for key in ('port', 'socks-port', 'mixed-port')) and not actual['inbound']:
            assert not actual['ok'] and actual['status'] == -3, (name, actual)
            continue
        assert actual['ok'] == expected, (name, actual, reference)
        if actual['ok'] and reference['ok']:
            expected_ports = [reference['value'][key] for key in ('port', 'socks-port', 'mixed-port') if reference['value'][key]]
            assert actual['ports'] == expected_ports and actual['mode'] == reference['value']['mode'], (name, actual, reference)
            expected_family = 6 if reference['value']['allow-lan'] else 4
            assert actual['families'] == [expected_family] * len(expected_ports), (name, actual, reference)
        if intentional is not None:
            assert reference['ok'], (name, 'reference behavior changed', reference)
    print(f'{len(CASES)} fixed YAML semantic fixtures passed; 3 intentional strict differences recorded')


if __name__ == '__main__':
    main()
