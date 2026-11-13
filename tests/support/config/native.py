#!/usr/bin/env python3
"""Native Conf -> owned model -> ordered route contracts, without external I/O."""
import argparse
import json
from pathlib import Path
import subprocess

GENERAL = '[General]\nconfig-version=1\n'
ROUTE = ('tcp', 'api.example.com', '443', '127.0.0.2', '45000', '-')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('compiler', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    evidence = []

    def run(name, text, route=None, status=0):
        result = subprocess.run([str(args.compiler.resolve()), *(route or ())],
                                input=text, text=True, capture_output=True, check=True)
        actual = json.loads(result.stdout)
        assert actual['status'] == status and actual['ok'] == (status == 0), (name, actual)
        evidence.append({'case': name, 'status': status})
        return actual

    minimal = run('explicit-direct', GENERAL + 'mode=direct\n')
    assert minimal['nodes'] == [
        {'name': 'DIRECT', 'type': 'direct', 'udp': True, 'fields': {}},
        {'name': 'REJECT', 'type': 'reject', 'udp': True, 'fields': {}}]
    assert minimal['groups'] == [{'name': 'GLOBAL', 'selected': 'DIRECT', 'members': ['DIRECT', 'REJECT']}]
    assert not minimal['listeners'] and not minimal['rules']
    spelling = run('literal-strings-decimal-port', GENERAL + 'mode=direct\n[Proxy]\n'
                   'p=socks5,x,0010,username=00123,password=08,udp-relay=false\n')
    assert spelling['nodes'][2] == {'name': 'p', 'type': 'socks5', 'udp': False,
                                   'fields': {'server': 'x', 'port': 10, 'username': '00123', 'password': '08'}}
    # Two independent spellings normalize to the same non-source model.
    equivalent = run('quoted-decimal-port', GENERAL + 'mode="direct"\n[Proxy]\n'
                    '"p" = "socks5", "x", "10", username="00123", password="08", udp-relay="false"\n')
    for field in ('mode', 'nodes', 'groups', 'listeners', 'rules'):
        assert spelling[field] == equivalent[field], field

    cases = [
        ('domain', 'DOMAIN,API.EXAMPLE.COM.', ROUTE, 0),
        ('suffix', 'DOMAIN-SUFFIX,.example.com', ROUTE, 0),
        ('keyword', 'DOMAIN-KEYWORD,example', ROUTE, 0),
        ('cidr-numeric', 'IP-CIDR,127.0.0.5/8', ('tcp', '127.0.0.1', '443', '127.0.0.2', '45000', '-'), 0),
        ('cidr-dns', 'IP-CIDR,127.0.0.5/8', (*ROUTE[:-1], '127.0.0.1'), 1),
        ('cidr6', 'IP-CIDR6,::1/128', ('tcp', '::1', '443', '::1', '45000', '-'), 0),
        ('source-cidr', 'SRC-IP-CIDR,127.0.0.0/8', ROUTE, 0),
        ('source-port', 'SRC-PORT,44000-46000', ROUTE, 0),
        ('target-port', 'DST-PORT,443', ROUTE, 0),
        ('network', 'NETWORK,tcp', ROUTE, 0),
    ]
    for name, rule, metadata, dns in cases:
        actual = run(name, GENERAL + '[Rule]\n' + rule + ',REJECT\nFINAL,DIRECT\n', metadata)
        assert actual['route'] == {'node': 'REJECT', 'rule': 0, 'udp': True, 'dns_calls': dns}, (name, actual)
    final = run('explicit-final', GENERAL + '[Rule]\nDOMAIN,other.example,REJECT\nFINAL,DIRECT\n', ROUTE)
    assert final['route'] == {'node': 'DIRECT', 'rule': 1, 'udp': True, 'dns_calls': 0}
    no_resolve = run('no-resolve', GENERAL + '[Rule]\nIP-CIDR,127.0.0.0/8,REJECT,no-resolve\nFINAL,DIRECT\n', ROUTE)
    assert no_resolve['route'] == {'node': 'DIRECT', 'rule': 1, 'udp': True, 'dns_calls': 0}
    filtered = run('udp-capability-filter', GENERAL + '[Proxy]\np=direct,udp-relay=false\n'
                   '[Proxy Group]\nChoice=select,p,DIRECT\n[Rule]\nNETWORK,udp,Choice\nFINAL,DIRECT\n',
                   ('udp', *ROUTE[1:]))
    assert filtered['route'] == {'node': 'DIRECT', 'rule': 1, 'udp': True, 'dns_calls': 0}
    terminal = run('final-cannot-bypass-udp-capability', GENERAL + '[Proxy]\np=direct,udp-relay=false\n'
                   '[Rule]\nFINAL,p\n', ('udp', *ROUTE[1:]))
    assert terminal['route'] == {'status': -3, 'dns_calls': 0}
    for mode in ('direct', 'global'):
        actual = run(mode + '-ignores-rules', GENERAL + f'mode={mode}\n[Rule]\nFINAL,REJECT\n', ROUTE)
        assert actual['route'] == {'node': 'DIRECT', 'rule': -1, 'udp': True, 'dns_calls': 0}
    for name, text, status in [
        ('missing-version', '[General]\nmode=direct\n', -1),
        ('unknown-version', '[General]\nconfig-version=2\nmode=direct\n', -1),
        ('no-fallback-yaml', 'mode: direct\n', -1),
        ('no-fallback-json', '{"mode":"direct"}', -1),
        ('unsupported-section', GENERAL + '[TUN]\n', -3),
        ('missing-final', GENERAL + '[Rule]\nDOMAIN,a.test,DIRECT\n', -1),
        ('final-before-rule', GENERAL + '[Rule]\nFINAL,DIRECT\nDOMAIN,a.test,REJECT\n', -1),
        ('unknown-ref', GENERAL + '[Rule]\nFINAL,missing\n', -1),
        ('native-unknown-key', GENERAL + 'external-controller=127.0.0.1:9000\nmode=direct\n', -3),
        ('include-rejected', GENERAL + 'mode=direct\n#!include https://example.test/file\n', -3),
    ]:
        run(name, text, status=status)
    if args.report:
        args.report.write_text(json.dumps({'format': 'Solaris Conf v1', 'cases': evidence}, indent=2) + '\n')
    print(f'{len(evidence)} native model and route cases passed')


if __name__ == '__main__':
    main()
