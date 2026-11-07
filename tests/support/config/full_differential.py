#!/usr/bin/env python3
"""Compare owned images with the checksum-pinned, full mihomo config loader.

Every report retains both actual projections and the exact intentional
difference. This does not apply configuration, dial peers or test OS networking.
All credentials below are synthetic fixtures. Existing raw-YAML differential
fixtures remain a separate test rather than substituting for this loader test.
"""
import argparse
import base64
import json
from pathlib import Path
import platform
import shutil
import subprocess


CASES = []
UUID = '1f0a72b3-9320-4f2b-a9e5-55f8a9d184d7'
GUARD_CASES = {
    'provider': {'proxy-providers': {'external': {'type': 'http', 'url': 'http://127.0.0.1:9/unused'}}},
    'geodata': {'rules': ['GEOIP,CN,DIRECT']},
    'dns': {'dns': {'enable': True}},
    'tun': {'tun': {'enable': True}},
    'ntp': {'ntp': {'enable': True}},
    'certificate': {'proxies': [{'name': 'p', 'type': 'anytls', 'server': 'x', 'port': 443, 'password': 'fixture', 'certificate': 'must-not-read.pem'}]},
    'plugin': {'proxies': [{'name': 'p', 'type': 'ss', 'server': 'x', 'port': 443, 'password': 'fixture', 'cipher': 'aes-128-gcm', 'plugin': 'v2ray-plugin'}]},
    'active-group': {'proxy-groups': [{'name': 'g', 'type': 'url-test', 'proxies': ['DIRECT']}]},
}


def case(name, source, *, expected=(True, True), reason='', requires=(), route=None, differences=None):
    CASES.append(dict(name=name, yaml=source if isinstance(source, str) else json.dumps(source),
                      expected=expected, reason=reason, requires=requires, route=route,
                      differences=differences or {}))


def proxy(kind, **fields):
    value = dict(name='node', type=kind)
    if kind not in ('direct', 'reject'):
        value.update(server='proxy.example', port=443)
    if kind in ('ss', 'anytls'):
        value.update(password='fixture-password')
    if kind == 'ss':
        value['cipher'] = 'aes-128-gcm'
    if kind == 'vless':
        value.update(uuid=UUID)
        value['packet-encoding'] = 'xudp'
    value.update(fields)
    return {'proxies': [value]}


STRICT = 'M2 rejects ambiguous or out-of-range input instead of silently coercing or ignoring it.'
SUBSET = 'M2 deliberately exposes only the documented subset and fails closed for unsupported settings.'
for name, source in [('defaults', '{}'), ('null-defaults', 'mode: null\nport: null\nproxies: null'),
                     ('all-ports-zero', 'port: 0\nsocks-port: 0\nmixed-port: 0'),
                     ('empty-collections', {'proxies': [], 'proxy-groups': [], 'rules': [], 'listeners': []})]:
    case(name, source)
for mode in ('rule', 'direct', 'global'):
    case('mode-' + mode, {'mode': mode})
case('mode-invalid', 'mode: invalid', expected=(False, False))
case('mode-uppercase', 'mode: GLOBAL', expected=(False, True), reason=STRICT)
case('unknown-root', 'unknown-option: true', expected=(False, True), reason=SUBSET)
case('known-unsupported-root', 'unified-delay: true', expected=(False, True), reason=SUBSET)
case('template-root', 'x-template: {not-runtime: value}')
case('duplicate-key', 'port: 7890\nport: 7891', expected=(False, False))
case('alias-cycle', 'proxies: &cycle [*cycle]', expected=(False, False))
case('undefined-alias', 'proxies: *missing', expected=(False, False))
for name, scalar in [('decimal', '7890'), ('octal', '010'), ('hex', '0x1f90'), ('leading-zero-eight', '08')]:
    case('port-' + name, 'port: ' + scalar, requires=('inbound',))
for name, scalar in [('quoted', '"7890"'), ('explicit-string', '!!str 7890')]:
    case('port-' + name, 'port: ' + scalar, expected=(False, False))
for name, scalar in [('fraction', '1.5'), ('negative', '-1'), ('overflow', '65536')]:
    case('port-' + name, 'port: ' + scalar, expected=(False, True), reason=STRICT)
case('top-listeners', {'port': 7890, 'socks-port': 7891, 'mixed-port': 7892}, requires=('inbound',))
case('duplicate-endpoint', {'port': 7890, 'socks-port': 7890}, expected=(False, True), reason=STRICT, requires=('inbound',))
for bind in ('*', '127.0.0.2', '::1'):
    delta = {'/listeners': ([{'name': 'mixed', 'type': 'mixed', 'address': '[::1]:7890', 'udp': True, 'auth': []}], [],
        'Solaris accepts an unbracketed numeric IPv6 host. The fixed reference concatenates it without brackets and its actual zero-port guard disables that malformed endpoint.')} if bind == '::1' else {}
    case('bind-lan-' + bind, {'allow-lan': True, 'bind-address': bind, 'mixed-port': 7890}, requires=('inbound',), differences=delta)
    case('bind-local-' + bind, {'allow-lan': False, 'bind-address': bind, 'mixed-port': 7890}, requires=('inbound',))
case('legacy-bool', 'allow-lan: yes\nport: 7890', requires=('inbound',))
case('quoted-legacy-bool', 'allow-lan: "yes"\nport: 7890', requires=('inbound',))
case('quoted-true', 'allow-lan: "true"\nport: 7890', expected=(False, False))
case('merge-inheritance', 'x-base: &base {server: proxy.example, port: 1080, type: socks5, udp: true}\nproxies:\n- <<: *base\n  name: node\n  udp: false')
case('merge-explicit-wins', 'x-a: &a {port: 7890}\n<<: *a\nport: 7891', requires=('inbound',))
case('merge-first-wins', 'x-a: &a {port: 7890}\nx-b: &b {port: 7891}\n<<: [*a,*b]', requires=('inbound',))
case('auth-colon', {'authentication': ['user:fixture:password'], 'port': 7890}, requires=('inbound',))
for value in ('missing-colon', ':password', 'user:'):
    case('auth-invalid-' + value, {'authentication': [value], 'port': 7890}, expected=(False, True), reason=STRICT, requires=('inbound',))
case('auth-duplicate', {'authentication': ['u:p', 'u:q'], 'port': 7890}, expected=(False, True), reason=STRICT, requires=('inbound',))
for kind in ('http', 'socks', 'mixed'):
    case('listener-default-' + kind, {'listeners': [{'name': 'in', 'type': kind, 'port': 7890}]}, requires=('inbound',))
    if kind != 'http':
        for udp in (True, False):
            case(f'listener-{kind}-udp-{udp}', {'listeners': [{'name': 'in', 'type': kind, 'port': 7890, 'udp': udp}]}, requires=('inbound',))
case('listeners-auth-inheritance', {'authentication': ['global:p'], 'listeners': [
    {'name': 'inherits', 'type': 'socks', 'port': 7890},
    {'name': 'anonymous', 'type': 'mixed', 'port': 7891, 'users': []},
    {'name': 'override', 'type': 'http', 'port': 7892, 'users': [{'username': 'u', 'password': 'p'}]}]}, requires=('inbound',))
case('listener-v6', {'listeners': [{'name': 'in', 'type': 'mixed', 'listen': '::1', 'port': 7890}]}, requires=('inbound',))
case('listener-quoted-port', "listeners: [{name: in, type: http, port: '010'}]", requires=('inbound',))
case('listener-octal-port', 'listeners: [{name: in, type: http, port: 010}]', requires=('inbound',))
case('listener-zero', 'listeners: [{name: in, type: http, port: 0}]', expected=(False, True), reason=SUBSET, requires=('inbound',))
case('listener-range', 'listeners: [{name: in, type: http, port: 7890-7892}]', expected=(False, True), reason=SUBSET, requires=('inbound',))
case('listener-hostname', 'listeners: [{name: in, type: http, listen: localhost, port: 7890}]', expected=(False, False), requires=('inbound',))
case('listener-unknown-field', 'listeners: [{name: in, type: http, port: 7890, extra-field: true}]', expected=(False, True), reason=SUBSET, requires=('inbound',))
case('listener-http-udp', 'listeners: [{name: in, type: http, port: 7890, udp: true}]', expected=(False, True), reason=SUBSET, requires=('inbound',))
for kind in ('direct', 'reject', 'socks5', 'ss', 'vless', 'anytls'):
    requires = (kind,) if kind in ('ss', 'vless', 'anytls') else ()
    case('node-default-' + kind, proxy(kind), requires=requires)
    case('node-udp-' + kind, proxy(kind, udp=True), requires=requires)
case('named-direct-udp-disabled', proxy('direct', udp=False), differences={'/nodes/2/udp': (False, True, 'M2 honors the explicit per-node UDP admission gate, including named direct/reject.')})
case('socks-auth', proxy('socks5', username='fixture-user', password='fixture-password'))
case('socks-tcp-carrier', proxy('socks5', network='tcp'))
case('socks-ipv6-server', proxy('socks5', server='::1'))
case('socks-weak-fields', 'proxies: [{name: 123, type: socks5, server: 456, port: "1080", username: 789, password: 123, udp: true}]')
case('socks-invalid-weak-bool', 'proxies: [{name: node, type: socks5, server: x, port: 1080, username: user, password: true, udp: "true"}]', expected=(False, False))
case('socks-weak-fraction', 'proxies: [{name: p, type: socks5, server: x, port: 1080.5}]', expected=(False, True), reason=STRICT)
case('socks-password-only', proxy('socks5', password='fixture-password'), expected=(False, True), reason=STRICT)
case('node-unknown-field', proxy('socks5', **{'extra-field': 1}), expected=(False, True), reason=SUBSET)
case('node-unsupported-carrier', proxy('socks5', network='ws'), expected=(False, True), reason=SUBSET)
case('node-port-zero', proxy('socks5', port=0), expected=(False, True), reason=STRICT)
case('node-duplicate', {'proxies': [proxy('socks5')['proxies'][0]] * 2}, expected=(False, False))
case('node-reserved', proxy('socks5', name='DIRECT'), expected=(False, False))
for cipher, length in [('aes-128-gcm', 0), ('aes-256-gcm', 0), ('chacha20-ietf-poly1305', 0),
                       ('2022-blake3-aes-128-gcm', 16), ('2022-blake3-aes-256-gcm', 32), ('2022-blake3-chacha20-poly1305', 32)]:
    password = base64.b64encode(bytes(range(length))).decode() if length else 'fixture-password'
    for uot in (False, True):
        fields = {'cipher': cipher, 'password': password, 'udp': True, 'udp-over-tcp': uot}
        if uot:
            fields['udp-over-tcp-version'] = 2
        case(f'ss-{cipher}-uot-{uot}', proxy('ss', **fields), requires=('ss',))
case('ss-uot-default-version', proxy('ss', **{'udp-over-tcp': True}), expected=(False, True), reason='M2 requires explicit UoT v2; the reference defaults to legacy v1.', requires=('ss',))
case('ss-invalid-cipher', proxy('ss', cipher='invalid'), expected=(False, False), requires=('ss',))
case('ss-invalid-key', proxy('ss', cipher='2022-blake3-aes-128-gcm'), expected=(False, False), requires=('ss',))
for size in (16, 32):
    chain = ':'.join(base64.b64encode(bytes(range(offset, offset + size))).decode() for offset in (0, 16))
    case(f'ss-eih-{size}', proxy('ss', cipher=f'2022-blake3-aes-{size * 8}-gcm', password=chain), requires=('ss',))
for name, values in [('vless-plain', {}),
                     ('vless-tls-vision', {'tls': True, 'servername': 'tls.example', 'flow': 'xtls-rprx-vision'}),
                     ('vless-tls-vision-udp443', {'tls': True, 'flow': 'xtls-rprx-vision-udp443'}),
                     ('vless-explicit-none', {'encryption': 'none'}),
                     ('vless-compact-uppercase-uuid', {'uuid': UUID.replace('-', '').upper()})]:
    delta = {'/nodes/2/fields/flow': ('xtls-rprx-vision-udp443', 'xtls-rprx-vision',
        'M2 preserves the documented UDP 443 override. The fixed reference constructor truncates the flow suffix to plain Vision.')} if values.get('flow') == 'xtls-rprx-vision-udp443' else {}
    case(name, proxy('vless', **values), requires=('vless',), differences=delta)
case('vless-invalid-uuid', proxy('vless', uuid='invalid'), expected=(False, True), reason='M2 requires a real UUID; the reference maps arbitrary strings into UUID identities.', requires=('vless',))
case('vless-vision-no-security', proxy('vless', flow='xtls-rprx-vision'), expected=(False, True), reason='M2 rejects Vision without TLS or VLESS encryption during configuration validation.', requires=('vless',))
case('vless-packetaddr', proxy('vless', **{'packet-encoding': 'packetaddr'}), expected=(False, True), reason=SUBSET, requires=('vless',))
vless_implicit = proxy('vless')
del vless_implicit['proxies'][0]['packet-encoding']
case('vless-default-xudp', vless_implicit, requires=('vless',))
for appearance in ('native', 'xorpub', 'random'):
    for rtt in ('1rtt', '0rtt'):
        case(f'vless-encryption-{appearance}-{rtt}', proxy('vless', encryption=
            f'mlkem768x25519plus.{appearance}.{rtt}.hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo'), requires=('vless',))
case('vless-invalid-encryption', proxy('vless', encryption='invalid'), expected=(False, False), requires=('vless',))
for seconds in (0, 1, 5, 6, 17, 3600):
    case(f'anytls-seconds-{seconds}', proxy('anytls', **{'idle-session-timeout': seconds, 'idle-session-check-interval': seconds, 'min-idle-session': 2, 'sni': 'tls.example'}), requires=('anytls',))
case('anytls-weak-seconds', proxy('anytls', **{'idle-session-timeout': '17', 'idle-session-check-interval': '7'}), requires=('anytls',))
case('anytls-bounds', proxy('anytls', **{'idle-session-timeout': 3601}), expected=(False, True), reason='M2 bounds idle duration to one hour and pool size to 64; the reference accepts larger values.', requires=('anytls',))
case('anytls-pool-max', proxy('anytls', **{'min-idle-session': 64}), requires=('anytls',))
case('anytls-pool-overflow', proxy('anytls', **{'min-idle-session': 65}), expected=(False, True), reason='M2 bounds the idle session pool at 64.', requires=('anytls',))
case('anytls-negative-seconds', proxy('anytls', **{'idle-session-timeout': -1}), expected=(False, True), reason=STRICT, requires=('anytls',))
case('select-members', {'proxy-groups': [{'name': 'choose', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}]})
case('select-reserved-global', {'proxy-groups': [{'name': 'GLOBAL', 'type': 'select', 'proxies': ['REJECT']}]}, expected=(False, True), reason='M2 reserves generated GLOBAL as a flat group of leaf nodes.')
case('select-missing-member', {'proxy-groups': [{'name': 'choose', 'type': 'select', 'proxies': ['missing']}]}, expected=(False, False))
case('select-duplicate-member', {'proxy-groups': [{'name': 'choose', 'type': 'select', 'proxies': ['DIRECT', 'DIRECT']}]}, expected=(False, True), reason=STRICT)
case('select-nested', {'proxy-groups': [{'name': 'first', 'type': 'select', 'proxies': ['DIRECT']}, {'name': 'second', 'type': 'select', 'proxies': ['first']}]}, expected=(False, True), reason='M2 select groups are flat, so nested membership is rejected.')
case('select-cycle', {'proxy-groups': [{'name': 'first', 'type': 'select', 'proxies': ['second']}, {'name': 'second', 'type': 'select', 'proxies': ['first']}]}, expected=(False, False))
case('select-empty', {'proxy-groups': [{'name': 'choose', 'type': 'select', 'proxies': []}]}, expected=(False, False))
case('rule-missing-target', {'rules': ['MATCH,missing']}, expected=(False, False))
case('rule-invalid-type', {'rules': ['BAD-RULE,x,DIRECT']}, expected=(False, False))
case('rule-invalid-prefix', {'rules': ['IP-CIDR,10.0.0.0/33,DIRECT']}, expected=(False, False))
case('rule-invalid-range', {'rules': ['DST-PORT,10-2,DIRECT']}, expected=(False, True), reason=STRICT)
case('rule-port-set', {'rules': ['DST-PORT,80/443,DIRECT']}, expected=(False, True), reason='M2 accepts one inclusive port range per rule; reference port sets are not exposed.')
case('rule-modifier-domain', {'rules': ['DOMAIN,example.com,DIRECT,no-resolve']}, expected=(False, True), reason=STRICT)
case('rule-all-kinds', {'rules': ['DOMAIN,example.com,DIRECT', 'DOMAIN-SUFFIX,example.net,REJECT',
    'DOMAIN-KEYWORD,api,DIRECT', 'IP-CIDR,10.1.2.3/8,REJECT,no-resolve', 'IP-CIDR6,fd00::1234/64,DIRECT',
    'SRC-IP-CIDR,192.168.0.0/16,REJECT', 'SRC-PORT,1000-2000,DIRECT', 'DST-PORT,443,REJECT',
    'NETWORK,udp,DIRECT', 'MATCH,REJECT']})

# Actual ordered matcher probes, with a resolver supplied only when demanded.
# Both sides receive identical metadata and one controlled answer/failure.
def route_case(name, rules, destination='api.example.com', *, network='tcp', port=443,
               source='192.168.1.2', source_port=1234, answer='10.1.2.3', config=None, differences=None):
    cfg = dict(config or {})
    cfg['rules'] = rules
    case('route-' + name, cfg, route=[network, destination, str(port), source, str(source_port), answer], differences=differences)


route_case('domain', ['DOMAIN,api.example.com,REJECT', 'MATCH,DIRECT'])
route_case('suffix', ['DOMAIN-SUFFIX,example.com,REJECT', 'MATCH,DIRECT'])
route_case('suffix-apex', ['DOMAIN-SUFFIX,example.com,REJECT', 'MATCH,DIRECT'], 'example.com')
route_case('uppercase-rule', ['DOMAIN,API.EXAMPLE.COM,REJECT', 'MATCH,DIRECT'])
route_case('suffix-boundary', ['DOMAIN-SUFFIX,example.com,REJECT', 'MATCH,DIRECT'], 'notexample.com')
route_case('keyword', ['DOMAIN-KEYWORD,api,REJECT', 'MATCH,DIRECT'])
route_case('cidr-resolve', ['IP-CIDR,10.0.0.0/8,REJECT', 'MATCH,DIRECT'])
route_case('cidr6-resolve', ['IP-CIDR6,fd00::/64,REJECT', 'MATCH,DIRECT'], answer='fd00::1')
route_case('cidr-numeric', ['IP-CIDR,10.0.0.0/8,REJECT'], '10.1.2.3')
route_case('cidr6-numeric', ['IP-CIDR6,fd00::/64,REJECT'], 'fd00::1')
route_case('no-resolve', ['IP-CIDR,10.0.0.0/8,REJECT,no-resolve', 'MATCH,DIRECT'])
route_case('later-resolve', ['IP-CIDR,10.0.0.0/8,REJECT,no-resolve', 'IP-CIDR,10.0.0.0/8,DIRECT'])
route_case('one-resolution', ['IP-CIDR,172.16.0.0/12,REJECT', 'IP-CIDR,10.0.0.0/8,DIRECT'])
route_case('dns-failure', ['IP-CIDR,10.0.0.0/8,REJECT', 'DOMAIN,api.example.com,DIRECT'], answer='-')
route_case('domain-before-dns', ['DOMAIN,api.example.com,REJECT', 'IP-CIDR,10.0.0.0/8,DIRECT'])
route_case('source-cidr', ['SRC-IP-CIDR,192.168.0.0/16,REJECT'])
route_case('source-cidr6', ['SRC-IP-CIDR,fd00::/64,REJECT'], source='fd00::1')
route_case('source-port-low', ['SRC-PORT,1234-2000,REJECT'])
route_case('source-port-high', ['SRC-PORT,1000-1234,REJECT'])
route_case('source-port-miss', ['SRC-PORT,1235-2000,REJECT'])
route_case('destination-port', ['DST-PORT,443,REJECT'])
route_case('destination-port-miss', ['DST-PORT,443,REJECT'], port=80)
route_case('network-udp', ['NETWORK,udp,REJECT'], network='udp')
route_case('network-tcp', ['NETWORK,tcp,REJECT'])
route_case('direct-fallback', [])
route_case('direct-mode', ['MATCH,REJECT'], config={'mode': 'direct'})
route_case('global-mode', ['MATCH,REJECT'], config={'mode': 'global'})
udp_config = proxy('socks5', udp=False)
udp_config['proxy-groups'] = [{'name': 'choose', 'type': 'select', 'proxies': ['node', 'DIRECT']}]
route_case('udp-skip-node', ['MATCH,node', 'MATCH,REJECT'], network='udp', config=proxy('socks5', udp=False))
route_case('udp-skip-group', ['MATCH,choose', 'MATCH,REJECT'], network='udp', config=udp_config)
route_case('tcp-select-group', ['MATCH,choose'], config=udp_config)
for name, rule, canonical in [('rule-absolute-name', 'DOMAIN,api.example.com.,REJECT', 'api.example.com'),
                              ('rule-leading-dot-suffix', 'DOMAIN-SUFFIX,.example.com,REJECT', 'example.com')]:
    reason = 'Routing normalization: Solaris canonicalizes absolute-name trailing dots and suffix leading dots by its established ASCII-domain contract. The fixed reference retains those rule characters; this is an actual matching difference.'
    route_case(name, [rule, 'MATCH,DIRECT'], differences={
        '/rules/0/value': (canonical, rule.split(',')[1], reason),
        '/route/node': ('REJECT', 'DIRECT', reason), '/route/rule': (0, 1, reason)})
for destination in ('API.EXAMPLE.COM',):
    reason = 'Routing normalization: after actual SOCKS metadata decoding, Solaris folds ASCII host case while the fixed reference preserves it. This uses real decoders and matchers without opening a listener.'
    route_case('metadata-' + destination, ['DOMAIN,api.example.com,REJECT', 'MATCH,DIRECT'], destination,
               differences={'/route/node': ('REJECT', 'DIRECT', reason), '/route/rule': (0, 1, reason)})
route_case('metadata-fqdn', ['DOMAIN,api.example.com,REJECT', 'MATCH,DIRECT'], 'api.example.com.')


def invoke(binary, source, route, sandbox):
    command = [str(binary), *(route or [])]
    if sandbox:
        command = ['sandbox-exec', '-p', '(version 1) (allow default) (deny network*)', *command]
    result = subprocess.run(command, input=source, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f'{binary.name} exited {result.returncode}: {result.stdout[-4096:]} {result.stderr[-4096:]}')
    return json.loads(result.stdout)


def differences(left, right, path=''):
    if type(left) is not type(right):
        return [(path, left, right)]
    if isinstance(left, dict) and left.keys() == right.keys():
        return [entry for key in sorted(left) for entry in differences(left[key], right[key], path + '/' + key)]
    if isinstance(left, list) and len(left) == len(right):
        return [entry for i, (a, b) in enumerate(zip(left, right)) for entry in differences(a, b, path + '/' + str(i))]
    return [] if left == right else [(path, left, right)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('compiler', type=Path)
    parser.add_argument('reference', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    sandbox = platform.system() == 'Darwin'
    if sandbox and not shutil.which('sandbox-exec'):
        raise RuntimeError('macOS acceptance requires deny-network sandbox-exec')
    evidence = json.loads(args.reference.with_name(args.reference.name + '-evidence.json').read_text())
    reports, failures = [], []
    guard_reports = []
    for name, source in GUARD_CASES.items():
        result = invoke(args.reference.resolve(), json.dumps(source), None, sandbox)
        assert result.get('stage') == 'harness-guard' and result['ok'] is False, (name, result)
        guard_reports.append({'name': name, 'result': result})
    for item in CASES:
        record = {'name': item['name'], 'yaml': item['yaml'], 'intentional_differences': []}
        try:
            actual = invoke(args.compiler.resolve(), item['yaml'], item['route'], sandbox)
            reference = invoke(args.reference.resolve(), item['yaml'], item['route'], sandbox)
            record.update(solaris=actual, reference=reference)
            assert reference.get('stage') != 'harness-guard', reference
            unavailable = [feature for feature in item['requires'] if not actual['capabilities'][feature]]
            if unavailable:
                assert not actual['ok'] and actual['status'] == -3, actual
                record['intentional_differences'].append({'reason': 'Build disables ' + ', '.join(unavailable), 'solaris': actual['status'], 'reference': reference['ok']})
                record['build_disabled'] = unavailable
            else:
                assert (actual['ok'], reference['ok']) == item['expected'], (item['expected'], actual, reference)
                if actual['ok'] != reference['ok']:
                    assert item['reason']
                    record['intentional_differences'].append({'path': '/ok', 'solaris': actual['ok'], 'reference': reference['ok'], 'reason': item['reason']})
                elif actual['ok']:
                    projection = {key: value for key, value in actual.items() if key not in ('status', 'capabilities', 'representation')}
                    reference_projection = {key: value for key, value in reference.items() if key != 'representation'}
                    found = differences(projection, reference_projection)
                    for path, left, right in found:
                        reason = None
                        expected = item['differences'].get(path)
                        if expected and (left, right) == expected[:2]:
                            reason = expected[2]
                        # The M2 design intentionally keeps every select flat,
                        # including generated GLOBAL. Do not hide other deltas.
                        if path == f"/groups/{len(actual['groups']) - 1}/members" and actual['groups'][-1]['name'] == 'GLOBAL':
                            names = [g['name'] for g in actual['groups'][:-1]]
                            if right == left + names:
                                reason = 'M2 generated GLOBAL contains leaf nodes only; the reference also includes configured groups.'
                        assert reason, (path, left, right)
                        record['intentional_differences'].append(dict(path=path, solaris=left, reference=right, reason=reason))
                    for path in item['differences']:
                        assert any(entry[0] == path for entry in found), ('expected difference disappeared', path)
            record['passed'] = True
        except Exception as error:
            record['passed'] = False
            record['failure'] = str(error)
            failures.append(item['name'])
            print(item['name'] + ': ' + str(error), flush=True)
        reports.append(record)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'reference_evidence': evidence, 'network_sandbox': sandbox,
        'normalization_rules': ['Protocol registry aliases map to public names.',
            'UUID bytes render as lowercase hex without hyphens; constructor UUID and flow text remain under representation.',
            'Equivalent unspecified listener addresses render as [::]:port; original reference genAddr/disabled results remain under representation.',
            'CIDR payloads compare masked numeric networks; original reference payload remains under representation.',
            'Source CIDR always suppresses destination resolution; original stored no-resolve flags remain under representation.'],
        'scope': 'Original full ParseRawConfig; offline constructor image and real ordered matcher with controlled DNS. No ApplyConfig, listener activation or peer traffic.',
        'resource_guard_checks': guard_reports,
        'cases': reports, 'passed': len(reports) - len(failures), 'failed': len(failures)}, indent=2) + '\n')
    assert not failures, f'{len(failures)} full-loader differences need review: {failures}; report={args.report}'
    intentional = sum(bool(record['intentional_differences']) for record in reports)
    print(f'{len(reports)} full-loader/matcher fixtures and {len(guard_reports)} resource guards passed; {intentional} cases record explicit subset/build differences; report={args.report}')


if __name__ == '__main__':
    main()
