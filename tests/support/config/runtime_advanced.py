#!/usr/bin/env python3
"""Advanced declared Conf combinations through the public SDK and pinned peers."""
import argparse
import base64
from contextlib import ExitStack
import json
import ipaddress
from pathlib import Path
import queue
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

from runtime_proxy import (proxy_config, Runtime, Peer, echo, config, by_name, http_tunnel, socks_tcp,
                           udp_control, udp_exchange, assert_echo, address, exact)
from runtime_control import HeadPeer, probe
from runtime_protocol import TlsHeadPeer
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loopback import udp_pair, tcp_udp_pair

UUID = '7b4bb031-41b5-4d1d-b062-1ea0cab957c1'
PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


class DatagramPeer:
    def __init__(self, family):
        self.socket, self.guard = udp_pair(family)
        self.host, self.port = self.socket.getsockname()[:2]
        self.errors = queue.Queue(); self.stop = threading.Event()
        self.received = queue.Queue()
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.stop.is_set():
            try:
                data, peer = self.socket.recvfrom(65536)
                if peer[1] == self.port:
                    raise AssertionError('UDP source collided with guarded echo port')
                self.received.put((time.monotonic(), peer, data)); self.socket.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                return
            except Exception as error:
                self.errors.put(error); return

    def check(self):
        if not self.errors.empty():
            raise self.errors.get()

    def close(self):
        self.stop.set(); self.socket.close(); self.guard.close()


def keys(peer, kind):
    lines = subprocess.check_output([peer, kind], text=True).splitlines()
    values = dict(line.split(': ', 1) for line in lines if ': ' in line)
    return ((values['PrivateKey'], values['Password (PublicKey)']) if kind == 'x25519'
            else (values['Seed'], values['Client']))


class Reservations(list):
    def __init__(self):
        super().__init__()
        self.guards = []


def reserve(reservations):
    tcp, udp, guard = tcp_udp_pair(socket.AF_INET)
    reservations.extend((tcp, udp))
    # Keep IPv6 reserved while the external IPv4 peer is running, so a
    # dual-stack ephemeral socket cannot claim one of its UDP relay ports.
    reservations.guards.append(guard)
    return tcp.getsockname()[1]


def launch(binary, path, port, log):
    child = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
    deadline = time.monotonic() + 8
    while True:
        if child.poll() is not None:
            log.seek(0); raise AssertionError(log.read())
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return child
        except OSError:
            if time.monotonic() >= deadline:
                child.terminate(); child.wait(5); raise AssertionError('reference peer startup timed out')
            time.sleep(.02)


def xray_cases(xray, cert, key, reservations):
    xkey, kemkey, relaykey = keys(xray, 'x25519'), keys(xray, 'mlkem768'), keys(xray, 'x25519')
    inbounds, cases = [], []

    def add(label, appearance=None, chain=None, tls=None, vision=False, padded=True):
        port = reserve(reservations)
        padding = '100-35-35.' if padded else ''
        decryption = 'none' if appearance is None else f'mlkem768x25519plus.{appearance}.600s.{padding}' + '.'.join(k[0] for k in chain)
        user = {'id': UUID}
        if vision:
            user['flow'] = 'xtls-rprx-vision'
        inbound = {'tag': label, 'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                   'settings': {'clients': [user], 'decryption': decryption}, 'streamSettings': {'network': 'raw'}}
        if tls:
            inbound['streamSettings'].update({'security': 'tls', 'tlsSettings': {
                'minVersion': tls, 'maxVersion': tls,
                'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]}})
        inbounds.append(inbound)
        for option in (['xtls-rprx-vision', 'xtls-rprx-vision-udp443'] if vision else ['1rtt', '0rtt']):
            node = {'name': 'proxy', 'type': 'vless', 'server': '127.0.0.1', 'port': port,
                    'uuid': UUID, 'udp-relay': True, 'packet-encoding': 'xudp'}
            if tls:
                node.update({'tls': True, 'tls-server-name': 'localhost'})
            if appearance is None:
                node['encryption'] = 'none'
            else:
                rtt = ('1rtt' if appearance == 'native' else '0rtt') if vision else option
                client_padding = '100-35-35.100-5-5.100-37-37.' if padded and not vision else padding
                node['encryption'] = f'mlkem768x25519plus.{appearance}.{rtt}.{client_padding}' + '.'.join(k[1] for k in chain)
            if vision:
                node['flow'] = option
            cases.append((label + '/' + option, node, vision, option.endswith('udp443') if vision else True))

    for appearance in ['native', 'xorpub', 'random']:
        for name, chain in [('x25519', [xkey]), ('mlkem768', [kemkey]), ('relay', [relaykey, kemkey, xkey])]:
            add(f'encryption-{appearance}-{name}', appearance, chain)
    add('encryption-over-tls', 'random', [xkey], tls='1.3', padded=False)
    add('vision-tls13', tls='1.3', vision=True)
    for appearance in ['native', 'xorpub', 'random']:
        add('vision-encryption-' + appearance, appearance, [xkey], vision=True)
    add('vision-encryption-over-tls12', 'random', [xkey], tls='1.2', vision=True)
    return inbounds, cases


def ss_cases(reservations):
    inbounds, cases = [], []
    for bits in [128, 256]:
        method = f'2022-blake3-aes-{bits}-gcm'
        def key(value):
            return base64.b64encode(bytes([value]) * (bits // 8)).decode()
        for depth in [1, 2, 8]:
            ports = [reserve(reservations) for _ in range(depth)]
            identities = [key(0x31 + i) for i in range(depth)]
            for i in range(depth - 1):
                inbounds.append({'type': 'shadowsocks', 'tag': f'eih-{bits}-{depth}-{i}', 'listen': '127.0.0.1',
                                 'listen_port': ports[i], 'method': method, 'password': identities[i],
                                 'destinations': [{'name': 'next', 'password': identities[i + 1],
                                                   'server': '127.0.0.1', 'server_port': ports[i + 1]}]})
            inbounds.append({'type': 'shadowsocks', 'tag': f'eih-{bits}-{depth}-terminal', 'listen': '127.0.0.1',
                             'listen_port': ports[-1], 'method': method, 'password': identities[-1],
                             'users': [{'name': 'primary', 'password': key(73)}, {'name': 'alternate', 'password': key(74)}]})
            for uot in [False, True]:
                for user in ([73, 74] if depth == 1 else [73]):
                    node = {'name': 'proxy', 'type': 'ss', 'server': '127.0.0.1', 'port': ports[0],
                            'encrypt-method': method, 'password': ':'.join(identities + [key(user)]), 'udp-relay': True}
                    if uot:
                        node.update({'udp-over-tcp': True, 'udp-over-tcp-version': 2})
                    cases.append((f'EIH-AES{bits}/depth{depth}/' + ('UoT' if uot else 'native') + f'/user{user}', node, False, None))
    return inbounds, cases


def policy443(runtime, port, allowed):
    # The peer redirects original destination port 443 to an ephemeral echo.
    # This tests the client policy without requiring privileged local binds.
    control, bound = udp_control(port)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('127.0.0.1', 0)); client.settimeout(2 if allowed else .15)
        payload = b'sdk-original-port-443'
        client.sendto(b'\0\0\0' + address('127.0.0.1', 443) + payload, bound)
        if allowed:
            result = client.recv(65536)
            assert result[:3] == b'\0\0\0' and result.endswith(payload), result
        else:
            try:
                result = client.recv(65536)
                raise AssertionError(('Vision must reject UDP/443', result))
            except socket.timeout:
                pass


def checked_udp(runtime, client, bound, target, payload, label, node, args, cert):
    try:
        udp_exchange(client, bound, target, payload)
    except Exception:
        print('UDP failure label:', label, 'target:', (target.host, target.port), file=sys.stderr, flush=True)
        print('Solaris live records:', runtime.command('L'), file=sys.stderr, flush=True)
        print('Solaris traffic:', runtime.command('F'), file=sys.stderr, flush=True)
        with target.received.mutex:
            observed = list(target.received.queue)[-16:]
        print('Echo received/sent tails:', [(stamp, peer, len(packet), packet[:90]) for stamp, peer, packet in observed], file=sys.stderr, flush=True)
        if not target.errors.empty():
            print('Echo fixture error:', repr(target.errors.queue[0]), file=sys.stderr, flush=True)
        encryption = node.get('encryption', '')
        if args.encryption_control and node['type'] == 'vless' and not node.get('flow'):
            result = subprocess.run([args.encryption_control, 'probe-short', f'127.0.0.1:{node["port"]}', node['encryption'],
                                     str(cert) if node.get('tls') else '-',
                                     f'[{target.host}]:{target.port}' if ':' in target.host else f'{target.host}:{target.port}',
                                     payload.decode(), '3'], capture_output=True, text=True, timeout=10)
            category = 'unsupported comparison (not peer evidence)' if result.returncode == 64 else 'exact target/payload comparison'
            print('Same-peer independent encrypted control:', category, result.returncode, result.stdout, result.stderr,
                  file=sys.stderr, flush=True)
        else:
            print('No matching independent encrypted control for this variant; no peer attribution made.', file=sys.stderr, flush=True)
        raise


def controlled_xudp(conn, tls_context=None):
    channels = {}
    try:
        conn.settimeout(5)
        if tls_context:
            conn = tls_context.wrap_socket(conn, server_side=True)
        assert exact(conn, 19) == b'\0' + bytes.fromhex(UUID.replace('-', '')) + b'\0\3'
        conn.sendall(b'\0\0')
        first = True
        while True:
            metadata = exact(conn, struct.unpack('!H', exact(conn, 2))[0])
            if len(metadata) >= 4 and metadata[2] == 3:
                return
            assert metadata[:5] == b'\0\0' + bytes([1 if first else 2, 1, 2]), metadata
            if first:
                assert len(metadata) >= 16 and metadata[-8:] != bytes(8)
                metadata = metadata[:-8]
            first = False
            port, kind = struct.unpack('!HB', metadata[5:8])
            assert kind in (1, 3)
            host = str(ipaddress.ip_address(metadata[8:]))
            payload = exact(conn, struct.unpack('!H', exact(conn, 2))[0])
            family = socket.AF_INET if kind == 1 else socket.AF_INET6
            if family not in channels:
                channels[family] = socket.socket(family, socket.SOCK_DGRAM)
                channels[family].settimeout(2)
            channels[family].sendto(payload, (host, port))
            reply, peer = channels[family].recvfrom(65536)
            endpoint = struct.pack('!HB', peer[1], kind) + ipaddress.ip_address(peer[0]).packed
            response = b'\0\0\2\1\2' + endpoint
            conn.sendall(struct.pack('!H', len(response)) + response + struct.pack('!H', len(reply)) + reply)
    except (EOFError, ConnectionResetError):
        pass
    finally:
        for channel in channels.values():
            channel.close()
        conn.close()


def controlled_empty_cases(runtime, cert, tls_context, udp4, udp6):
    peers = [Peer(controlled_xudp), Peer(lambda conn: controlled_xudp(conn, tls_context))]
    for encrypted, peer in enumerate(peers):
        node = {'name': 'proxy', 'type': 'vless', 'server': '127.0.0.1', 'port': peer.port,
                'uuid': UUID, 'encryption': 'none', 'packet-encoding': 'xudp', 'udp-relay': True}
        if encrypted:
            node.update({'tls': True, 'tls-server-name': 'localhost'})
        listeners = by_name(runtime.prepare(0, config(18080, 18081, route='proxy') + proxy_config(node), ephemeral=True))
        runtime.commit(0); runtime.command('R', bytes([0]))
        control, bound = udp_control(listeners['socks']['port'])
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(('127.0.0.1', 0))
            for target in (udp4, udp6):
                udp_exchange(client, bound, target, b'control')
                udp_exchange(client, bound, target, b'')
        peer.check()
        print('public controlled XUDP:', 'TLS' if encrypted else 'plain', 'IPv4/IPv6 empty datagrams passed', flush=True)


def test(args):
    for binary, version in [(args.xray, args.xray_version), (args.peer, args.version)]:
        actual = subprocess.check_output([binary, 'version'], text=True).splitlines()[0]
        assert version.removeprefix('v') in actual, actual
    def long_echo(conn):
        conn.settimeout(30); echo(conn)
    tcp = Peer(long_echo)
    udp4, udp6, udp443 = DatagramPeer(socket.AF_INET), DatagramPeer(socket.AF_INET6), DatagramPeer(socket.AF_INET)
    children, logs, runtime, reservations = [], [], None, Reservations()
    with tempfile.TemporaryDirectory(prefix='solaris-runtime-advanced-') as directory:
        root = Path(directory); cert, key, cnf = root / 'cert.pem', root / 'key.pem', root / 'cert.cnf'
        cnf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n'
                       '[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=critical,CA:TRUE\n')
        subprocess.run([shutil.which('openssl'), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                        '-out', str(cert), '-days', '1', '-config', str(cnf)], check=True, capture_output=True, timeout=20)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.minimum_version = server_tls.maximum_version = ssl.TLSVersion.TLSv1_3
        server_tls.load_cert_chain(cert, key)
        client_tls = ssl.create_default_context(cafile=cert)
        client_tls.minimum_version = client_tls.maximum_version = ssl.TLSVersion.TLSv1_3
        def tls_echo(conn):
            conn.settimeout(30)
            with server_tls.wrap_socket(conn, server_side=True) as secure:
                assert secure.version() == 'TLSv1.3'; echo(secure)
        secure_tcp = Peer(tls_echo)
        http_head, https_head = HeadPeer(), TlsHeadPeer(cert, key)
        xray_inbounds, vless = xray_cases(args.xray, cert, key, reservations)
        control_port = reserve(reservations)
        xray_inbounds.append({'tag': 'independent-empty-control', 'listen': '127.0.0.1', 'port': control_port,
                              'protocol': 'vless', 'settings': {'clients': [{'id': UUID}], 'decryption': 'none'},
                              'streamSettings': {'network': 'raw'}})
        ss_inbounds, shadowsocks = ss_cases(reservations)
        tcp_ports = [tcp.port, secure_tcp.port, http_head.peer.port, https_head.peer.port]
        udp_ports = [udp4.port, udp6.port, udp443.port, 443]
        final_rules = [{'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32', '::1/128'], 'port': ','.join(map(str, tcp_ports))},
                       {'action': 'allow', 'network': 'udp', 'ip': ['127.0.0.1/32', '::1/128'], 'port': ','.join(map(str, udp_ports))}]
        xray_config = {'log': {'loglevel': 'warning'}, 'inbounds': xray_inbounds,
                       'routing': {'rules': [{'type': 'field', 'network': 'udp', 'port': '443', 'outboundTag': 'udp443'}]},
                       'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}, 'settings': {'finalRules': final_rules}},
                                     {'tag': 'udp443', 'protocol': 'freedom', 'settings': {'redirect': f'127.0.0.1:{udp443.port}', 'finalRules': final_rules}}]}
        ss_config = {'log': {'level': 'warn'}, 'inbounds': ss_inbounds,
                     'outbounds': [{'type': 'direct', 'tag': 'direct', 'domain_strategy': 'ipv4_only'}], 'route': {'final': 'direct'}}
        (root / 'xray.json').write_text(json.dumps(xray_config)); (root / 'ss.json').write_text(json.dumps(ss_config))
        try:
            for sock in reservations:
                sock.close()
            for binary, path, port in [(args.xray, root / 'xray.json', xray_inbounds[0]['port']),
                                       (args.peer, root / 'ss.json', ss_inbounds[0]['listen_port'])]:
                log = path.with_suffix('.log').open('w+'); logs.append(log)
                children.append(launch(binary, path, port, log))
            runtime = Runtime(args.client); runtime.command('Y', cert.read_bytes())
            bad_cases = []
            overflow = dict(shadowsocks[0][1]); part = overflow['password'].split(':')[0]
            overflow['password'] = ':'.join([part] * 10); bad_cases.append((overflow, -1))
            chacha = dict(overflow); chacha['encrypt-method'] = '2022-blake3-chacha20-poly1305'
            chacha['password'] = ':'.join([base64.b64encode(bytes([85]) * 32).decode()] * 2); bad_cases.append((chacha, -1))
            legacy = dict(shadowsocks[1][1]); legacy.update({'udp-over-tcp': True, 'udp-over-tcp-version': 1}); bad_cases.append((legacy, -3))
            vision_bad = dict(vless[0][1]); vision_bad.update({'encryption': 'none', 'flow': 'xtls-rprx-vision'}); bad_cases.append((vision_bad, -1))
            ws_bad = dict(vless[0][1]); ws_bad['network'] = 'ws'; bad_cases.append((ws_bad, -3))
            for node, expected in bad_cases:
                runtime.prepare(0, config(18080, 18081, route='proxy') + proxy_config(node), ephemeral=True, expected=expected)
                assert runtime.command('Q')['revision'] == 0
            control = subprocess.run([args.control, f'127.0.0.1:{control_port}', UUID, f'{udp4.host}:{udp4.port}'],
                                     check=True, capture_output=True, text=True, timeout=5)
            print(control.stdout.strip(), flush=True)
            print('Reference limitation: pinned Xray empty XUDP is not counted as a passing interop case; controlled public SDK evidence follows.', flush=True)
            controlled_empty_cases(runtime, cert, server_tls, udp4, udp6)
            started = time.monotonic()
            for label, node, vision, allow443 in vless + shadowsocks:
                conf = config(18080, 18081, route='proxy') + proxy_config(node)
                listeners = by_name(runtime.prepare(0, conf, ephemeral=True))
                assert len({item['worker'] for item in listeners.values()}) == 2
                revision = runtime.commit(0)['revision']; runtime.command('R', bytes([0]))
                with ExitStack() as stack:
                    first = stack.enter_context(http_tunnel(listeners['web']['port'], tcp))
                    second = stack.enter_context(socks_tcp(listeners['socks']['port'], tcp))
                    for conn in (first, second): assert_echo(conn, PAYLOAD)
                    inner = []
                    for open_tunnel, port in [(http_tunnel, listeners['web']['port']), (socks_tcp, listeners['socks']['port'])]:
                        raw = open_tunnel(port, secure_tcp)
                        secure = stack.enter_context(client_tls.wrap_socket(raw, server_hostname='localhost'))
                        assert secure.version() == 'TLSv1.3'; assert_echo(secure, PAYLOAD); inner.append(secure)
                    control, bound = udp_control(listeners['socks']['port']); stack.enter_context(control)
                    client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)); client.bind(('127.0.0.1', 0))
                    checked_udp(runtime, client, bound, udp4, b'advanced-ipv4', label, node, args, cert)
                    if node['type'] == 'ss': udp_exchange(client, bound, udp4, b'')
                    if allow443 is not None: policy443(runtime, listeners['socks']['port'], allow443)
                    state = runtime.command('G'); node_id = next(n['id'] for n in state['nodes'] if n['name'] == 'proxy')
                    flows = [entry for entry in runtime.command('L')['connections']
                             if entry['purpose'] == 0 and entry['state'] == 1 and entry['kind'] == 1
                             and entry['node'] and entry['revision'] == revision]
                    assert len(flows) == 4 and {entry['worker'] for entry in flows} == {0, 1}, flows
                    assert all(entry['node'] == node_id and entry['revision'] == revision for entry in flows), flows
                    for target in (http_head, https_head):
                        probe(runtime, revision, node_id, target); result = runtime.command('H')
                        assert result['http'] == 204 and result['node'] == node_id and result['revision'] == revision
                    runtime.prepare(0, config(18080, 18081, route='REJECT'), ephemeral=True)
                    runtime.commit(0); runtime.command('R', bytes([0]))
                    for conn in (first, second, *inner): assert_echo(conn, b'old-advanced-plan-after-publication')
                    checked_udp(runtime, client, bound, udp6, b'old-advanced-new-family', label, node, args, cert)
                assert all(conn.fileno() == -1 for conn in (first, second, *inner))
                # Closing client FDs is not a synchronous remote/observer fence.
                # Exercise the public close barrier before the next generation.
                runtime.command('D')
                assert not runtime.command('L')['connections']
                print('public advanced:', label, 'two owners / TCP+TLS13 / UDP4+reload-UDP6 / probes / retire passed', flush=True)
            runtime.finish(); runtime = None
            print(f'Advanced public SDK matrix: {len(vless)} VLESS + {len(shadowsocks)} EIH combinations, 2 controlled empty-XUDP + {len(bad_cases)} fail-closed cases, {time.monotonic()-started:.2f}s', flush=True)
        except Exception:
            for log in logs:
                log.seek(0); print(log.read()[-16000:], file=sys.stderr)
            raise
        finally:
            if runtime: runtime.abort()
            for child in children:
                child.terminate()
                try: child.wait(5)
                except subprocess.TimeoutExpired: child.kill(); child.wait(5)
            for log in logs: log.close()
            for sock in [*reservations, *reservations.guards]: sock.close()
            for peer in (udp4, udp6, udp443): peer.close()
        tcp.check(); secure_tcp.check(); http_head.peer.check(); https_head.peer.check()
        udp4.check(); udp6.check(); udp443.check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('client'); parser.add_argument('--xray', required=True); parser.add_argument('--xray-version', required=True)
    parser.add_argument('--peer', required=True); parser.add_argument('--version', required=True); parser.add_argument('--control', required=True); parser.add_argument('--encryption-control')
    test(parser.parse_args())
