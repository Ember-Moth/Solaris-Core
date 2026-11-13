#!/usr/bin/env python3
"""Public Conf/SDK activation against the pinned independent protocol peer."""
import argparse
import base64
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from runtime_proxy import (proxy_config, Runtime, Peer, echo, config, by_name, http_tunnel,
                           socks_tcp, udp_control, udp_exchange, assert_echo)
from runtime_control import HeadPeer, probe


class TlsHeadPeer(HeadPeer):
    def __init__(self, cert, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        super().__init__()
        self.url = self.url.replace('http:', 'https:', 1)

    def handle(self, conn):
        with self.context.wrap_socket(conn, server_side=True) as secure:
            super().handle(secure)


def test(args):
    version = subprocess.check_output([args.peer, 'version'], text=True).splitlines()[0]
    assert args.version.removeprefix('v') in version, version
    methods = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
               '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
               '2022-blake3-chacha20-poly1305']
    uuid = '00112233-4455-6677-8899-aabbccddeeff'
    password = 'solaris-runtime-interop'
    runtime, peer = None, None
    tcp, udp4, udp6 = Peer(echo), Peer(None, udp=True), Peer(None, socket.AF_INET6, udp=True)
    with tempfile.TemporaryDirectory(prefix='solaris-runtime-protocol-') as directory:
        root = Path(directory)
        key, cert = root / 'key.pem', root / 'cert.pem'
        conf = root / 'cert.cnf'
        conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                        '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                        'basicConstraints=critical,CA:TRUE\n')
        subprocess.run([shutil.which('openssl'), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1', '-config', str(conf)],
                       check=True, capture_output=True)
        http_head, https_head = HeadPeer(), TlsHeadPeer(cert, key)
        reservations = [socket.socket() for _ in range(10)]
        for sock in reservations:
            sock.bind(('127.0.0.1', 0))
        ports = [sock.getsockname()[1] for sock in reservations]
        tls = {'enabled': True, 'certificate_path': str(cert), 'key_path': str(key)}
        inbounds, cases = [], []
        for index, method in enumerate(methods):
            secret = (base64.b64encode(bytes([73]) * (16 if 'aes-128' in method else 32)).decode()
                      if method.startswith('2022-') else password)
            inbounds.append({'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': ports[index],
                             'method': method, 'password': secret})
            for uot in (False, True):
                node = {'name': 'proxy', 'type': 'ss', 'server': '127.0.0.1', 'port': ports[index],
                        'encrypt-method': method, 'password': secret, 'udp-relay': True}
                if uot:
                    node.update({'udp-over-tcp': True, 'udp-over-tcp-version': 2})
                cases.append((method + (' UoT' if uot else ' native'), node))
        for offset, encrypted in enumerate((False, True), 6):
            inbound = {'type': 'vless', 'listen': '127.0.0.1', 'listen_port': ports[offset],
                       'users': [{'uuid': uuid}]}
            node = {'name': 'proxy', 'type': 'vless', 'server': '127.0.0.1', 'port': ports[offset],
                    'uuid': uuid, 'encryption': 'none', 'udp-relay': True, 'packet-encoding': 'xudp'}
            if encrypted:
                inbound['tls'] = tls
                node.update({'tls': True, 'tls-server-name': 'localhost'})
            inbounds.append(inbound)
            cases.append(('VLESS TLS' if encrypted else 'VLESS plain', node))
        inbounds.append({'type': 'anytls', 'listen': '127.0.0.1', 'listen_port': ports[8],
                         'users': [{'name': 'runtime', 'password': password}], 'tls': tls})
        cases.append(('AnyTLS', {'name': 'proxy', 'type': 'anytls', 'server': '127.0.0.1',
                                 'port': ports[8], 'password': password, 'tls-server-name': 'localhost', 'udp-relay': True}))
        inbounds.append({'type': 'socks', 'listen': '127.0.0.1', 'listen_port': ports[9],
                         'users': [{'username': 'runtime', 'password': password}]})
        cases.append(('SOCKS5', {'name': 'proxy', 'type': 'socks5', 'server': '127.0.0.1',
                                 'port': ports[9], 'username': 'runtime', 'password': password, 'udp-relay': True}))
        for index, inbound in enumerate(inbounds):
            inbound['tag'] = f'peer-{index}'
        peer_config = root / 'config.json'
        peer_config.write_text(json.dumps({'log': {'level': 'warn'}, 'inbounds': inbounds,
                                          'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                                          'route': {'final': 'direct'}}))
        with (root / 'peer.log').open('w+') as log:
            try:
                for sock in reservations:
                    sock.close()
                peer = subprocess.Popen([args.peer, 'run', '-c', str(peer_config)], stdout=log, stderr=log)
                deadline = time.monotonic() + 5
                while True:
                    if peer.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', ports[0]), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, 'peer startup timed out'
                        time.sleep(.02)
                runtime = Runtime(args.client)
                tls_node = next(node for label, node in cases if label == 'VLESS TLS')
                tls_conf = config(18080, 18081, route='proxy') + proxy_config(tls_node)
                runtime.prepare(0, tls_conf, ephemeral=True, expected=-1)
                runtime.command('Y', b'not-a-PEM-trust-bundle')
                runtime.prepare(0, tls_conf, ephemeral=True, expected=-1)
                assert runtime.command('Q')['revision'] == 0
                runtime.command('Y', cert.read_bytes())
                for label, node in cases:
                    conf = config(18080, 18081, route='proxy') + proxy_config(node)
                    prepared = runtime.prepare(0, conf, ephemeral=True)
                    listeners = by_name(prepared)
                    assert len({x['worker'] for x in listeners.values()}) == 2
                    revision = runtime.commit(0)['revision']
                    runtime.command('R', bytes([0]))
                    with http_tunnel(listeners['web']['port'], tcp) as first:
                        with socks_tcp(listeners['socks']['port'], tcp) as second:
                            for conn in (first, second):
                                assert_echo(conn, bytes((i * 17 + 29) & 255 for i in range(65541)))
                            control, bound = udp_control(listeners['socks']['port'])
                            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                                client.bind(('127.0.0.1', 0))
                                udp_exchange(client, bound, udp4, b'public-sdk-ipv4')
                                udp_exchange(client, bound, udp6, b'public-sdk-ipv6')
                                state = runtime.command('G')
                                node_id = next(n['id'] for n in state['nodes'] if n['name'] == 'proxy')
                                before_probe = runtime.command('F')['logical'][1]['read']
                                for head in (http_head, https_head):
                                    probe(runtime, revision, node_id, head)
                                    result = runtime.command('H')
                                    assert result['http'] == 204 and result['node'] == node_id
                                    assert result['revision'] == revision and result['read'] and result['written']
                                assert runtime.command('F')['logical'][1]['read'] > before_probe
                                # A live old protocol instance must survive publication and
                                # the release of both its prepared handle and active reference.
                                next_config = config(18080, 18081, route='REJECT')
                                runtime.prepare(0, next_config, ephemeral=True)
                                runtime.commit(0)
                                runtime.command('R', bytes([0]))
                                assert_echo(first, b'old-protocol-after-publication')
                                assert_echo(second, b'old-second-owner-after-publication')
                                udp_exchange(client, bound, udp4, b'old-protocol-association')
                    print('public runtime:', label, 'two owners / TCP / UDP4+6 / HTTP+HTTPS probes / retire passed', flush=True)
                runtime.finish()
                runtime = None
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                for sock in reservations:
                    sock.close()
                if runtime is not None and runtime.child.poll() is None:
                    runtime.child.kill()
                    runtime.child.wait(timeout=5)
                if peer is not None:
                    peer.terminate()
                    peer.wait(timeout=5)
    tcp.check()
    udp4.check()
    udp6.check()
    http_head.peer.check()
    https_head.peer.check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('client')
    parser.add_argument('--peer', required=True)
    parser.add_argument('--version', required=True)
    test(parser.parse_args())
