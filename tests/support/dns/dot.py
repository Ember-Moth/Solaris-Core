#!/usr/bin/env python3
"""Independent OpenSSL-backed DNS-over-TLS peers; ephemeral trust, loopback only."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile

from exchange import Peer


class TLSPeer(Peer):
    def __init__(self, family, mode, context, handshake_delay=0, response_delay=0):
        super().__init__(family, mode)
        self.context = context
        self.handshake_delay, self.response_delay = handshake_delay, response_delay
        self.negotiated = []

    def handle_tcp(self, connection):
        secured = None
        try:
            connection.settimeout(3)
            if self.handshake_delay:
                self.stop.wait(self.handshake_delay)
            secured = self.context.wrap_socket(connection, server_side=True)
            self.negotiated.append(secured.selected_alpn_protocol())
            if self.response_delay:
                self.stop.wait(self.response_delay)
            super().handle_tcp(secured)
        except OSError:
            pass  # expected chain/name failures, cancellation and injected OOM
        finally:
            if secured:
                secured.close()
            connection.close()


def certificates(directory):
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('OpenSSL CLI is required for ephemeral DNS TLS fixtures')
    output = []
    for name in ('trusted', 'other'):
        cert, key = directory / (name + '.pem'), directory / (name + '.key')
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'],
                       check=True, capture_output=True, timeout=20)
        output.append((cert, key))
    return output


def server_context(cert, key, protocols):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    if protocols:
        context.set_alpn_protocols(protocols)
    return context


def run(binary, family, mode, expected, trust, context, timeout=1000, handshake_delay=0, response_delay=0):
    with TLSPeer(family, mode, context, handshake_delay, response_delay) as peer:
        completed = subprocess.run([str(binary), peer.host, str(peer.port), 'tls', mode, str(timeout), str(trust)],
                                   capture_output=True, text=True, timeout=8)
        assert completed.returncode == 0, (family, mode, completed.returncode, completed.stdout, completed.stderr)
        result = json.loads(completed.stdout)
        assert result['closed'] == 1 and result['callbacks'] == result['accepted'] and result['udp'] == 0 and result['fallback'] == 0, (mode, result)
        if mode.startswith('fail_'):
            assert result['status'] == (-2 if result['allocation_failures'] else 0), (mode, result)
        else:
            expected = expected if isinstance(expected, tuple) else (expected,)
            accepted = 0 if mode in ('missing_trust', 'missing_identity', 'invalid_identity', 'tlsfields_on_tcp') else 1
            assert result['status'] in expected and result['accepted'] == accepted, (mode, result)
        if result['status'] == 0:
            assert result['alpn_length'] == (0 if mode == 'no_alpn' else 3), (mode, result)
            assert peer.tcp_queries == 1 and peer.udp_queries == 0, (mode, result)
        if mode in ('deny', 'deny_deadline', 'network_changed', 'network_deadline',
                    'cancel_before', 'cancel_protect', 'deadline_protect',
                    'missing_trust', 'missing_identity', 'invalid_identity', 'tlsfields_on_tcp'):
            peer.fence_requested.set()
            assert peer.fence_done.wait(2), peer.errors
            assert peer.tcp_connections == 0 and peer.udp_queries == 0 and result['bytes_written'] == 0, (mode, result)
        if mode in ('wrong_ca', 'wrong_name', 'alpn_missing', 'alpn_mismatch'):
            assert peer.tcp_queries == 0 and result['bytes_written'] == 0, (mode, result)
    assert not peer.errors, (mode, peer.errors)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert json.loads(subprocess.check_output([str(binary), '--capabilities'], text=True))['tls'], 'DoT contract requires TLS build'
    count, failures = 0, 0
    with tempfile.TemporaryDirectory(prefix='solaris-dns-tls-') as temporary:
        (trusted, key), (other, _) = certificates(Path(temporary))
        dot = server_context(trusted, key, ['dot'])
        no_alpn = server_context(trusted, key, [])
        mismatch = server_context(trusted, key, ['h2'])
        for family in (socket.AF_INET, socket.AF_INET6):
            for mode, expected, trust, context in [
                ('normal', 0, trusted, dot), ('numeric_identity', 0, trusted, dot),
                ('alpn_required', 0, trusted, dot), ('no_alpn', 0, trusted, no_alpn),
                ('wrong_ca', -13, other, dot), ('wrong_name', -13, trusted, dot),
                ('missing_trust', -1, trusted, dot), ('missing_identity', -1, trusted, dot),
                ('invalid_identity', -1, trusted, dot), ('tlsfields_on_tcp', -1, trusted, dot),
                ('alpn_missing', -3, trusted, no_alpn), ('alpn_mismatch', (-3, -8), trusted, mismatch),
                ('split', 0, trusted, dot), ('wrongframes', 0, trusted, dot),
                ('truncated', -8, trusted, dot), ('malformed', -1, trusted, dot), ('oversize', -14, trusted, dot),
                ('deny', -13, trusted, dot), ('deny_deadline', -13, trusted, dot),
                ('network_changed', -15, trusted, dot), ('network_deadline', -15, trusted, dot),
                ('cancel_before', -9, trusted, dot), ('cancel_protect', -9, trusted, dot),
                ('deadline_protect', -6, trusted, dot), ('cancel', -9, trusted, dot), ('stop', -9, trusted, dot),
                ('timeout', -6, trusted, dot),
            ]:
                run(binary, family, mode, expected, trust, context, 120 if mode == 'timeout' else 1000)
                count += 1
            for mode, expected in [('cancel', -9), ('stop', -9), ('timeout', -6)]:
                run(binary, family, mode, expected, trusted, dot, 100 if mode == 'timeout' else 1000, handshake_delay=0.2)
                count += 1
            run(binary, family, 'handshake_budget', -6, trusted, dot, 250, handshake_delay=0.18, response_delay=0.12)
            count += 1
        for allocation in range(1, 49):
            result = run(binary, socket.AF_INET, f'fail_{allocation}', None, trusted, dot)
            failures += result['allocation_failures']; count += 1
    assert failures >= 15, failures
    print(f'{count} DNS-over-TLS cases passed: IPv4/IPv6, independent CA/name/ALPN checks, framing, total deadline, protection/cancel/stop barriers and {failures} injected allocation failures ({ssl.OPENSSL_VERSION})')


if __name__ == '__main__':
    main()
