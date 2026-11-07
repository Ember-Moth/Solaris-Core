#!/usr/bin/env python3
"""Verified HTTPS targets for the public SDK probe; no public-network access."""
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def main(binary):
    openssl = shutil.which('openssl')
    if not openssl:
        print('HTTPS probe test skipped: openssl unavailable')
        return 77
    with tempfile.TemporaryDirectory(prefix='solaris-sdk-probe-') as directory:
        root = Path(directory)
        for name in ['trusted', 'untrusted']:
            subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(root / (name + '.key')), '-out', str(root / (name + '.pem')),
                            '-subj', '/CN=probe.invalid', '-addext', 'subjectAltName=IP:127.0.0.1'],
                           check=True, capture_output=True, timeout=20)
        (root / 'invalid.pem').write_text('not a PEM trust bundle')
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / 'trusted.pem', root / 'trusted.key')
        sockets, threads, requests, failures, handshake_failures = [], [], [], [], []
        stop = threading.Event()

        def handle(conn, secure):
            try:
                with conn:
                    conn.settimeout(5)
                    if secure:
                        try:
                            conn = tls.wrap_socket(conn, server_side=True)
                        except ssl.SSLError as error:
                            handshake_failures.append(str(error))
                            return  # expected for bad CA / bad identity
                    with conn:
                        data = bytearray()
                        while not data.endswith(b'\r\n\r\n'):
                            block = conn.recv(4096)
                            if not block:
                                return
                            data.extend(block)
                            assert len(data) < 4096
                        assert data.startswith(b'HEAD /secure HTTP/1.1\r\n')
                        requests.append(secure)
                        conn.sendall(b'HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n')
            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception as error:
                failures.append(error)

        def accept(listener, secure):
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                    thread = threading.Thread(target=handle, args=(conn, secure), daemon=True)
                    threads.append(thread); thread.start()
                except socket.timeout:
                    continue
                except OSError:
                    return

        try:
            ports = {}
            for secure in [False, True]:
                listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(16); listener.settimeout(.1)
                sockets.append(listener); ports[secure] = listener.getsockname()[1]
                threading.Thread(target=accept, args=(listener, secure), daemon=True).start()
            plain = f'http://127.0.0.1:{ports[False]}/secure'
            secure = f'https://127.0.0.1:{ports[True]}/secure'
            wrong_host = f'https://localhost:{ports[True]}/secure'
            for url, trust, expected in [(plain, '-', 0), (secure, 'trusted.pem', 0),
                                         (secure, '-', -1), (secure, 'invalid.pem', -1),
                                         (secure, 'untrusted.pem', 999), (wrong_host, 'trusted.pem', 999)]:
                previous_failures = len(handshake_failures)
                previous_requests = len(requests)
                result = subprocess.run([binary, url, str(root / trust) if trust != '-' else '-', str(expected)],
                                        capture_output=True, text=True, timeout=15)
                assert result.returncode == 0, (url, trust, result.stdout, result.stderr)
                if url == wrong_host or trust == 'untrusted.pem':
                    deadline = time.monotonic() + 2
                    while len(handshake_failures) == previous_failures and time.monotonic() < deadline:
                        time.sleep(.01)
                    assert len(handshake_failures) > previous_failures, (url, 'client failed without reaching the TLS server')
                    assert len(requests) == previous_requests, (url, 'untrusted connection sent HTTP bytes')
            for thread in threads:
                thread.join(2)
            assert not failures, failures
            assert sorted(requests) == [False, True], requests
            print('Public HTTP/HTTPS probes: copied trust, valid CA, missing/malformed/wrong CA and identity rejection passed')
        finally:
            stop.set()
            for listener in sockets:
                listener.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1]))
