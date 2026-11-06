#!/usr/bin/env python3
"""AnyTLS v2 against pinned sing-box, with independent TCP and UDP endpoints."""
import argparse
import json
import hashlib
import ssl
import struct
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

PASSWORD = 'solaris-anytls-independent-peer'
PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--association-client')
    parser.add_argument('client')
    parser.add_argument('--udp-client', required=True)
    parser.add_argument('--peer', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.peer, 'version'], text=True).splitlines()[0]
    assert args.version.removeprefix('v') in version
    sockets, threads, failures, complete = [], [], [], []
    controlled_sessions = []
    stop = threading.Event()
    peer = None

    def echo(conn):
        data = bytearray()
        try:
            with conn:
                conn.settimeout(5)
                while True:
                    b = conn.recv(3029)
                    if not b:
                        break
                    data.extend(b)
                    conn.sendall(b)
        except (OSError, ConnectionError):
            pass
        if data:
            if data != PAYLOAD:
                failures.append(f'incomplete TCP content: {len(data)}')
            else:
                complete.append(True)

    def tcp(sock):
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                thread = threading.Thread(target=echo, args=(conn,), daemon=True)
                threads.append(thread)
                thread.start()
            except socket.timeout:
                pass
            except OSError:
                break

    def udp(sock):
        while not stop.is_set():
            try:
                data, source = sock.recvfrom(65536)
                sock.sendto(data, source)
            except socket.timeout:
                pass
            except OSError:
                break

    def frame(command, stream=0, data=b''):
        return struct.pack('!BIH', command, stream, len(data)) + data

    def controlled(conn, tls, mode):
        streams, last_id, complete_count = {}, 0, 0
        try:
            with tls.wrap_socket(conn, server_side=True) as wire:
                wire.settimeout(5)

                def exact(n):
                    data = bytearray()
                    while len(data) < n:
                        value = wire.recv(n - len(data))
                        if not value:
                            raise EOFError()
                        data.extend(value)
                    return bytes(data)

                assert exact(32) == hashlib.sha256(PASSWORD.encode()).digest()
                padding_length = struct.unpack('!H', exact(2))[0]
                assert padding_length == 30
                assert exact(padding_length) == bytes(padding_length)
                settings = False
                while True:
                    command, stream, length = struct.unpack('!BIH', exact(7))
                    data = exact(length)
                    if command == 0:
                        continue
                    if command == 4:
                        assert not settings and stream == 0
                        settings = True
                        assert b'v=2' in data and b'client=Solaris/0.1.0' in data
                        response = frame(10, data=b'v=2') + frame(6, data=b'stop=2\n0=41-41\n1=42-42')
                        if mode == 'version':
                            response = frame(10, data=b'v=1')
                        elif mode == 'unknown':
                            response = frame(255)
                        elif mode == 'truncated':
                            wire.sendall(b'\x0a\x00')
                            return
                        for part in range(0, len(response), 3):
                            wire.sendall(response[part:part+3])
                        continue
                    if command == 1:
                        assert settings and not data and stream > last_id
                        last_id = stream
                        streams[stream] = None
                        continue
                    if command == 2:
                        assert stream in streams
                        if streams[stream] is None:
                            assert len(data) == 7 and data[0] == 1
                            streams[stream] = bytearray()
                            wire.sendall(frame(7, stream, b'refused' if mode == 'denied' else b''))
                        else:
                            streams[stream].extend(data)
                            wire.sendall(frame(2, stream, data))
                        continue
                    if command == 3:
                        assert not data and streams.pop(stream) == PAYLOAD
                        complete_count += 1
                        continue
                    raise AssertionError(f'unexpected command {command}')
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as exc:
            failures.append(f'controlled {mode}: {exc!r}')
        finally:
            conn.close()
            if mode == 'reuse':
                controlled_sessions.append(complete_count)

    def listen_controlled(sock, tls, mode):
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                thread = threading.Thread(target=controlled, args=(conn, tls, mode), daemon=True)
                threads.append(thread)
                thread.start()
            except socket.timeout:
                pass
            except OSError:
                break

    with tempfile.TemporaryDirectory(prefix='solaris-anytls-') as directory:
        root = Path(directory)
        try:
            for family, host, kind in [(socket.AF_INET, '127.0.0.1', socket.SOCK_STREAM),
                                        (socket.AF_INET6, '::1', socket.SOCK_STREAM),
                                        (socket.AF_INET, '127.0.0.1', socket.SOCK_DGRAM),
                                        (socket.AF_INET, '127.0.0.1', socket.SOCK_DGRAM),
                                        (socket.AF_INET6, '::1', socket.SOCK_DGRAM)]:
                sock = socket.socket(family, kind)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, 0))
                sock.settimeout(0.1)
                if kind == socket.SOCK_STREAM:
                    sock.listen(32)
                sockets.append(sock)
                thread = threading.Thread(target=tcp if kind == socket.SOCK_STREAM else udp, args=(sock,), daemon=True)
                threads.append(thread)
                thread.start()
            key, cert = root / 'peer.key', root / 'peer.pem'
            conf = root / 'cert.cnf'
            conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n')
            subprocess.run([shutil.which('openssl'), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '1', '-config', str(conf)],
                           check=True, capture_output=True)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            config = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'anytls', 'listen': '127.0.0.1',
                      'listen_port': port, 'padding_scheme': ['stop=4', '0=19-19', '1=111-111', '2=40-40,c,100-100', '3=20-20'], 'users': [{'name': 'solaris-test', 'password': PASSWORD}],
                      'tls': {'enabled': True, 'certificate_path': str(cert), 'key_path': str(key)}}],
                      'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
            config_path = root / 'config.json'
            config_path.write_text(json.dumps(config))
            with (root / 'peer.log').open('w+') as log:
                peer = subprocess.Popen([args.peer, 'run', '-c', str(config_path)], stdout=log, stderr=log)
                until = time.monotonic() + 5
                while True:
                    if peer.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        if time.monotonic() >= until:
                            raise RuntimeError('peer startup timed out')
                        time.sleep(.02)

                def run(command):
                    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                    print(result.stdout, end='')
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f'client {result.returncode}: {result.stderr}\npeer: {log.read()}')

                for mode, host, target in [(0, '127.0.0.1', 0), (0, '::1', 1), (0, 'localhost', 0),
                                            (1, '127.0.0.1', 0), (2, '127.0.0.1', 0), (3, '127.0.0.1', 0)]:
                    run([args.client, 'anytls', str(port), host, str(sockets[target].getsockname()[1]),
                         PASSWORD if mode != 3 else 'wrong', '-', str(cert), str(mode)])
                run([args.client, 'anytls', str(port), '127.0.0.1', str(sockets[0].getsockname()[1]), PASSWORD, '-', str(cert), '0', '3'])
                for mode, host in [(0, '127.0.0.1'), (0, 'localhost'), (4, '127.0.0.1'), (5, '127.0.0.1'),
                                   (1, 'localhost'), (2, '127.0.0.1'), (3, '127.0.0.1')]:
                    run([args.udp_client, 'anytls', str(port), PASSWORD if mode != 3 else 'wrong', '-',
                         *(str(s.getsockname()[1]) for s in sockets[2:]), str(mode), host, 'uot', str(cert)])
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                if args.association_client:
                    run([args.association_client, 'anytls', str(port), PASSWORD, '-',
                         *(str(s.getsockname()[1]) for s in sockets[2:]), '6', 'localhost', 'uot', str(cert)])
                tls.load_cert_chain(cert, key)
                for mode in ['reuse', 'version', 'unknown', 'truncated', 'denied']:
                    sock = socket.socket()
                    sock.bind(('127.0.0.1', 0))
                    sock.listen(8)
                    sock.settimeout(.1)
                    sockets.append(sock)
                    thread = threading.Thread(target=listen_controlled, args=(sock, tls, mode), daemon=True)
                    threads.append(thread)
                    thread.start()
                    command = [args.client, 'anytls', str(sock.getsockname()[1]), '127.0.0.1',
                               str(sockets[0].getsockname()[1]), PASSWORD, '-', str(cert), '0' if mode == 'reuse' else '3']
                    if mode == 'reuse':
                        command.append('3')
                    run(command)
                until = time.monotonic() + 3
                while len(controlled_sessions) < 2 and time.monotonic() < until:
                    time.sleep(.01)
                assert controlled_sessions == [3, 3], controlled_sessions
                until = time.monotonic() + 3
                while len(complete) < 12 and time.monotonic() < until:
                    time.sleep(.01)
                assert not failures and len(complete) == 12, (failures, len(complete))
                print('AnyTLS TCP/UoT: two workers, IPv4/IPv6/domain, empty packets, backpressure and cancellation passed')
        finally:
            stop.set()
            for sock in sockets:
                sock.close()
            if peer:
                peer.terminate()
                try:
                    peer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.wait()
            for thread in threads:
                thread.join(timeout=1)


if __name__ == '__main__':
    main()
