#!/usr/bin/env python3
"""Independent RFC 6455 clients/servers exercise the proxy's opaque tunnel boundary."""
import argparse
import base64
import concurrent.futures
import hashlib
import os
import queue
import socket
import shutil
import sys
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from inbound import Harness, Peer, exact, until, all_bytes

KEY = b'dGhlIHNhbXBsZSBub25jZQ=='
GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
AUTH = b'Proxy-Authorization: Basic dXNlcjpwYXNz\r\n'


def frame(opcode, payload=b'', fin=True, masked=False, compressed=False):
    head = bytearray([(128 if fin else 0) | (64 if compressed else 0) | opcode])
    n = len(payload); mask_bit = 128 if masked else 0
    if n < 126:
        head.append(mask_bit | n)
    elif n <= 65535:
        head.append(mask_bit | 126); head.extend(struct.pack('!H', n))
    else:
        head.append(mask_bit | 127); head.extend(struct.pack('!Q', n))
    if masked:
        key = os.urandom(4); head.extend(key)
        payload = bytes(value ^ key[i % 4] for i, value in enumerate(payload))
    return bytes(head) + payload


def read_frame(conn, masked):
    a, b = exact(conn, 2)
    assert bool(b & 128) == masked
    n = b & 127
    if n == 126:
        n = struct.unpack('!H', exact(conn, 2))[0]
    elif n == 127:
        n = struct.unpack('!Q', exact(conn, 8))[0]
    assert n <= 2 * 1024 * 1024
    key = exact(conn, 4) if masked else None
    data = exact(conn, n)
    if key:
        data = bytes(value ^ key[i % 4] for i, value in enumerate(data))
    return bool(a & 128), a & 15, bool(a & 64), data


def headers(conn):
    raw = until(conn)
    lines = raw.split(b'\r\n')
    fields = {k.lower(): v.strip() for k, v in (line.split(b':', 1) for line in lines[1:-2])}
    return lines[0], fields


def switching(fields):
    accept = base64.b64encode(hashlib.sha1(fields[b'sec-websocket-key'] + GUID).digest())
    return (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            b'Sec-WebSocket-Accept: ' + accept + b'\r\nSec-WebSocket-Protocol: chat\r\n'
            b'Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n')


def websocket(conn):
    try:
        line, fields = headers(conn)
    except EOFError:
        return
    conn.settimeout(60)
    assert line.startswith(b'GET /') and fields[b'upgrade'].lower() == b'websocket'
    assert fields[b'sec-websocket-version'] == b'13' and fields[b'origin'] == b'http://origin.example'
    assert fields[b'cookie'] == b'session=value' and b'proxy-authorization' not in fields
    if b'/direct' in line:
        assert fields[b'connection'].lower() == b'upgrade' and b'x-remove' not in fields
        # Early client frames must remain on the proxy until the 101 boundary.
        conn.settimeout(.025)
        try:
            assert not conn.recv(1), 'client bytes forwarded before 101'
        except socket.timeout:
            pass
        conn.settimeout(60)
    reply = switching(fields)
    if b'/large' in line:
        reply = reply[:-2] + b'X-Padding: ' + b'x' * 28000 + b'\r\n\r\n'
    if b'/split' in line:
        for value in reply:
            conn.sendall(bytes([value]))
        conn.sendall(frame(1, b'welcome') + frame(9, b'server-ping'))
    else:
        conn.sendall(b'HTTP/1.1 103 Early Hints\r\nLink: </chat>\r\n\r\n' + reply +
                     frame(1, b'welcome') + frame(9, b'server-ping'))
    fragments = bytearray(); message_type = 0; compressed = False
    while True:
        try:
            fin, op, rsv, data = read_frame(conn, True)
        except (EOFError, ConnectionResetError, ssl.SSLEOFError):
            return
        if op == 8:
            conn.sendall(frame(8, data)); return
        if op == 9:
            conn.sendall(frame(10, data)); continue
        if op == 10:
            assert data == b'server-ping'; continue
        if op in (1, 2):
            assert not message_type
            message_type, compressed = op, rsv
        else:
            assert op == 0 and message_type and not rsv
        fragments.extend(data)
        if fin:
            payload = bytes(fragments)
            if compressed:
                payload = zlib.decompressobj(-15).decompress(payload + b'\x00\x00\xff\xff')
            conn.sendall(frame(message_type, payload))
            message_type = 0; fragments.clear()


def request(peer, path='/direct', absolute=True, auth=False):
    target = f'http://localhost:{peer.port}{path}' if absolute else path
    return (f'GET {target} HTTP/1.1\r\nHost: localhost:{peer.port}\r\n'.encode() +
            b'Connection: keep-alive, Upgrade, X-Remove\r\nUpgrade: websocket\r\nX-Remove: private\r\n' +
            b'Sec-WebSocket-Key: ' + KEY + b'\r\nSec-WebSocket-Version: 13\r\n' +
            b'Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n' +
            b'Origin: http://origin.example\r\nCookie: session=value\r\n' + (AUTH if auth else b'') + b'\r\n')


def connect(h, peer, *, auth=False, tunnel=False, tls=None, split=False, early=False, large=False):
    conn = h.connect(); conn.settimeout(8)
    if tunnel:
        conn.sendall(f'CONNECT localhost:{peer.port} HTTP/1.1\r\nHost: localhost:{peer.port}\r\n'.encode() +
                     (AUTH if auth else b'') + b'\r\n')
        assert until(conn).startswith(b'HTTP/1.1 200 ')
    if tls:
        conn = tls.wrap_socket(conn, server_hostname='localhost')
    path = '/large' if large else '/split' if split else '/connect' if tunnel else '/direct'
    head = request(peer, path, not tunnel, auth and not tunnel)
    if split:
        for value in head:
            conn.sendall(bytes([value]))
    else:
        conn.sendall(head + (frame(1, b'early', masked=True) if early else b''))
    while True:
        line, fields = headers(conn)
        if not line.startswith(b'HTTP/1.1 103 '):
            break
    assert line.startswith(b'HTTP/1.1 101 '), (line, fields)
    assert fields[b'upgrade'].lower() == b'websocket'
    assert fields[b'sec-websocket-accept'] == base64.b64encode(hashlib.sha1(KEY + GUID).digest())
    assert fields[b'sec-websocket-protocol'] == b'chat' and b'permessage-deflate' in fields[b'sec-websocket-extensions']
    assert read_frame(conn, False) == (True, 1, False, b'welcome')
    assert read_frame(conn, False) == (True, 9, False, b'server-ping')
    conn.sendall(frame(10, b'server-ping', masked=True))
    if early:
        assert read_frame(conn, False) == (True, 1, False, b'early')
    return conn


def exercise(conn):
    payload = os.urandom(140000)
    conn.sendall(frame(2, payload[:70000], False, True) + frame(9, b'interleaved', masked=True) +
                 frame(0, payload[70000:], True, True))
    assert read_frame(conn, False) == (True, 10, False, b'interleaved')
    assert read_frame(conn, False) == (True, 2, False, payload)
    message = b'compression survives the proxy ' * 3000
    compressor = zlib.compressobj(wbits=-15)
    compressed = (compressor.compress(message) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
    conn.sendall(frame(1, compressed, masked=True, compressed=True))
    assert read_frame(conn, False) == (True, 1, False, message)
    # Backpressure with a message larger than all configured user-space queues.
    payload = os.urandom(600000)
    conn.sendall(frame(2, payload, masked=True)); time.sleep(.02)
    assert read_frame(conn, False) == (True, 2, False, payload)


def close(conn):
    payload = struct.pack('!H', 1000) + b'finished'
    conn.sendall(frame(8, payload, masked=True))
    assert read_frame(conn, False) == (True, 8, False, payload)
    assert not all_bytes(conn)
    conn.close()


def rejected(h):
    for wire, expected in [
        (b'HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno!PIPELINED', b'HTTP/1.1 403 '),
        (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n', b'HTTP/1.1 502 '),
        (b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n', b'HTTP/1.1 502 '),
        (b'HTTP/1.1 103 Early Hints\r\n\r\n', b'HTTP/1.1 502 '),
        (b'HTTP/1.1 101 Switching Protocols\r\nX: ' + b'x' * 1100, b'HTTP/1.1 502 '),
    ]:
        observed = queue.Queue()
        def peer(conn):
            headers(conn); conn.sendall(wire)
            if wire.startswith(b'HTTP/1.1 103'):
                conn.shutdown(socket.SHUT_WR)
            observed.put(all_bytes(conn))
        origin = Peer(peer)
        h.start(header=1024)
        with h.connect() as conn:
            conn.sendall(request(origin) + frame(1, b'must-stay-buffered', masked=True))
            output = all_bytes(conn); assert output.startswith(expected), output
            if expected.startswith(b'HTTP/1.1 403'):
                assert output.endswith(b'no!') and b'PIPELINED' not in output
        assert observed.get(timeout=3) == b''
        h.stop(); origin.check()
    def stalled(conn):
        headers(conn); assert not all_bytes(conn)
    origin = Peer(stalled)
    h.start(handshake=100)
    with h.connect() as conn:
        conn.sendall(request(origin)); assert all_bytes(conn).startswith(b'HTTP/1.1 504 ')
    h.stop(); origin.check()


def failures(h, peer):
    h.start(auth=True)
    with h.connect() as conn:
        conn.sendall(request(peer)); assert all_bytes(conn).startswith(b'HTTP/1.1 407 ')
    h.stop()
    for allocation in range(16):
        h.start(); conn = h.connect()
        while h.stats()[0] != 1:
            pass
        h.command('M', struct.pack('!i', allocation))
        conn.sendall(request(peer)); conn.settimeout(.03)
        try:
            conn.recv(1024)
        except (socket.timeout, ConnectionResetError):
            pass
        h.command('M', struct.pack('!i', -1)); conn.close(); h.stop()
    for allocation in range(16):
        ready, release = threading.Event(), threading.Event()
        def response(conn):
            _, fields = headers(conn); ready.set(); assert release.wait(2)
            conn.sendall(switching(fields)); all_bytes(conn)
        origin = Peer(response); h.start(); conn = h.connect(); conn.sendall(request(origin))
        assert ready.wait(2)
        h.command('M', struct.pack('!i', allocation)); release.set(); conn.settimeout(.03)
        try:
            conn.recv(1024)
        except (socket.timeout, ConnectionResetError):
            pass
        h.command('M', struct.pack('!i', -1)); conn.close(); h.stop(); origin.check()
    print('WebSocket authentication and handshake/response allocation rollback passed', flush=True)


def test(binary, duration):
    h = Harness(binary); peer = Peer(websocket)
    with tempfile.TemporaryDirectory(prefix='solaris-websocket-') as directory:
        cert, key = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                        '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost'], check=True, capture_output=True, timeout=20)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_tls.load_cert_chain(cert, key)
        client_tls = ssl.create_default_context(cafile=cert)
        def secure(conn):
            with server_tls.wrap_socket(conn, server_side=True) as secured:
                websocket(secured)
        tls_peer = Peer(secure)
        for protocol in [1, 3]:
            for auth in [False, True]:
                h.start(protocol=protocol, auth=auth)
                for origin, tunnel, tls in [(peer, False, None), (peer, True, None), (tls_peer, True, client_tls)]:
                    conn = connect(h, origin, auth=auth, tunnel=tunnel, tls=tls, early=not tunnel)
                    exercise(conn); close(conn)
                conn = connect(h, peer, auth=auth, split=True); close(conn)
                h.stop()
        print('WS Upgrade, CONNECT WS/WSS, auth, split/coalesced handshakes, compression, fragmentation and close passed', flush=True)
        h.start(); conn = connect(h, peer, large=True); exercise(conn); close(conn); h.stop()
        rejected(h)
        failures(h, peer)
        timed = Harness(binary, "--manual-clock")
        timed.start(handshake=2000, idle=200)
        conn = connect(timed, peer)
        for i in range(8):
            timed.command('K', struct.pack('!I', 75))
            conn.sendall(frame(9, bytes([i]), masked=True))
            assert read_frame(conn, False) == (True, 10, False, bytes([i]))
        timed.command('K', struct.pack('!I', 201))
        assert not all_bytes(conn); conn.close(); timed.stop(); timed.finish()
        print('handshake deadline, rejection framing and heartbeat/idle expiration passed', flush=True)
        if duration:
            h.start()
            connections = [connect(h, tls_peer if i % 2 else peer, tunnel=bool(i % 2),
                                   tls=client_tls if i % 2 else None) for i in range(16)]
            began = time.monotonic(); rounds = 0
            while time.monotonic() - began < duration:
                payload = struct.pack('!I', rounds)
                for conn in connections:
                    conn.sendall(frame(9, payload, masked=True))
                    assert read_frame(conn, False) == (True, 10, False, payload)
                rounds += 1
                time.sleep(min(10, max(0, duration - (time.monotonic() - began))))
            for conn in connections:
                close(conn)
            h.stop()
            print(f'16 concurrent WS/WSS connections: {time.monotonic()-began:.2f}s, {rounds} heartbeat rounds, 0 errors', flush=True)
        # Stop with a buffered partial response and a live upgraded stream.
        h.start(); active = connect(h, peer)
        ready = threading.Event()
        def partial(conn):
            headers(conn); conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\n'); ready.set()
            assert not all_bytes(conn)
        pending_peer = Peer(partial); pending = h.connect(); pending.sendall(request(pending_peer))
        assert ready.wait(2); h.finish()
        assert not all_bytes(active) and not all_bytes(pending)
        active.close(); pending.close(); pending_peer.check()
        peer.check(); tls_peer.check()
    print('WebSocket inbound contract passed', flush=True)


if __name__ == '__main__':
    if not shutil.which('openssl'):
        print('WebSocket TLS contract skipped: openssl executable unavailable', flush=True); sys.exit(77)
    parser = argparse.ArgumentParser(); parser.add_argument('binary'); parser.add_argument('--duration', type=float, default=0)
    args = parser.parse_args(); test(args.binary, args.duration)
