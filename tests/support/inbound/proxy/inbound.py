#!/usr/bin/env python3
"""Independent socket peers for HTTP, SOCKS5 and mixed inbound contracts."""
import base64
import concurrent.futures
import os
import queue
import socket
import ssl
import shutil
import tempfile
import struct
import subprocess
import sys
import threading
import time


def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise EOFError((n, bytes(out)))
        out.extend(part)
    return bytes(out)


def until(sock, marker=b'\r\n\r\n'):
    out = bytearray()
    while not out.endswith(marker):
        out.extend(exact(sock, 1))
        assert len(out) < 100000
    return bytes(out)


def all_bytes(sock):
    out = bytearray()
    while True:
        try:
            part = sock.recv(65536)
        except (ConnectionResetError, ConnectionAbortedError):
            break
        if not part:
            break
        out.extend(part)
    return bytes(out)


def address(host, port):
    try:
        return b'\x01' + socket.inet_pton(socket.AF_INET, host) + struct.pack('!H', port)
    except OSError:
        try:
            return b'\x04' + socket.inet_pton(socket.AF_INET6, host) + struct.pack('!H', port)
        except OSError:
            b = host.encode()
            return bytes([3, len(b)]) + b + struct.pack('!H', port)


def read_address(sock):
    kind = exact(sock, 1)[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(sock, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
    else:
        assert kind == 3
        host = exact(sock, exact(sock, 1)[0]).decode()
    return host, struct.unpack('!H', exact(sock, 2))[0]


class Harness:
    def __init__(self, binary, *args):
        self.p = subprocess.Popen([binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.events = []
        self.queue = queue.Queue()
        threading.Thread(target=self.reader, daemon=True).start()

    def reader(self):
        try:
            while True:
                head = self.p.stdout.read(5)
                if not head:
                    break
                assert len(head) == 5
                n = struct.unpack('!I', head[1:])[0]
                data = self.p.stdout.read(n)
                assert len(data) == n
                self.queue.put((chr(head[0]), data))
        finally:
            self.queue.put(('EOF', b''))

    def take(self, kind, timeout=6):
        deadline = time.monotonic() + timeout
        while True:
            for i, event in enumerate(self.events):
                if event[0] == kind:
                    return self.events.pop(i)[1]
            event = self.queue.get(timeout=max(0.01, deadline - time.monotonic()))
            assert event[0] != 'EOF', ('child exited', self.p.poll(), self.events)
            self.events.append(event)

    def command(self, kind, payload=b'', expected=0):
        self.p.stdin.write(kind.encode() + struct.pack('!I', len(payload)) + payload)
        self.p.stdin.flush()
        if kind != 'T':
            rc = struct.unpack('!i', self.take('A'))[0]
            if expected is not None:
                assert rc == expected, (kind, rc, expected)
            return rc

    def start(self, protocol=3, auth=False, family=4, udp=True, handshake=2000, idle=10000, limit=64, header=32768):
        self.command('N', bytes([protocol, auth, family, udp]) + struct.pack('!IIII', handshake, idle, limit, header))
        self.port = struct.unpack('!I', self.take('B'))[0]
        self.host = '::1' if family == 6 else '127.0.0.1'
        return self.port

    def connect(self):
        return socket.create_connection((self.host, self.port), 3)

    def stop(self):
        self.command('S')
        self.take('S')
        self.events = [e for e in self.events if e[0] != 'R']

    def stats(self):
        self.command('Q')
        return struct.unpack('!IIIIII', self.take('Q'))

    def mode(self, value):
        self.command('G', struct.pack('!I', value))

    def finish(self):
        self.command('T')
        self.take('Z')
        assert self.p.wait(5) == 0


class Peer:
    def __init__(self, handler, family=socket.AF_INET, udp=False):
        self.handler = handler
        self.s = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.s.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
        self.host, self.port = self.s.getsockname()[:2]
        self.errors = queue.Queue()
        if not udp:
            self.s.listen(32)
        threading.Thread(target=self.run, args=(udp,), daemon=True).start()

    def run(self, udp):
        if udp:
            while True:
                data, peer = self.s.recvfrom(65536)
                self.s.sendto(data, peer)
        else:
            while True:
                conn, _ = self.s.accept()
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        try:
            with conn:
                conn.settimeout(5)
                self.handler(conn)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            self.errors.put(error)

    def check(self):
        if not self.errors.empty():
            raise self.errors.get()


def echo(conn):
    while True:
        data = conn.recv(65536)
        if not data:
            break
        conn.sendall(data)


captures = queue.Queue()


def http(conn):
    head = until(conn)
    lines = head.split(b'\r\n')
    headers = dict(line.split(b':', 1) for line in lines[1:-2])
    headers = {k.lower(): v.strip() for k, v in headers.items()}
    body = b''
    if headers.get(b'expect') == b'100-continue':
        conn.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
    if b'content-length' in headers:
        body = exact(conn, int(headers[b'content-length']))
    elif b'transfer-encoding' in headers:
        assert headers[b'transfer-encoding'] == b'chunked'
        while True:
            n = int(until(conn, b'\r\n').split(b';')[0].strip(), 16)
            if not n:
                while until(conn, b'\r\n') != b'\r\n':
                    pass
                break
            body += exact(conn, n)
            assert exact(conn, 2) == b'\r\n'
    captures.put((lines[0], headers, body))
    result = body or b'http-ok'
    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(result)).encode() + b'\r\nConnection: close\r\n\r\n' + result)


def socks(h, peer, auth=False, command=1, coalesced=False, host=None):
    conn = h.connect()
    greeting = b'\x05\x01' + (b'\x02' if auth else b'\x00')
    credentials = b'\x01\x04user\x04pass' if auth else b''
    request = b'\x05' + bytes([command, 0]) + address(host or peer.host, peer.port)
    if coalesced:
        conn.sendall(greeting + credentials + request)
    else:
        for byte in greeting:
            conn.sendall(bytes([byte]))
    assert exact(conn, 2) == b'\x05' + (b'\x02' if auth else b'\x00')
    if auth:
        if not coalesced:
            for byte in credentials:
                conn.sendall(bytes([byte]))
        assert exact(conn, 2) == b'\x01\x00'
    if not coalesced:
        for byte in request:
            conn.sendall(bytes([byte]))
    assert exact(conn, 3) == b'\x05\x00\x00'
    bound = read_address(conn)
    return conn, bound


def http_request(h, peer, body=b'', auth=False, extra=b'', chunks=False, pipeline=b''):
    authority = f'[{peer.host}]:{peer.port}' if ':' in peer.host else f'{peer.host}:{peer.port}'
    request = (f'POST http://{authority}/path?q=1 HTTP/1.1\r\nHost: {authority}\r\n').encode()
    if auth:
        request += b'Proxy-Authorization: Basic ' + base64.b64encode(b'user:pass') + b'\r\n'
    request += b'Connection: keep-alive, X-Remove\r\nX-Remove: secret\r\nProxy-Connection: keep-alive\r\n' + extra
    request += b'Transfer-Encoding: chunked\r\n\r\n' if chunks else b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
    wire = b'%x\r\n' % len(body) + body + b'\r\n0\r\nX-Checksum: checked\r\n\r\n' if chunks and body else body
    with h.connect() as conn:
        conn.sendall(request + wire + pipeline)
        response = all_bytes(conn)
    assert response.endswith(body or b'http-ok'), response[:200]
    line, headers, captured = captures.get(timeout=3)
    assert line == b'POST /path?q=1 HTTP/1.1' and captured == body
    assert headers[b'connection'] == b'close'
    for key in [b'proxy-authorization', b'proxy-connection', b'x-remove']:
        assert key not in headers, headers


def no_data(conn):
    assert all_bytes(conn) == b''


def edges(h, tcp, origin, udp):
    h.start(auth=True)
    with h.connect() as conn:
        conn.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        response = all_bytes(conn)
        assert response.startswith(b'HTTP/1.1 407 ') and b'Proxy-Authenticate: Basic' in response
    with h.connect() as conn:
        conn.sendall(b'\x05\x01\x00')
        assert all_bytes(conn) == b'\x05\xff'
    with h.connect() as conn:
        conn.sendall(b'\x05\x01\x02\x01\x04user\x03bad')
        assert all_bytes(conn) == b'\x05\x02\x01\x01'
    assert h.stats()[3] == 3
    h.stop()
    h.start()
    for bad in [b'Host: a\r\nHost: a', b'Host: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked',
                b'Host: a\r\nContent-Length: 1\r\nContent-Length: 1', b'Host: a\r\nConnection: Content-Length',
                b'Host: a\r\nUpgrade: websocket']:
        with h.connect() as conn:
            conn.sendall(b'POST / HTTP/1.1\r\n' + bad + b'\r\n\r\n')
            assert all_bytes(conn).startswith(b'HTTP/1.1 400 ')
    # Success may only follow a real outbound open.
    with socket.socket() as refused:
        refused.bind(('127.0.0.1', 0))
        port = refused.getsockname()[1]
        refused.close()  # A bound, non-listening macOS socket silently drops SYN.
        with h.connect() as conn:
            conn.sendall(f'CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n'.encode())
            response = all_bytes(conn)
            assert response.startswith(b'HTTP/1.1 502 ') and b'200' not in response
        with h.connect() as conn:
            conn.sendall(b'\x05\x01\x00\x05\x01\x00' + address('127.0.0.1', port))
            assert exact(conn, 2) == b'\x05\x00'
            assert exact(conn, 3) == b'\x05\x05\x00'
            read_address(conn); no_data(conn)
    for command, target, code in [(2, address(tcp.host, tcp.port), 7), (1, b'\x09', 8),
                                   (1, address('bad host', 80), 8), (3, address('example.com', 0), 8), (3, address('127.0.0.2', 0), 2)]:
        with h.connect() as conn:
            conn.sendall(b'\x05\x01\x00\x05' + bytes([command, 0]) + target)
            assert exact(conn, 2) == b'\x05\x00'
            assert exact(conn, 3) == bytes([5, code, 0])
            read_address(conn); no_data(conn)
    # Expect/Continue does not wait for the body before opening the origin.
    with h.connect() as conn:
        conn.sendall(f'POST http://{origin.host}:{origin.port}/ HTTP/1.1\r\nHost: {origin.host}:{origin.port}\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n'.encode())
        assert until(conn) == b'HTTP/1.1 100 Continue\r\n\r\n'
        conn.sendall(b'body'); assert all_bytes(conn).endswith(b'body')
        assert captures.get(timeout=2)[2] == b'body'
    # Concurrent mixed protocol handshakes share one listener safely.
    def transfer(index):
        if index % 2:
            conn = socks(h, tcp)[0]
        else:
            conn = h.connect()
            conn.sendall(f'CONNECT {tcp.host}:{tcp.port} HTTP/1.1\r\nHost: {tcp.host}:{tcp.port}\r\n\r\n'.encode())
            assert until(conn).startswith(b'HTTP/1.1 200 ')
        with conn:
            payload = bytes([index]) * 40000
            conn.sendall(payload); conn.shutdown(socket.SHUT_WR); assert all_bytes(conn) == payload
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(transfer, range(16)))
    h.stop()
    h.start(handshake=100, idle=100, limit=1, header=1024)
    with h.connect() as conn:
        conn.sendall(b'G')
        no_data(conn)
    with h.connect() as conn:
        conn.sendall(b'GET / HTTP/1.1\r\nHost: a\r\nX: ' + b'x' * 1100)
        assert all_bytes(conn).startswith(b'HTTP/1.1 431 ')
    with socks(h, tcp)[0] as conn:
        with h.connect() as rejected:
            no_data(rejected)
        no_data(conn)
    assert h.stats()[2] >= 1
    h.stop()
    # Controlled delayed outbound proves the parent handshake timeout response.
    h.start(handshake=100); h.mode(4)
    with h.connect() as conn:
        conn.sendall(f'CONNECT {tcp.host}:{tcp.port} HTTP/1.1\r\nHost: {tcp.host}:{tcp.port}\r\n\r\n'.encode())
        assert all_bytes(conn).startswith(b'HTTP/1.1 504 ')
    with h.connect() as conn:
        conn.sendall(b'\x05\x01\x00\x05\x01\x00' + address(tcp.host, tcp.port))
        assert exact(conn, 5) == b'\x05\x00\x05\x06\x00'
        read_address(conn); no_data(conn)
    h.stop(); h.mode(0)
    # Authentication and plan callbacks may close their own listener.
    for mode in [2, 3]:
        h.start(auth=mode == 2)
        h.mode(mode)
        with h.connect() as conn:
            conn.sendall(f'CONNECT {tcp.host}:{tcp.port} HTTP/1.1\r\nHost: {tcp.host}:{tcp.port}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n'.encode())
            no_data(conn)
        h.take('S'); h.mode(0)
    # Rejected creation promises no close callback; rollback allows reuse.
    for allocation in range(12):
        h.command('M', struct.pack('!i', allocation))
        rc = h.command('N', bytes([3, 0, 4, 1]) + struct.pack('!IIII', 2000, 10000, 64, 32768), expected=None)
        h.command('M', struct.pack('!i', -1))
        if rc == 0:
            h.take('B'); h.stop()
        else:
            assert rc == -2, rc
        h.start(); h.stop()
    # Both numeric families also work as listener and target.
    tcp6, http6, udp6 = Peer(echo, socket.AF_INET6), Peer(http, socket.AF_INET6), Peer(None, socket.AF_INET6, udp=True)
    h.start(family=6)
    http_request(h, http6, body=b'ipv6')
    with socks(h, tcp6)[0] as conn:
        conn.sendall(b'ipv6'); assert exact(conn, 4) == b'ipv6'
    control, bound = socks(h, type('Any', (), {'host': '0.0.0.0', 'port': 0}), command=3)
    with control, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
        client.settimeout(2); content = b'\0\0\0' + address(udp6.host, udp6.port) + b'ipv6'
        client.sendto(content, bound); assert client.recv(1024) == content
    h.stop(); tcp6.check(); http6.check()
    print('auth, malformed framing, real open failure, limits, callback close, allocation rollback and IPv6 passed', flush=True)


def multiple_and_udp_edges(h, tcp, origin, udp):
    h.start(protocol=1); first = h.port
    h.start(protocol=2); second = h.port
    assert first != second
    with socks(h, tcp)[0] as conn:
        conn.sendall(b'multiple'); assert exact(conn, 8) == b'multiple'
        h.port = first; http_request(h, origin)
        conn.sendall(b'active'); assert exact(conn, 6) == b'active'
    h.port = second; h.stop(); h.command('W'); h.port = first
    http_request(h, origin); h.stop()
    # Explicit UDP client port is enforced from the first packet.
    h.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong:
        client.bind(('127.0.0.1', 0)); client.settimeout(2); wrong.settimeout(.05)
        control, bound = socks(h, type('Any', (), {'host': '127.0.0.1', 'port': client.getsockname()[1]}), command=3)
        with control:
            content = b'\0\0\0' + address(udp.host, udp.port) + b'pinned'
            wrong.sendto(content, bound)
            try:
                wrong.recv(1024); raise AssertionError('ignored explicit UDP port')
            except socket.timeout:
                pass
            client.sendto(content, bound); assert client.recv(1024) == content
    h.stop()
    # UDP selection can close the listener while an association is being created.
    h.start()
    control, bound = socks(h, type('Any', (), {'host': '0.0.0.0', 'port': 0}), command=3)
    h.mode(3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(b'\0\0\0' + address(udp.host, udp.port) + b'close', bound)
        h.take('S'); no_data(control)
    h.mode(0)
    # Failure during first UDP submit/open/reply must leave a drainable association.
    for allocation in range(24):
        h.start()
        control, bound = socks(h, type('Any', (), {'host': '0.0.0.0', 'port': 0}), command=3)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.03)
            h.command('M', struct.pack('!i', allocation))
            client.sendto(b'\0\0\0' + address(udp.host, udp.port) + b'allocation', bound)
            try:
                client.recv(1024)
            except socket.timeout:
                pass
            h.command('M', struct.pack('!i', -1))
        h.stop()
    print('simultaneous listeners, UDP port binding, callback close and active allocation failures passed', flush=True)


def curl_interop(h, origin):
    curl, openssl = shutil.which('curl'), shutil.which('openssl')
    if not curl or not openssl:
        print('curl/TLS client interop skipped: curl or openssl unavailable', flush=True)
        return
    with tempfile.TemporaryDirectory(prefix='solaris-inbound-tls-') as directory:
        cert, key = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                        '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost'], check=True, capture_output=True, timeout=20)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        def tls(conn):
            with context.wrap_socket(conn, server_side=True) as secured:
                http(secured)
        secure = Peer(tls)
        h.start(auth=True)
        for proxy in ['http', 'socks5h']:
            for scheme, peer in [('http', origin), ('https', secure)]:
                command = [curl, '--silent', '--show-error', '--max-time', '5', '--noproxy', '',
                           '--proxy', f'{proxy}://user:pass@{h.host}:{h.port}', '--cacert', cert,
                           f'{scheme}://localhost:{peer.port}/client']
                result = subprocess.run(command, check=True, capture_output=True, timeout=8)
                assert result.stdout == b'http-ok', result
                _, headers, _ = captures.get(timeout=2)
                assert b'proxy-authorization' not in headers
        h.stop(); secure.check()
    print('curl HTTP/SOCKS5 authentication and verified TLS tunnels passed', flush=True)


def allocation_edges(h, tcp, udp):
    # A rejected native accept must not tear down the reusable endpoint. Keep
    # allocation disabled across several arrivals to exercise the embedded
    # rejection socket while its previous close callback is still pending.
    for allocation in [0, 1, 2]:
        h.start()
        h.command('M', struct.pack('!i', allocation))
        rejected = [h.connect() for _ in range(8)]
        for conn in rejected:
            with conn:
                no_data(conn)
        h.command('M', struct.pack('!i', -1))
        with socks(h, tcp)[0] as conn:
            conn.sendall(b'listener-survived')
            assert exact(conn, 17) == b'listener-survived'
        h.stop()
    # Arm failures after accept, so handshake/parser/relay allocations are covered.
    for protocol in [1, 2]:
        for allocation in range(24):
            h.start(protocol=protocol)
            conn = h.connect()
            # Owner snapshot is the barrier proving the client has been accepted.
            deadline = time.monotonic() + 2
            while h.stats()[0] != 1:
                assert time.monotonic() < deadline
            h.command('M', struct.pack('!i', allocation))
            if protocol == 1:
                request = f'CONNECT {tcp.host}:{tcp.port} HTTP/1.1\r\nHost: {tcp.host}:{tcp.port}\r\n\r\n'.encode()
            else:
                request = b'\x05\x01\x00\x05\x03\x00' + address('0.0.0.0', 0)
            conn.sendall(request); conn.settimeout(.05)
            try:
                conn.recv(1024)
            except (socket.timeout, ConnectionResetError):
                pass
            h.command('M', struct.pack('!i', -1))
            conn.close(); h.stop()
    print('live HTTP/UDP handshake allocation rollback passed', flush=True)


def test(binary):
    h = Harness(binary)
    tcp = Peer(echo)
    udp = Peer(None, udp=True)
    origin = Peer(http)
    for protocol in [1, 2, 3]:
        for auth in [False, True]:
            h.start(protocol=protocol, auth=auth)
            if protocol != 2:
                http_request(h, origin, auth=auth)
                http_request(h, origin, body=os.urandom(200000), auth=auth)
                http_request(h, origin, body=os.urandom(70000), auth=auth, chunks=True)
                http_request(h, origin, body=b'first-only', auth=auth, pipeline=b'GET http://bad.invalid/ HTTP/1.1\r\nHost: bad.invalid\r\n\r\n')
                authority = f'{tcp.host}:{tcp.port}'
                request = f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n'.encode()
                if auth:
                    request += b'Proxy-Authorization: Basic dXNlcjpwYXNz\r\n'
                with h.connect() as conn:
                    conn.sendall(request + b'\r\nprefetched')
                    assert until(conn).startswith(b'HTTP/1.1 200 ')
                    assert exact(conn, 10) == b'prefetched'
                    conn.sendall(b'half-close')
                    conn.shutdown(socket.SHUT_WR)
                    assert all_bytes(conn) == b'half-close'
            if protocol != 1:
                for coalesced in [False, True]:
                    with socks(h, tcp, auth, coalesced=coalesced)[0] as conn:
                        content = os.urandom(200000)
                        conn.sendall(content)
                        conn.shutdown(socket.SHUT_WR)
                        assert all_bytes(conn) == content
                with socks(h, tcp, auth, host='localhost')[0] as conn:
                    conn.sendall(b'domain')
                    assert exact(conn, 6) == b'domain'
                control, bound = socks(h, type('Any', (), {'host': '0.0.0.0', 'port': 0}), auth, command=3)
                with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong:
                    client.bind(('127.0.0.1', 0)); client.settimeout(2); wrong.settimeout(.12)
                    # Invalid fragments cannot claim the association's source port.
                    wrong.sendto(b'\0\0\1' + address(udp.host, udp.port) + b'bad', bound)
                    content = b'\0\0\0' + address(udp.host, udp.port) + b'datagram'
                    client.sendto(content, bound)
                    assert client.recv(1024) == content
                    wrong.sendto(content, bound)
                    try:
                        wrong.recv(1024)
                        raise AssertionError('source port takeover')
                    except socket.timeout:
                        pass
                    client.sendto(b'\0\0\0' + address(udp.host, udp.port), bound)
                    assert client.recv(1024) == b'\0\0\0' + address(udp.host, udp.port)
                    control.close()
                    time.sleep(.03)
                    client.sendto(content, bound); client.settimeout(.12)
                    try:
                        client.recv(1024)
                        raise AssertionError('UDP survived control close')
                    except (socket.timeout, ConnectionResetError):
                        pass
            h.stop()
            print(f'protocol={protocol} auth={auth}: transfer and close passed', flush=True)
    edges(h, tcp, origin, udp)
    curl_interop(h, origin)
    multiple_and_udp_edges(h, tcp, origin, udp)
    allocation_edges(h, tcp, udp)
    tcp.check(); origin.check()
    # Stop while a relay and incomplete handshake are still live.
    h.start()
    active = socks(h, tcp)[0]
    incomplete = h.connect(); incomplete.sendall(b"GET ")
    h.finish()
    no_data(active); no_data(incomplete); active.close(); incomplete.close()
    print('HTTP/SOCKS5/mixed loopback contract passed')


if __name__ == '__main__':
    test(sys.argv[1])
