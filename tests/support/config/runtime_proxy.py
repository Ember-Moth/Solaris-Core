#!/usr/bin/env python3
"""YAML -> public ABI -> real sockets -> transactional reload peers."""
import atexit
import base64
import hashlib
import json
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'inbound' / 'proxy'))
from inbound import Peer, echo, exact, until, all_bytes, address, read_address


class Runtime:
    def __init__(self, binary):
        self.child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        atexit.register(self.abort)
        self.events = queue.Queue()
        def reader():
            for line in self.child.stdout:
                self.events.put(json.loads(line))
            self.events.put({'eof': self.child.poll()})
        threading.Thread(target=reader, daemon=True).start()
        assert self.take() == {'ready': True}

    def abort(self):
        if self.child.poll() is None:
            self.child.kill()
            self.child.wait(timeout=5)

    def take(self):
        value = self.events.get(timeout=25)
        assert 'eof' not in value, ('SDK process exited', value)
        return value

    def command(self, kind, payload=b'', expected=0):
        self.child.stdin.write(kind.encode() + struct.pack('!I', len(payload)) + payload)
        self.child.stdin.flush()
        value = self.take()
        if expected is not None:
            assert value['status'] == expected, (kind, value, expected)
        return value

    def prepare(self, slot, conf, ephemeral=False, expected=0):
        return self.command('P', bytes([slot, int(ephemeral)]) + conf.encode(), expected)

    def commit(self, slot, expected=0):
        return self.command('C', bytes([slot]), expected)

    def finish(self):
        self.command('T')
        assert self.child.wait(timeout=5) == 0


class DualStackPeer(Peer):
    def __init__(self):
        self.handler = echo
        self.s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.s.bind(('::1', 0))
        self.host, self.port = self.s.getsockname()[:2]
        self.v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.v4.bind(('127.0.0.1', self.port))
        self.errors = queue.Queue()
        for sock in (self.s, self.v4):
            sock.listen(32)
            threading.Thread(target=self.serve, args=(sock,), daemon=True).start()

    def serve(self, sock):
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()


def config(http_port, socks_port=None, route='DIRECT', auth=False, udp=True, extra=''):
    result = '[General]\nconfig-version=1\nmode=rule\n[Listener]\n'
    result += f'web = http, 127.0.0.1, {http_port}\n'
    if socks_port is not None:
        selected = 'Local' if auth else '""'
        result += (f'socks = socks5, 127.0.0.1, {socks_port}, '
                   f'udp-relay={str(udp).lower()}, authentication={selected}\n')
    result += extra
    if auth:
        result += '[Authentication]\nLocal = user=newpass\n'
    return result + f'[Rule]\nFINAL,{route}\n'


def proxy_config(node):
    """Write native protocol records for the independent peer fixtures."""
    import json
    def token(value):
        if isinstance(value, bool): return str(value).lower()
        return json.dumps(str(value), ensure_ascii=False)
    parts = [node['type']]
    if node['type'] not in ('direct', 'reject'):
        parts += [token(node['server']), token(node['port'])]
    parts += [key + '=' + token(value) for key, value in node.items()
              if key not in ('name', 'type', 'server', 'port')]
    return '[Proxy]\n' + token(node['name']) + ' = ' + ', '.join(parts) + '\n'


def by_name(prepared):
    return {info['name']: info for info in prepared['listeners']}


def connect(port):
    return socket.create_connection(('127.0.0.1', port), timeout=3)


def http_tunnel(port, target):
    conn = connect(port)
    host = f'[{target.host}]' if ':' in target.host else target.host
    authority = f'{host}:{target.port}'
    conn.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
    assert until(conn).startswith(b'HTTP/1.1 200 ')
    return conn


def socks_greet(port, auth=False):
    conn = connect(port)
    method = 2 if auth else 0
    conn.sendall(bytes([5, 1, method]))
    assert exact(conn, 2) == bytes([5, method])
    if auth:
        conn.sendall(b'\x01\x04user\x07newpass')
        assert exact(conn, 2) == b'\x01\x00'
    return conn


def socks_request(conn, host, port, udp=False, success=True):
    conn.sendall(bytes([5, 3 if udp else 1, 0]) + address(host, port))
    response = exact(conn, 3)
    assert response[0] == 5 and response[2] == 0, response
    bound = read_address(conn)
    assert (response[1] == 0) == success, response
    return bound


def socks_tcp(port, target, auth=False):
    conn = socks_greet(port, auth)
    socks_request(conn, target.host, target.port)
    return conn


def udp_control(port, auth=False):
    conn = socks_greet(port, auth)
    bound = socks_request(conn, '0.0.0.0', 0, udp=True)
    return conn, bound


def assert_echo(conn, payload):
    conn.sendall(payload)
    assert exact(conn, len(payload)) == payload


def udp_exchange(client, bound, target, payload, success=True):
    packet = b'\0\0\0' + address(target.host, target.port) + payload
    client.sendto(packet, bound)
    client.settimeout(2 if success else .15)
    if success:
        response = client.recv(65536)
        assert response == packet, (response, packet)
    else:
        try:
            response = client.recv(65536)
            raise AssertionError(('unexpected UDP response', response))
        except socket.timeout:
            pass


def origin(conn):
    head = until(conn)
    lines = head.split(b'\r\n')
    assert lines[0].startswith(b'GET /runtime HTTP/1.1'), lines[0]
    assert b'Proxy-' not in head
    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nruntime-ok')


def plain_http(port, target):
    with connect(port) as conn:
        conn.sendall(f'GET http://{target.host}:{target.port}/runtime HTTP/1.1\r\nHost: {target.host}:{target.port}\r\n\r\n'.encode())
        assert all_bytes(conn).endswith(b'runtime-ok')


def websocket_origin(conn):
    head = until(conn)
    headers = dict(line.split(b':', 1) for line in head.split(b'\r\n')[1:-2])
    key = headers[b'Sec-WebSocket-Key'].strip()
    accept = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
    conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
    echo(conn)


def websocket(port, target):
    conn = connect(port)
    conn.sendall((f'GET http://{target.host}:{target.port}/runtime HTTP/1.1\r\nHost: {target.host}:{target.port}\r\n'
                  'Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n'
                  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n').encode())
    assert until(conn).startswith(b'HTTP/1.1 101 ')
    return conn


def no_admission(port):
    try:
        with connect(port) as conn:
            conn.sendall(b'\x05\x01\x00')
            assert all_bytes(conn) == b''
    except (ConnectionRefusedError, ConnectionResetError):
        pass


def test(binary):
    runtime = Runtime(binary)
    tcp, http, ws = Peer(echo), Peer(origin), Peer(websocket_origin)
    udp4, udp6 = Peer(None, udp=True), Peer(None, socket.AF_INET6, udp=True)
    prepared = runtime.prepare(0, config(18080, 18081), ephemeral=True)
    listeners = by_name(prepared)
    a, b = listeners['web']['port'], listeners['socks']['port']
    assert a and b and a != b
    assert listeners['web']['configured_port'] == 18080 and listeners['socks']['configured_port'] == 18081
    assert all(info['requested_port'] == 0 and info['overridden'] for info in listeners.values())
    assert len({entry['worker'] for entry in listeners.values()}) == 2, listeners
    assert prepared['base'] == 0
    no_admission(a); no_admission(b)
    revision = runtime.commit(0)['revision']; assert revision == 1
    assert runtime.command('Q')['revision'] == revision
    plain_http(a, http)
    old_http, old_socks, old_ws = http_tunnel(a, tcp), socks_tcp(b, tcp), websocket(a, ws)
    pending = socks_greet(b)
    u, ubound = udp_control(b)
    v, vbound = udp_control(b)
    w, wbound = udp_control(b)
    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3)]
    for client in clients: client.bind(('127.0.0.1', 0))
    udp_exchange(clients[0], ubound, udp4, b'before-reload')

    # Failure after candidate resources start cannot interrupt the old service.
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1', 0)); occupied.listen(4)
        extra = f'blocked = http, 127.0.0.1, {occupied.getsockname()[1]}\n'
        runtime.prepare(8, config(a, b, extra=extra), expected=-8)
        assert_echo(old_http, b'old-service-after-rollback')
        plain_http(a, http)

    stale = runtime.prepare(9, config(a, b))
    swapped = runtime.prepare(1, config(b, a, route='REJECT'))
    assert stale['base'] == swapped['base'] == revision
    assert {x['port'] for x in swapped['listeners']} == {a, b}
    revision = runtime.commit(1)['revision']; assert revision == 2
    runtime.commit(9, expected=-11)
    assert runtime.command('Q')['revision'] == revision
    socks_request(pending, tcp.host, tcp.port)
    for conn in [old_http, old_socks, old_ws, pending]: assert_echo(conn, b'old-generation-survives')
    with socks_greet(a) as rejected: socks_request(rejected, tcp.host, tcp.port, success=False)
    # An existing UDP plan must remain able to create a new family lane.
    udp_exchange(clients[0], ubound, udp6, b'old-bundle-new-ipv6-lane')
    udp_exchange(clients[1], vbound, udp4, b'new-first-packet-is-rejected', success=False)

    runtime.prepare(2, config(b, a)); revision = runtime.commit(2)['revision']; assert revision == 3
    plain_http(b, http)
    # Logical socks ID moved from b to a; old control must still find that ID.
    udp_exchange(clients[1], vbound, udp4, b'logical-entry-follows-port-swap')
    runtime.prepare(3, config(b, a, auth=True)); revision = runtime.commit(3)['revision']; assert revision == 4
    udp_exchange(clients[0], ubound, udp4, b'existing-association-survives-auth')
    udp_exchange(clients[1], vbound, udp6, b'existing-new-lane-after-auth')
    udp_exchange(clients[2], wbound, udp4, b'old-auth-cannot-create-association', success=False)
    assert all_bytes(w) == b''
    with connect(a) as denied:
        denied.sendall(b'\x05\x01\x00'); assert all_bytes(denied) == b'\x05\xff'
    with socks_tcp(a, tcp, auth=True) as current: assert_echo(current, b'new-auth-works')

    runtime.prepare(4, config(b, a, auth=True, udp=False)); runtime.commit(4)
    with socks_greet(a, auth=True) as denied: socks_request(denied, '0.0.0.0', 0, udp=True, success=False)
    udp_exchange(clients[0], ubound, udp4, b'existing-association-survives-disable')
    runtime.prepare(5, config(b)); runtime.commit(5)
    no_admission(a)
    plain_http(b, http)
    assert_echo(old_socks, b'old-tcp-survives-entry-removal')
    udp_exchange(clients[0], ubound, udp6, b'old-udp-survives-entry-removal')
    dns_config = config(b).replace('[Rule]\nFINAL,DIRECT',
        '[Rule]\nIP-CIDR,127.0.0.0/8,DIRECT\nIP-CIDR6,::1/128,DIRECT\nFINAL,REJECT')
    runtime.prepare(10, dns_config); runtime.commit(10)
    dns_peer = DualStackPeer()
    with http_tunnel(b, SimpleNamespace(host='localhost', port=dns_peer.port)) as resolved:
        assert_echo(resolved, b'public-rule-lazy-dns')
    candidate = runtime.prepare(6, '[General]\nconfig-version=1\n[Listener]\npending=mixed,0.0.0.0,18090\n[Rule]\nFINAL,DIRECT\n', ephemeral=True)
    candidate_port = candidate['listeners'][0]['port']; no_admission(candidate_port)
    runtime.command('S')
    assert runtime.command('Q')['revision'] == 0
    for conn in [old_http, old_socks, old_ws, pending, u, v]: assert all_bytes(conn) == b''
    for port in [a, b, candidate_port]: no_admission(port)
    for conn in [old_http, old_socks, old_ws, pending, u, v, w]: conn.close()
    for client in clients: client.close()
    runtime.command('N')
    fresh = runtime.prepare(7, config(b)); assert fresh['base'] > revision
    restarted = runtime.commit(7)['revision']; assert restarted > revision
    plain_http(b, http)
    runtime.finish()
    for peer in [tcp, http, ws, dns_peer]: peer.check()
    print('public SDK: prepare admission, two owners, bind rollback, stale CAS, port swap, TCP/WS/UDP generation, auth/remove and stop/restart passed')


if __name__ == '__main__':
    test(sys.argv[1])
