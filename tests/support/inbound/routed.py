#!/usr/bin/env python3
"""Real TCP/UDP handoff tests with captured and replaceable immutable route views."""
from pathlib import Path
import queue
import socket
import struct
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parent / 'proxy'))
from inbound import Harness, Peer, echo, socks, until, exact, all_bytes, address


def revision(h, kind, expected):
    data = h.take(kind, timeout=2)
    value = struct.unpack('!I', data[:4])[0]
    assert value == expected, (kind, value, expected, h.events)
    return data


def publish(h, value, auth=1, udp=1, pending=False):
    h.command('V' if pending else 'G', struct.pack('!III', value, auth, udp))


def stop(h):
    h.command('S'); h.take('S'); h.events.clear()


def connect_request(conn, port, auth=True):
    conn.sendall(f'CONNECT route.invalid:{port} HTTP/1.1\r\nHost: route.invalid:{port}\r\n'.encode() +
                 (b'Proxy-Authorization: Basic dXNlcjpwYXNz\r\n' if auth else b'') + b'\r\n')


def udp_control(h, auth=True):
    control, bound = socks(h, type('Any', (), {'host': '0.0.0.0', 'port': 0}), auth=auth, command=3)
    accepted = struct.unpack('!I', h.take('O'))[0]
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); client.bind(('127.0.0.1', 0)); client.settimeout(2)
    return control, bound, client, accepted


def datagram(client, bound, peer, payload, domain=False, receive=True):
    wire = b'\0\0\0' + address('route.invalid' if domain else peer.host, peer.port) + payload
    client.sendto(wire, bound)
    if receive:
        output = client.recv(65536)
        assert output == b'\0\0\0' + address(peer.host, peer.port) + payload, output


def tcp_generation(h, peer):
    h.start(auth=True, handshake=5000)
    old = h.connect(); revision(h, 'O', 1)
    publish(h, 2)
    connect_request(old, peer.port)
    assert until(old).startswith(b'HTTP/1.1 200 ')
    old.sendall(b'old'); assert exact(old, 3) == b'old'
    data = revision(h, 'R', 1); assert struct.unpack('!I', data[4:8])[0] == 6
    revision(h, 'D', 1); revision(h, 'P', 1)
    new = h.connect(); revision(h, 'O', 2); connect_request(new, peer.port)
    assert until(new).startswith(b'HTTP/1.1 200 ')
    revision(h, 'R', 2); revision(h, 'D', 2); revision(h, 'P', 2)
    h.command('L'); h.take('L')
    # Removing a physical listener leaves accepted streams independent.
    old.sendall(b'alive'); new.sendall(b'new')
    assert exact(old, 5) == b'alive' and exact(new, 3) == b'new'
    old.close(); revision(h, 'V', 1); new.close(); stop(h)
    print('TCP accept pins old generation; physical listener close preserves streams', flush=True)


def udp_capture(h, first, second):
    h.start(auth=True, handshake=5000)
    control, bound, client, accepted = udp_control(h); assert accepted == 1
    publish(h, 2, pending=True); h.command('J', struct.pack('!I', 2))
    datagram(client, bound, first, b'first', domain=True)
    data = revision(h, 'R', 1)
    _, network, source_port, target_port = struct.unpack('!IIII', data)
    assert network == 17 and source_port == client.getsockname()[1] and target_port == first.port
    revision(h, 'D', 1); revision(h, 'P', 1)
    datagram(client, bound, second, b'second')
    datagram(client, bound, first, b'again', domain=True)
    # Queue a command as an owner barrier before inspecting captured events.
    h.command('Q', struct.pack('!I', 1)); h.take('Q')
    assert not any(kind in ('R', 'P', 'D') for kind, _ in h.events), h.events
    control.close(); revision(h, 'V', 1); client.close(); stop(h)
    print('UDP view captured before deferred pump; one plan and initial numeric mapping reused', flush=True)


def udp_idle(h, peer, change_auth):
    h.start(auth=True, idle=100, handshake=5000)
    control, bound, client, _ = udp_control(h)
    datagram(client, bound, peer, b'first'); revision(h, 'R', 1); revision(h, 'P', 1)
    publish(h, 2, auth=2 if change_auth else 1)
    datagram(client, bound, peer, b'existing')
    time.sleep(.3)
    if change_auth:
        datagram(client, bound, peer, b'revoked', receive=False)
        control.settimeout(2); assert not all_bytes(control)
        revision(h, 'V', 1)
        assert not any(kind == 'R' for kind, _ in h.events), h.events
    else:
        datagram(client, bound, peer, b'new-association')
        revision(h, 'R', 2); revision(h, 'P', 2)
        # The current generation may retire while its plan is held by an old
        # control connection's association in a different inbound container.
        publish(h, 3); revision(h, 'V', 2)
        datagram(client, bound, peer, b'old-association-still-active')
        control.close(); revision(h, 'V', 1)
    control.close(); client.close(); stop(h)
    print(f'UDP control survives association idle; auth_change={change_auth} admission passed', flush=True)


def udp_full_queue_close(h, peer):
    h.start(auth=True, handshake=5000)
    h.command('H', struct.pack('!I', 1))
    control, bound, client, _ = udp_control(h)
    datagram(client, bound, peer, b'held', domain=True, receive=False)
    revision(h, 'R', 1); revision(h, 'D', 1)
    datagram(client, bound, peer, b'queue-full', domain=True, receive=False)
    deadline = time.monotonic() + 2
    while True:
        h.command('Q', struct.pack('!I', 1)); refs, dropped = struct.unpack('!II', h.take('Q'))
        if dropped:
            assert refs > 1
            break
        assert time.monotonic() < deadline
    publish(h, 2)
    control.close()
    revision(h, 'K', 1)
    # EAGAIN must preserve the id used to cancel and drain the held association.
    revision(h, 'V', 1)
    assert not any(kind == 'P' for kind, _ in h.events), h.events
    client.close(); stop(h)
    print('UDP EAGAIN preserves association id; control close cancels pending route without late open', flush=True)


def pending_close(h):
    connections = queue.Queue()
    def target(conn):
        connections.put(True); echo(conn)
    peer = Peer(target)
    h.start(handshake=5000); h.command('H', struct.pack('!I', 1))
    conn = h.connect(); revision(h, 'O', 1); connect_request(conn, peer.port, auth=False)
    revision(h, 'R', 1); revision(h, 'D', 1)
    stop(h)
    assert not all_bytes(conn); conn.close(); assert connections.empty(); peer.check()
    print('Closing detached inbound drains late DNS without dialing', flush=True)


def main(binary):
    h = Harness(binary); tcp, first, second = Peer(echo), Peer(None, udp=True), Peer(None, udp=True)
    h.start(); h.command('F'); h.take('F'); stop(h)
    tcp_generation(h, tcp)
    udp_capture(h, first, second)
    udp_idle(h, first, False)
    udp_idle(h, first, True)
    udp_full_queue_close(h, first)
    pending_close(h)
    # Engine stop is also a callback/resource barrier for in-progress routing.
    h.start(handshake=5000); h.command('H', struct.pack('!I', 1))
    conn = h.connect(); revision(h, 'O', 1); connect_request(conn, tcp.port, auth=False)
    revision(h, 'R', 1); revision(h, 'D', 1)
    h.finish(); assert not all_bytes(conn); conn.close()
    assert not any(kind == 'P' for kind, _ in h.events), h.events
    tcp.check()
    print('Detached inbound/routed UDP lifecycle contract passed', flush=True)


if __name__ == '__main__':
    main(sys.argv[1])
