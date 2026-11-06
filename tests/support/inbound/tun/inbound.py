#!/usr/bin/env python3
"""Raw packets -> TUN ingress -> pinned direct plan -> real TCP/UDP peers."""
import ipaddress
import socket
import struct
import sys
import threading
import time
from lwip import Harness, Peer, checksum


def ip_packet(source, destination, protocol, segment):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    pseudo = b'' if protocol == 1 else src.packed + dst.packed + (
        struct.pack('!BBH', 0, protocol, len(segment)) if src.version == 4 else struct.pack('!I3xB', len(segment), protocol))
    where = 6 if protocol == 17 else 2
    value = checksum(pseudo + segment) or 65535
    segment = segment[:where] + struct.pack('!H', value) + segment[where + 2:]
    if src.version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), 7, 0, 64, protocol, 0, src.packed, dst.packed)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, len(segment), protocol, 64, src.packed, dst.packed)
    return header + segment


def udp(source, destination, sport, dport, payload):
    return ip_packet(source, destination, 17, struct.pack('!HHHH', sport, dport, len(payload) + 8, 0) + payload)


def take_udp(h, version, sport, dport):
    fragments, size, ident = {}, None, None
    while size is None or sum(map(len, fragments.values())) != size:
        wire = h.take('P', lambda p: p[0] >> 4 == version and (p[9] == 17 if version == 4 else p[6] in (17, 44)))
        assert len(wire) <= 1500
        if version == 4:
            assert checksum(wire[:20]) == 0
            assert struct.unpack_from('!H', wire, 2)[0] == len(wire)
            flags = struct.unpack_from('!H', wire, 6)[0]
            offset, more, header = (flags & 8191) * 8, bool(flags & 8192), 20
            current = struct.unpack_from('!H', wire, 4)[0]
            src, dst = wire[12:16], wire[16:20]
        else:
            assert struct.unpack_from('!H', wire, 4)[0] + 40 == len(wire)
            src, dst = wire[8:24], wire[24:40]
            if wire[6] == 44:
                assert wire[40:42] == b'\x11\0'
                flags = struct.unpack_from('!H', wire, 42)[0]
                offset, more, header = flags & 65528, bool(flags & 1), 48
                current = struct.unpack_from('!I', wire, 44)[0]
            else:
                offset, more, header, current = 0, False, 40, 0
        if ident is None:
            ident = current
        assert ident == current and offset not in fragments
        fragments[offset] = wire[header:]
        if not more:
            size = offset + len(wire) - header
    segment = b''.join(fragments[offset] for offset in sorted(fragments))
    assert len(segment) == size
    assert struct.unpack_from('!HHH', segment) == (sport, dport, len(segment))
    pseudo = src + dst + (struct.pack('!BBH', 0, 17, size) if version == 4 else struct.pack('!I3xB', size, 17))
    assert checksum(pseudo + segment) == 0
    assert str(ipaddress.ip_address(src)) == ('127.0.0.1' if version == 4 else '::1')
    assert str(ipaddress.ip_address(dst)) == ('10.12.0.2' if version == 4 else 'fd12::2')
    return segment[8:]


def tcp_round(h, ipv6, remote_first):
    host, family = ('::1', socket.AF_INET6) if ipv6 else ('127.0.0.1', socket.AF_INET)
    payload = bytes(i % 251 for i in range(20000))
    errors = []
    with socket.socket(family) as listener:
        listener.bind((host, 0)); listener.listen(); listener.settimeout(10)
        def server():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    received = bytearray()
                    while len(received) < len(payload):
                        part = connection.recv(len(payload) - len(received))
                        assert part
                        received.extend(part)
                    assert bytes(received) == payload
                    connection.sendall(received)
                    if remote_first:
                        connection.shutdown(socket.SHUT_WR)
                    assert connection.recv(1) == b''
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=server, daemon=True); thread.start()
        peer = Peer(h, ipv6, 40000 + 2 * int(ipv6) + int(remote_first))
        peer.destination, peer.dport = host, listener.getsockname()[1]
        peer.connect()
        for offset in range(0, len(payload), 1000):
            peer.send(0x18, payload[offset:offset + 1000])
        if not remote_first:
            peer.send(0x11)
        assert peer.receive(len(payload), fin=True) == payload
        if remote_first:
            peer.send(0x11)
        thread.join(10)
        assert not thread.is_alive() and not errors, errors
    deadline = time.monotonic() + 5
    while True:
        h.command('Q'); active = struct.unpack_from('!I', h.take('Q'))[0]
        if not active:
            break
        assert time.monotonic() < deadline, active
        h.drain(.01)


def udp_round(h, ipv6):
    host, family = ('::1', socket.AF_INET6) if ipv6 else ('127.0.0.1', socket.AF_INET)
    source, version = ('fd12::2', 6) if ipv6 else ('10.12.0.2', 4)
    sport = 41000 + int(ipv6)
    large = bytes(i % 251 for i in range(60000))
    observed = []
    for server_index in range(2):
        with socket.socket(family, socket.SOCK_DGRAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            server.bind((host, 0)); server.settimeout(5)
            for payload in (b'', b'regular', b'large'):
                h.command('P', udp(source, host, sport, server.getsockname()[1], payload))
                received, peer = server.recvfrom(65536)
                assert received == payload
                observed.append(peer[1])
                reply = large if payload == b'large' else payload
                server.sendto(reply, peer)
                assert take_udp(h, version, server.getsockname()[1], sport) == reply
    assert len(set(observed)) == 1, 'association changed its UDP source port across destinations'


def main(binary):
    h = Harness(binary)
    try:
        h.command('N')
        h.command('G', struct.pack('!I', 5))
        for ipv6 in (False, True):
            for remote_first in (False, True):
                tcp_round(h, ipv6, remote_first)
            udp_round(h, ipv6)
            source, local, proto = ('fd12::2', 'fd00::1', 58) if ipv6 else ('10.12.0.2', '198.18.0.1', 1)
            segment = struct.pack('!BBHHH', 128 if ipv6 else 8, 0, 0, 123, 456) + b'ping'
            wire = ip_packet(source, local, proto, segment)
            h.command('P', wire)
            reply = h.take('P', lambda p: p[6] == 58 if ipv6 else p[9] == 1)
            expected = ip_packet(local, source, proto, bytes([129 if ipv6 else 0]) + segment[1:])
            assert reply == expected
            h.command('P', ip_packet(source, '::1' if ipv6 else '127.0.0.1', proto, segment), expected=-3)
        h.command('P', b'\x45', expected=-1)
        h.command('P', b'x' * 1501, expected=-14)
        h.command('Q'); stats = struct.unpack('!6I', h.take('Q'))
        assert stats[0] == 0 and stats[1] == 1 and stats[2] >= 3 and stats[4] > 80 and stats[5] > 80, stats
        h.command('S'); h.status('S', 0)
        h.command('N', b'\x02', expected=-3)
        h.command('N', b'\x03', expected=-3)
        h.command('N', b'\x04')
        h.command('P', udp('fd12::2', '::1', 43000, 9, b'unsupported'), expected=-3)
        h.command('S'); h.status('S', 0)
        # Reentrant emit and selection close must drain pending stack/relay/UDP callbacks.
        for mode in (2, 4):
            h.command('N'); h.command('G', struct.pack('!I', mode))
            peer = Peer(h, False, 44000 + mode)
            peer.destination = '127.0.0.1'
            if mode == 2:
                peer.send(2)
            else:
                peer.send(2)
                from lwip import decode
                syn = decode(h.take('P', peer.matching)); peer.ack = syn[4] + 1
                peer.send(0x10)
            h.status('S', 0)
            h.command('G', struct.pack('!I', 0))
        h.command('N'); h.command('G', struct.pack('!I', 4))
        h.command('P', udp('10.12.0.2', '127.0.0.1', 45000, 9, b'cancel in UDP select'))
        h.status('S', 0); h.command('G', struct.pack('!I', 0))
        h.command('N')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0)); server.settimeout(5)
            h.command('P', udp('10.12.0.2', '127.0.0.1', 45001, server.getsockname()[1], b'reply-close'))
            payload, peer = server.recvfrom(1500)
            h.command('G', struct.pack('!I', 2)); server.sendto(payload, peer)
            assert take_udp(h, 4, server.getsockname()[1], 45001) == payload
            h.status('S', 0)
        h.command('G', struct.pack('!I', 0))
        # Constructor failures must release both UDP dispatcher and stack,
        # leave no on_close callback, and permit a subsequent activation.
        for failures in range(24):
            h.command('M', struct.pack('!I', failures))
            h.process.stdin.write(b'N\0\0\0\0'); h.process.stdin.flush()
            result = h.take('A', lambda data: struct.unpack_from('!I', data)[0] == ord('N'))
            status = struct.unpack_from('!i', result, 4)[0]
            assert status in (0, -2), (failures, status)
            h.command('M', struct.pack('!i', -1))
            if status == 0:
                h.command('S'); h.status('S', 0)
            else:
                h.drain(.01)
                assert not any(kind == 'S' for kind, _ in h.events)
        h.command('N')
        udp_round(h, False)
        h.stop()
    except BaseException:
        h.process.kill(); h.process.wait()
        print(h.process.stderr.read().decode(), file=sys.stderr)
        raise
    print('TUN ingress: dual-stack TCP/UDP, half-close, mapping, fragmented replies and lifecycle passed')


if __name__ == '__main__':
    main(sys.argv[1])
