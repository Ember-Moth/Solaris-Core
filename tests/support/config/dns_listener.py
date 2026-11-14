#!/usr/bin/env python3
"""Exercise paired DNS listeners through the public SDK transaction driver."""
import socket
import struct
import sys
import threading
from contextlib import ExitStack
from pathlib import Path

from runtime_proxy import Runtime
from inbound import exact
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dns'))
from service import Peer, parse_question, reply
from loopback import tcp_udp_pair

# TXT RDATA length is independent of DNS name compression. One complete RR
# spans the 512-byte limit, another spans the server's 1232-byte UDP cap.
TEXT = {
    'text.test': b'\x03dns\x05wire!',
    'edns.test': b'\x06opaque',
    'unsolicited.test': b'\x06opaque',
    'medium.test': (b'\xf0' + b'm' * 240) * 3,
    'large.test': (b'\xf0' + b'l' * 240) * 7,
}


class Upstream(Peer):
    """Real upstream with per-question gates for pipeline and cancellation tests."""
    def __init__(self):
        super().__init__('local-listener')
        self.names = []
        self.gates = {name: (threading.Event(), threading.Event())
                      for name in ('slow.test', 'shared.test', 'retire.test', 'pending-udp.test', 'pending-tcp.test')}
        self.replied = {name: threading.Event() for name in self.gates}

    def response(self, query):
        name, end = unpack_name(query, 12)
        if name in TEXT:
            identifier, flags, qd, an, ns, ar = struct.unpack_from('!6H', query)
            expected_flags = 0x110 if name == 'edns.test' else 0x100
            assert (flags, qd, an, ns) == (expected_flags, 1, 0, 0)
            if ar:
                assert ar == 1 and query[end + 4] == 0
                opt = struct.unpack_from('!HHIH', query, end + 5)
                assert opt == (41, 1232, 0x8000 if name == 'edns.test' else 0, 0), opt
            else:
                assert name != 'edns.test'

            assert struct.unpack_from('!HH', query, end) == (16, 1)
            with self.lock:
                self.names.append(name)
            rdata = TEXT[name]
            ttl = 60 if name == 'text.test' else 0
            record = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, ttl, len(rdata)) + rdata
            # The upstream supplies an OPT with its own size and private option,
            # or omits OPT entirely. The listener negotiates its own client hop.
            opt = (b'\0' + struct.pack('!HHIH', 41, 4096, 0x8000, 6)
                   + struct.pack('!HH2s', 65001, 2, b'XX')) if name in ('edns.test', 'unsolicited.test') else b''
            return struct.pack('!6H', identifier, 0x8180 | (flags & 0x10), 1, 1, 0, bool(opt)) + query[12:end + 4] + record + opt
        identifier, end, _, _ = parse_question(query)
        with self.lock:
            self.names.append(name)
        if name in self.gates:
            entered, release = self.gates[name]
            entered.set()
            assert release.wait(10), name
        if name == 'missing.test':
            return struct.pack('!6H', identifier, 0x8183, 1, 0, 0, 0) + query[12:end]
        assert name == 'remote.test' or name in self.gates, name
        return reply(query, last=42)

    def udp_reply(self, packet, client):
        name, end = unpack_name(packet, 12)
        if name in ('medium.test', 'large.test'):
            # Force real UDP -> TCP upstream fallback. The final TCP body is
            # independently delivered/truncated for each listener transport.
            identifier, = struct.unpack_from('!H', packet)
            self.udp.sendto(struct.pack('!6H', identifier, 0x8380, 1, 0, 0, 0) + packet[12:end + 4], client)
        else:
            super().udp_reply(packet, client)
        if name in self.replied:
            self.replied[name].set()

    def __exit__(self, *exc):
        for _, release in self.gates.values():
            release.set()
        super().__exit__(*exc)
        assert not self.errors, self.errors


class BrokenUpstream(Peer):
    def __init__(self):
        super().__init__('malformed-upstream')

    def tcp_reply(self, conn):
        try:
            with conn:
                conn.settimeout(3)
                prefix = exact(conn, 2)
                packet = exact(conn, struct.unpack('!H', prefix)[0])
                assert parse_question(packet)[3] == b'broken.test'
                conn.sendall(b'\x00\x08')  # shorter than a DNS header
                with self.lock:
                    self.tcp_queries += 1
        except Exception as error:
            self.errors.append(repr(error))

    def __exit__(self, *exc):
        super().__exit__(*exc)
        assert not self.errors, self.errors
        if not exc[0]:
            assert self.tcp_queries == 2, self.tcp_queries


def profile(upstream, listen, local='127.0.0.1', transport='udp'):
    return (f'[General]\nconfig-version=1\nmode=direct\n[DNS]\nenabled=true\nipv6=true\n'
            f'use-system-hosts=false\nupstream={transport}://127.0.0.1:{upstream}\nlisten={listen}\n'
            f'[Host]\nlocal.test = {local}\n')


def question(name, qtype=1):
    labels = [label.encode('ascii') for label in name.split('.')]
    return b''.join(bytes([len(label)]) + label for label in labels) + b'\0' + struct.pack('!HH', qtype, 1)


def query(identifier, name, edns=0, qtype=1, edns_flags=0, cd=False, options=b''):
    packet = struct.pack('!6H', identifier, 0x0100 | (0x10 if cd else 0), 1, 0, 0, int(bool(edns))) + question(name, qtype)
    if edns:
        packet += b'\0' + struct.pack('!HHIH', 41, edns, edns_flags, len(options)) + options
    return packet


def unpack_name(wire, offset):
    labels, next_offset = [], None
    while True:
        length = wire[offset]
        if length & 0xc0 == 0xc0:
            target = ((length & 0x3f) << 8) | wire[offset + 1]
            assert target < offset, (target, offset)
            if next_offset is None:
                next_offset = offset + 2
            offset = target
            continue
        offset += 1
        if not length:
            return b'.'.join(labels).decode('ascii'), next_offset or offset
        assert length <= 63 and offset + length <= len(wire)
        labels.append(wire[offset:offset + length])
        offset += length
        assert sum(map(len, labels)) + len(labels) <= 255


def check(wire, identifier, name, expected, *, rcode=0, truncated=False, qtype=1, edns=False, do=False, cd=False):
    ident, flags, questions, answers, authority, additional = struct.unpack_from('!6H', wire)
    assert ident == identifier and flags & 0x8000 and flags & 0x100, (ident, flags, identifier)
    assert (flags & 15) == rcode and bool(flags & 0x200) == truncated, (flags, name)
    assert questions == 1 and authority == 0 and additional == int(edns)
    assert bool(flags & 0x10) == cd
    q = question(name, qtype)
    assert wire[12:12 + len(q)] == q
    offset = 12 + len(q)
    records = []
    for index in range(answers + additional):
        owner, offset = unpack_name(wire, offset)
        kind, cls, ttl, size = struct.unpack_from('!HHIH', wire, offset)
        offset += 10
        record = wire[offset:offset + size]
        assert len(record) == size
        if index < answers:
            assert (owner, kind, cls) == (name, qtype, 1)
            if qtype == 1:
                assert size == 4 and ttl > 0
                records.append(socket.inet_ntoa(record))
            else:
                records.append(record)
        else:
            assert (owner, kind, cls, ttl, size) == ('', 41, 1232, 0x8000 if do else 0, 0)
        offset += size
    assert offset == len(wire)
    assert records == (expected[:len(records)] if truncated else expected), records


def frame(wire):
    return struct.pack('!H', len(wire)) + wire


def tcp_reply(conn):
    size, = struct.unpack('!H', exact(conn, 2))
    assert size >= 12, size
    return exact(conn, size)


def tcp_query(conn, identifier, name, **options):
    conn.sendall(frame(query(identifier, name, **options)))
    return tcp_reply(conn)


def udp_query(client, endpoint, identifier, name, **options):
    client.sendto(query(identifier, name, **options), endpoint)
    result, source = client.recvfrom(65535)
    assert source[:2] == endpoint, (source, endpoint)
    return result


def quiet(client):
    previous = client.gettimeout()
    client.settimeout(.25)
    try:
        client.recvfrom(65535)
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
        return
    finally:
        client.settimeout(previous)
    raise AssertionError('received an unexpected UDP reply')


def closed(conn):
    try:
        assert conn.recv(1) == b''
    except (ConnectionResetError, ConnectionAbortedError):
        pass


def inactive(client, endpoint):
    client.sendto(query(51, 'inactive.test'), endpoint)
    quiet(client)
    try:
        with socket.create_connection(endpoint, timeout=3) as conn:
            conn.sendall(frame(query(52, 'inactive.test')))
            closed(conn)
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
        pass


def dns_info(snapshot):
    value, = snapshot['listeners']
    assert value['name'] == 'dns' and value['protocol'] == 4 and value['udp'] == 1
    assert value['auth'] == 0 and value['id'] and value['port'] and 0 <= value['worker'] < 2
    return value


def bind_failure(runtime, upstream, block_udp):
    tcp, udp, guard = tcp_udp_pair(socket.AF_INET)
    with tcp, udp, guard:
        port = tcp.getsockname()[1]
        if block_udp:
            tcp.close()
            free_kind = socket.SOCK_STREAM
        else:
            tcp.listen(1)
            udp.close()
            free_kind = socket.SOCK_DGRAM
        revision = runtime.command('Q')['revision']
        result = runtime.prepare(12, profile(upstream, f'127.0.0.1:{port}'), expected=None)
        assert result['status'] != 0 and result['listeners'] == [], result
        assert runtime.command('Q')['revision'] == revision
        # Failed prepare must drain the other half of this pair by its callback.
        with socket.socket(socket.AF_INET, free_kind) as probe:
            probe.bind(('127.0.0.1', port))
            if free_kind == socket.SOCK_STREAM:
                probe.listen(1)


def test(binary):
    with ExitStack() as stack:
        upstream = stack.enter_context(Upstream())
        runtime = Runtime(binary)
        stack.callback(runtime.abort)
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.settimeout(3)
        initial = runtime.prepare(0, profile(upstream.port, '127.0.0.1:5353'), ephemeral=True)
        bound = dns_info(initial)
        endpoint = (bound['address'], bound['port'])
        assert endpoint[0] == '127.0.0.1' and bound['configured_port'] == 5353
        assert bound['requested_port'] == 0 and bound['overridden'] == 1
        assert runtime.command('Q')['listeners'] == []
        inactive(udp, endpoint)
        revision = runtime.commit(0)['revision']
        assert runtime.command('Q')['revision'] == revision and dns_info(runtime.command('Q')) == bound
        runtime.command('R', bytes([0]))

        check(udp_query(udp, endpoint, 1, 'local.test'), 1, 'local.test', ['127.0.0.1'])
        # The file itself is valid. Reusing the active ephemeral socket makes
        # the candidate's configured client upstream its own effective endpoint.
        bad_conf = profile(endpoint[1], '127.0.0.1:5354')
        if endpoint[1] == 5354:
            bad_conf = profile(endpoint[1], '127.0.0.1:5355')
        rejected = runtime.prepare(12, bad_conf, ephemeral=True, expected=-1)
        assert rejected['listeners'] == [] and runtime.command('Q')['revision'] == revision
        check(udp_query(udp, endpoint, 99, 'local.test'), 99, 'local.test', ['127.0.0.1'])
        check(udp_query(udp, endpoint, 2, 'missing.test'), 2, 'missing.test', [], rcode=3)
        check(udp_query(udp, endpoint, 3, 'remote.test'), 3, 'remote.test', ['127.0.0.42'])
        check(udp_query(udp, endpoint, 22, 'text.test', qtype=16), 22, 'text.test', [TEXT['text.test']], qtype=16)
        # A response received at the listening endpoint is not a query.
        qr_packet = bytearray(query(4, 'malformed.test'))
        qr_packet[2] |= 0x80
        for malformed in (b'\x12', query(4, 'malformed.test') + b'trailing', qr_packet):
            udp.sendto(malformed, endpoint)
            quiet(udp)
        with socket.create_connection(endpoint, timeout=3) as bad:
            bad.sendall(b'\x00\x00')
            closed(bad)

        for name, edns, limit, tc in [('medium.test', 0, 512, True), ('medium.test', 1024, 1024, False),
                                       ('large.test', 4096, 1232, True)]:
            answer = udp_query(udp, endpoint, 5, name, edns=edns, qtype=16)
            assert len(answer) <= limit
            check(answer, 5, name, [TEXT[name]], truncated=tc, qtype=16, edns=bool(edns))
        private_option = struct.pack('!HH2s', 65001, 2, b'YY')
        wire = udp_query(udp, endpoint, 80, 'edns.test', edns=512, qtype=16, edns_flags=0x8000,
                         cd=True, options=private_option)
        check(wire, 80, 'edns.test', [TEXT['edns.test']], qtype=16, edns=True, do=True, cd=True)
        # An unsolicited upstream OPT must not appear in a plain client's
        # response, including when it contains unknown options.
        check(udp_query(udp, endpoint, 81, 'unsolicited.test', qtype=16),
              81, 'unsolicited.test', [TEXT['unsolicited.test']], qtype=16)
        old = stack.enter_context(socket.create_connection(endpoint, timeout=3))
        check(tcp_query(old, 6, 'large.test', edns=512, qtype=16), 6, 'large.test', [TEXT['large.test']], qtype=16, edns=True)

        # Split the length prefix. While a later query is pending upstream,
        # complete a hosts hit on the same TCP stream, then drain after FIN.
        with socket.create_connection(endpoint, timeout=3) as pipeline:
            first = frame(query(7, 'slow.test'))
            pipeline.sendall(first[:1])
            check(udp_query(udp, endpoint, 8, 'local.test'), 8, 'local.test', ['127.0.0.1'])
            pipeline.sendall(first[1:9])
            check(udp_query(udp, endpoint, 23, 'local.test'), 23, 'local.test', ['127.0.0.1'])
            pipeline.sendall(first[9:] + frame(query(9, 'local.test')))
            pipeline.shutdown(socket.SHUT_WR)
            entered, release = upstream.gates['slow.test']
            assert entered.wait(3), 'slow query never reached the upstream'
            check(tcp_reply(pipeline), 9, 'local.test', ['127.0.0.1'])
            release.set()
            check(tcp_reply(pipeline), 7, 'slow.test', ['127.0.0.42'])
            closed(pipeline)

        # Two transports share a wire query. Break only the TCP frame stream.
        # The next UDP hosts hit is a receive-order fence for the first UDP
        # packet; it proves that the datagram reached this publication.
        with socket.create_connection(endpoint, timeout=3) as cancelled:
            cancelled.sendall(frame(query(28, 'shared.test')))
            entered, release = upstream.gates['shared.test']
            assert entered.wait(3)
            udp.sendto(query(29, 'shared.test'), endpoint)
            check(udp_query(udp, endpoint, 30, 'local.test'), 30, 'local.test', ['127.0.0.1'])
            cancelled.sendall(b'\x00\x00')
            closed(cancelled)
            release.set()
            shared_reply, source = udp.recvfrom(65535)
            assert source[:2] == endpoint
            check(shared_reply, 29, 'shared.test', ['127.0.0.42'])

        # Send more than one pipeline window. Buffered complete frames must
        # resume after backpressure even when the peer has sent its final FIN.
        with socket.create_connection(endpoint, timeout=3) as burst:
            identifiers = set(range(100, 140))
            burst.sendall(b''.join(frame(query(i, 'local.test')) for i in sorted(identifiers)))
            burst.shutdown(socket.SHUT_WR)
            while identifiers:
                answer = tcp_reply(burst)
                i, = struct.unpack_from('!H', answer)
                assert i in identifiers
                identifiers.remove(i)
                check(answer, i, 'local.test', ['127.0.0.1'])
            closed(burst)

        for block_udp in (False, True):
            bind_failure(runtime, upstream.port, block_udp)
            check(udp_query(udp, endpoint, 10, 'local.test'), 10, 'local.test', ['127.0.0.1'])
            check(tcp_query(old, 11, 'local.test'), 11, 'local.test', ['127.0.0.1'])

        fixed = f'127.0.0.1:{endpoint[1]}'
        fresh = dns_info(runtime.prepare(1, profile(upstream.port, fixed, '127.0.0.2')))
        assert fresh['id'] == bound['id'] and fresh['port'] == bound['port']
        assert fresh['configured_port'] == fresh['requested_port'] == fresh['port'] and not fresh['overridden']
        check(udp_query(udp, endpoint, 12, 'local.test'), 12, 'local.test', ['127.0.0.1'])
        # A datagram submitted to the old publication must still send its
        # response through this port after the physical pair has been reused.
        deferred_udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        deferred_udp.settimeout(3)
        deferred_udp.sendto(query(27, 'retire.test'), endpoint)
        assert upstream.gates['retire.test'][0].wait(3)
        assert runtime.commit(1)['revision'] > revision
        runtime.command('R', bytes([1]))
        upstream.gates['retire.test'][1].set()
        reply_old, source_old = deferred_udp.recvfrom(65535)
        assert source_old[:2] == endpoint
        check(reply_old, 27, 'retire.test', ['127.0.0.42'])
        check(udp_query(udp, endpoint, 13, 'local.test'), 13, 'local.test', ['127.0.0.2'])
        with socket.create_connection(endpoint, timeout=3) as current:
            check(tcp_query(current, 14, 'local.test'), 14, 'local.test', ['127.0.0.2'])
        check(tcp_query(old, 15, 'local.test'), 15, 'local.test', ['127.0.0.1'])
        assert runtime.prepare(2, profile(upstream.port, 'off'))['listeners'] == []
        runtime.commit(2)
        runtime.command('R', bytes([2]))
        assert runtime.command('Q')['listeners'] == []
        inactive(udp, endpoint)
        check(tcp_query(old, 16, 'local.test'), 16, 'local.test', ['127.0.0.1'])
        old.close()

        # The upstream accepts a connection and returns a malformed DNS frame.
        failed_upstream = stack.enter_context(BrokenUpstream())
        failed_conf = profile(failed_upstream.port, '127.0.0.1:5353', transport='tcp')
        port4 = dns_info(runtime.prepare(5, failed_conf, ephemeral=True))['port']
        runtime.commit(5)
        runtime.command('R', bytes([5]))
        check(udp_query(udp, ('127.0.0.1', port4), 25, 'broken.test'), 25, 'broken.test', [], rcode=2)
        with socket.create_connection(('127.0.0.1', port4), timeout=3) as tcp:
            check(tcp_query(tcp, 26, 'broken.test'), 26, 'broken.test', [], rcode=2)

        # Stop with two unanswered upstream requests, then reuse the exact old
        # port on a new generation. A delayed old response must not reach it.
        fresh = dns_info(runtime.prepare(3, profile(upstream.port, '[::1]:5353'), ephemeral=True))
        runtime.commit(3)
        runtime.command('R', bytes([3]))
        endpoint6 = ('::1', fresh['port'])
        assert fresh['address'] == '::1'
        udp6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
        udp6.settimeout(3)
        check(udp_query(udp6, endpoint6, 17, 'local.test'), 17, 'local.test', ['127.0.0.1'])
        with socket.create_connection(endpoint6, timeout=3) as pending:
            check(tcp_query(pending, 18, 'local.test'), 18, 'local.test', ['127.0.0.1'])
            pending.sendall(frame(query(19, 'pending-tcp.test')))
            udp6.sendto(query(20, 'pending-udp.test'), endpoint6)
            for name in ('pending-tcp.test', 'pending-udp.test'):
                assert upstream.gates[name][0].wait(3), name
            runtime.command('S')
            assert runtime.command('Q')['listeners'] == []
            closed(pending)
        runtime.command('N')
        restarted = dns_info(runtime.prepare(4, profile(upstream.port, f'[::1]:{fresh["port"]}')))
        assert restarted['port'] == endpoint6[1]
        runtime.commit(4)
        for name in ('pending-tcp.test', 'pending-udp.test'):
            upstream.gates[name][1].set()
        for name in ('pending-tcp.test', 'pending-udp.test'):
            assert upstream.replied[name].wait(3), name
        quiet(udp6)
        check(udp_query(udp6, endpoint6, 21, 'local.test'), 21, 'local.test', ['127.0.0.1'])
        runtime.finish()
        assert upstream.tcp_queries == 4
        expected = ['remote.test', 'missing.test', 'text.test', 'edns.test', 'unsolicited.test', 'medium.test', 'medium.test',
                    'large.test', 'large.test', *upstream.gates]
        assert sorted(upstream.names) == sorted(expected), upstream.names
    print('Public DNS listener: IPv4/IPv6 TCP+UDP, EDNS bounds, framing, pipeline, rollback, reload, stop and restart passed')


if __name__ == '__main__':
    test(sys.argv[1])
