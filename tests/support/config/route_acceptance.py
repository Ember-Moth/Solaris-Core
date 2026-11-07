#!/usr/bin/env python3
"""Public SDK plus explicit scheduler/clock/allocation gates and real loopback I/O.

The private driver occupies libuv's worker pool to queue the unchanged system
resolver. It never replaces DNS results, routing policy, plans or socket I/O.
"""
import io
import queue
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
from runtime_proxy import (Runtime, Peer, echo, config, by_name, connect, http_tunnel, socks_tcp,
                           udp_control, udp_exchange, assert_echo, address, read_address, until, all_bytes)
from runtime_control import live, wait_for, for_socket, u64, closed
from runtime_acceptance import apply, end_control


class DualTcpPeer(Peer):
    def __init__(self):
        self.accepted = queue.Queue()
        self.errors = queue.Queue()
        self.handler = self.handle_echo
        self.s, self.v4 = dual_sockets(socket.SOCK_STREAM)
        self.host, self.port = 'localhost', self.s.getsockname()[1]
        for source in (self.s, self.v4):
            source.listen(16)
            threading.Thread(target=self.serve, args=(source,), daemon=True).start()

    def serve(self, source):
        while True:
            conn, _ = source.accept()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle_echo(self, conn):
        self.accepted.put(True); echo(conn)


class DualUdpPeer:
    def __init__(self):
        self.s, self.v4 = dual_sockets(socket.SOCK_DGRAM)
        self.port = self.s.getsockname()[1]
        self.received = queue.Queue()
        self.errors = queue.Queue()
        for source in (self.s, self.v4):
            threading.Thread(target=self.serve, args=(source,), daemon=True).start()

    def serve(self, source):
        try:
            while True:
                data, peer = source.recvfrom(65536)
                self.received.put((data, source.family, peer))
                source.sendto(data, peer)
        except Exception as error:
            self.errors.put(error)

    def check(self):
        if not self.errors.empty(): raise self.errors.get()


def dual_sockets(kind):
    for _ in range(100):
        ipv6 = socket.socket(socket.AF_INET6, kind); ipv4 = socket.socket(socket.AF_INET, kind)
        ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            ipv6.bind(('::1', 0)); ipv4.bind(('127.0.0.1', ipv6.getsockname()[1]))
            return ipv6, ipv4
        except OSError:
            ipv6.close(); ipv4.close()
    raise AssertionError('could not reserve same-port IPv4/IPv6 loopback peers')


def dns_config(web, socks):
    return config(web, socks).replace('rules: ["MATCH,DIRECT"]',
        'rules: ["IP-CIDR,127.0.0.0/8,DIRECT", "IP-CIDR6,::1/128,DIRECT", "MATCH,REJECT"]')


def pending_connect(runtime, web, peer):
    conn = connect(web)
    conn.sendall(f'CONNECT localhost:{peer.port} HTTP/1.1\r\nHost: localhost:{peer.port}\r\n\r\n'.encode())
    record = wait_for(lambda: next((p for p in live(runtime) if p['source']['port'] == conn.getsockname()[1]
                                   and p['target']['host'] == 'localhost' and p['node'] == 0), None))
    runtime.command('V')
    record = runtime.command('I', u64(record['generation'], record['id']))['connection']
    assert record['state'] == 0 and record['node'] == 0
    assert peer.accepted.empty()
    return conn, record


def route_without_dns(runtime, ports, peer):
    web, socks = ports
    cases = [
        ('localhost', ['DOMAIN,localhost,REJECT', 'IP-CIDR,127.0.0.0/8,DIRECT'], 0),
        ('127.0.0.1', ['IP-CIDR,127.0.0.0/8,REJECT'], 0),
        ('localhost', ['SRC-IP-CIDR,127.0.0.0/8,REJECT'], 0),
        ('localhost', ['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve', 'MATCH,REJECT'], 1),
    ]
    import json
    for host, rules, expected_rule in cases:
        yaml = config(web, socks).replace('rules: ["MATCH,DIRECT"]', 'rules: ' + json.dumps(rules))
        _, revision = apply(runtime, yaml)
        reject = next(node['id'] for node in runtime.command('G')['nodes'] if node['name'] == 'REJECT')
        runtime.command('U')
        with connect(web) as conn:
            source = conn.getsockname()[1]
            conn.sendall(f'CONNECT {host}:{peer.port} HTTP/1.1\r\nHost: {host}:{peer.port}\r\n\r\n'.encode())
            # A rule that awaited the system resolver cannot finish while all
            # four worker threads are held. REJECT itself performs no DNS/I/O.
            assert all_bytes(conn).startswith(b'HTTP/1.1 502 ')
        runtime.command('V')
        record = next(p for p in runtime.command('L', b'\1')['connections'] if p['source']['port'] == source)
        assert record['revision'] == revision and record['rule'] == expected_rule and record['node'] == reject
        runtime.command('W')
        assert peer.accepted.empty()
    print('SDK R01: domain/numeric/source-CIDR/no-resolve decisions complete with the real resolver queue blocked', flush=True)


def pending_commit_close_stop(runtime, ports):
    web, socks = ports
    peer = DualTcpPeer()
    _, old_revision = apply(runtime, dns_config(web, socks))
    runtime.prepare(1, config(web, socks, route='REJECT'))
    runtime.command('U')
    conn, before = pending_connect(runtime, web, peer)
    revision = runtime.commit(1)['revision']; runtime.command('R', b'\1')
    assert revision != old_revision and before['revision'] == old_revision
    runtime.command('W')
    assert until(conn).startswith(b'HTTP/1.1 200 '); assert_echo(conn, b'queued-DNS-keeps-old-plan')
    after = for_socket(runtime, conn)
    assert after['revision'] == old_revision and after['rule'] in (0, 1) and after['node']
    assert after['target']['host'] == 'localhost' and after['dial']['host'] in ('127.0.0.1', '::1')
    peer.accepted.get(timeout=2)
    runtime.command('D', u64(after['generation'], after['id'])); closed(conn)
    with connect(web) as denied:
        denied.sendall(f'CONNECT localhost:{peer.port} HTTP/1.1\r\nHost: localhost:{peer.port}\r\n\r\n'.encode())
        assert all_bytes(denied).startswith(b'HTTP/1.1 502 ')
    assert peer.accepted.empty()

    for action in ('close', 'stop'):
        apply(runtime, dns_config(web, socks)); runtime.command('U')
        conn, record = pending_connect(runtime, web, peer)
        if action == 'close':
            runtime.command('d', u64(record['generation'], record['id']))
            wait_for(lambda: runtime.command('I', u64(record['generation'], record['id']))['connection']['state'] in (2, 3))
        else:
            runtime.command('s')
            wait_for(lambda: runtime.command('m')['state'] in (2, 4))
        runtime.command('W')
        if action == 'close':
            done = runtime.command('e'); assert done['matched'] == 1 and done['close_callbacks'] == 1
            runtime.command('V')
        else:
            assert runtime.command('w')['stop_events'] == 1
        closed(conn); assert peer.accepted.empty()
        if action == 'stop': runtime.command('N')
    peer.check()
    print('SDK R03: queued system DNS crosses commit on old plan; close/stop finish once without a target open', flush=True)


class DatagramBytes:
    def __init__(self, value): self.value = value
    def recv(self, size):
        result, self.value = self.value[:size], self.value[size:]
        return result


def send_udp(client, bound, host, port, payload):
    client.sendto(b'\0\0\0' + address(host, port) + payload, bound)


def receive_udp(client, port, expected=None):
    reader = DatagramBytes(client.recv(65536)); assert reader.recv(3) == b'\0\0\0'
    host, actual_port = read_address(reader); assert host in ('127.0.0.1', '::1') and actual_port == port
    if expected is not None: assert reader.value == expected
    return reader.value


def udp_record(runtime, client, closed_history=False):
    port = client.getsockname()[1]
    records = runtime.command('L', b'\1' if closed_history else b'')['connections']
    matches = [p for p in records if p['kind'] == 2 and p['source']['port'] == port]
    return max(matches, key=lambda p: p['id']) if matches else None


def routed_burst(runtime, ports):
    web, socks = ports
    peer = DualUdpPeer()
    _, old_revision = apply(runtime, dns_config(web, socks))
    runtime.prepare(1, config(web, socks, route='REJECT'))
    control, bound = udp_control(socks)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('127.0.0.1', 0)); client.settimeout(3)
        runtime.command('U')
        payloads = [f'queued-packet-{i}'.encode() for i in range(8)]
        send_udp(client, bound, 'localhost', peer.port, payloads[0])
        record = wait_for(lambda: udp_record(runtime, client))
        runtime.command('V'); assert record['revision'] == old_revision and record['node'] == 0
        for payload in payloads[1:]: send_udp(client, bound, 'localhost', peer.port, payload)
        runtime.command('V')
        assert peer.received.empty()
        assert udp_record(runtime, client)['id'] == record['id']
        current = runtime.commit(1)['revision']; runtime.command('R', b'\1'); assert current != old_revision
        runtime.command('W')
        received = [receive_udp(client, peer.port) for _ in payloads]
        assert sorted(received) == sorted(payloads)
        actual = [peer.received.get(timeout=2)[0] for _ in payloads]; assert sorted(actual) == sorted(payloads)
        result = wait_for(lambda: (p if (p := udp_record(runtime, client)) and p['packets_written'] == 8 and p['packets_read'] == 8 else None))
        assert result['id'] == record['id'] and result['revision'] == old_revision and result['node']
        other = '::1' if result['dial']['host'] == '127.0.0.1' else '127.0.0.1'
        send_udp(client, bound, other, peer.port, b'old-plan-new-family')
        receive_udp(client, peer.port, b'old-plan-new-family'); peer.received.get(timeout=2)
        result = udp_record(runtime, client); assert result['channels'] == 2 and result['revision'] == old_revision
    end_control(runtime, control); peer.check()
    print('SDK U01/U02/L02: eight packets during ROUTING share one old association; a new family lane survives reload', flush=True)


def idle_recapture(runtime, ports):
    web, socks = ports
    peer = Peer(None, udp=True)
    _, old_revision = apply(runtime, config(web, socks))
    control, bound = udp_control(socks)
    control_info = for_socket(runtime, control)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('127.0.0.1', 0)); client.settimeout(2)
        udp_exchange(client, bound, peer, b'original-association')
        first = wait_for(lambda: (p if (p := udp_record(runtime, client)) and p['packets_written'] == 1 else None))
        _, rejected_revision = apply(runtime, config(web, socks, route='REJECT'))
        udp_exchange(client, bound, peer, b'old-association-before-idle')
        wait_for(lambda: udp_record(runtime, client)['packets_written'] == 2); runtime.command('V')
        runtime.command('Z', u64(300100))
        wait_for(lambda: runtime.command('I', u64(first['generation'], first['id']))['connection']['state'] == 3)
        assert runtime.command('I', u64(control_info['generation'], control_info['id']))['connection']['state'] == 1
        udp_exchange(client, bound, peer, b'rebuilt-under-REJECT', success=False)
        rejected = wait_for(lambda: (p if (p := udp_record(runtime, client, True)) and p['id'] != first['id'] and p['state'] == 3 else None))
        assert rejected['revision'] == rejected_revision and rejected['node']
        _, allowed_revision = apply(runtime, config(web, socks))
        udp_exchange(client, bound, peer, b'rebuilt-under-current-DIRECT')
        current = wait_for(lambda: (p if (p := udp_record(runtime, client)) and p['packets_written'] == 1 else None))
        assert current['revision'] == allowed_revision and current['id'] != first['id']
        apply(runtime, config(web, socks, auth=True))
        udp_exchange(client, bound, peer, b'old-plan-survives-auth')
        wait_for(lambda: udp_record(runtime, client)['packets_written'] == 2); runtime.command('V')
        runtime.command('Z', u64(300100))
        wait_for(lambda: runtime.command('I', u64(current['generation'], current['id']))['connection']['state'] == 3)
        before = runtime.command('F')['logical'][0]['created']
        udp_exchange(client, bound, peer, b'old-auth-new-association-denied', success=False)
        closed(control)
        wait_for(lambda: runtime.command('I', u64(control_info['generation'], control_info['id']))['connection']['state'] == 3)
        assert runtime.command('F')['logical'][0]['created'] == before
    peer.check()
    print('SDK U02: injected monotonic advancement expires default 300s association, retains control, recaptures current route and rejects changed auth', flush=True)


def owner_prepare_failures(runtime, ports):
    web, socks = ports
    target = Peer(echo)
    _, active_revision = apply(runtime, config(web, socks))
    old_http, old_socks = http_tunnel(web, target), socks_tcp(socks, target)
    records = [for_socket(runtime, stream) for stream in (old_http, old_socks)]
    assert {record['worker'] for record in records} == {0, 1}
    extra = ('  - {name: extra-web, type: http, listen: 127.0.0.1, port: 19090}\n'
             '  - {name: extra-socks, type: socks, listen: 127.0.0.1, port: 19091, udp: true}\n')
    candidate = config(web, socks, extra=extra)
    for owner in (0, 1):
        failures = 0
        for index in range(128):
            for stream in (old_http, old_socks): assert_echo(stream, b'old-service-before-failure')
            wait_for(lambda: all(record['pending_requests'] == 0 for record in live(runtime)))
            armed = runtime.command('A', struct.pack('!II', owner, index))
            prepared = runtime.prepare(0, candidate, ephemeral=True, expected=None)
            result = runtime.command('A', struct.pack('!II', 0xffffffff, 0))
            if result['failed']:
                assert prepared['status'] == -2 and not prepared['listeners'], (owner, index, prepared, result)
                assert result['owner_allocations'] == index + 1
                failures += 1
            else:
                assert prepared['status'] == 0, (owner, index, prepared, result)
                assert {info['worker'] for info in prepared['listeners']} == {0, 1}
                runtime.command('R', b'\0')
            wait_for(lambda: runtime.command('m')['buffer_bytes'] == armed['buffer_bytes'])
            assert runtime.command('Q')['revision'] == active_revision
            for stream in (old_http, old_socks): assert_echo(stream, b'old-service-after-rollback')
            if not result['failed']:
                assert failures > 0
                print(f'SDK L01: owner {owner} candidate preparation {failures} allocation failure points rolled back; both old owners kept forwarding', flush=True)
                break
        else:
            raise AssertionError(('allocation walk did not reach a successful prepare', owner))
    for stream in (old_http, old_socks): stream.close()
    target.check()


def test(binary):
    runtime = Runtime(binary)
    prepared, _ = apply(runtime, config(18080, 18081), ephemeral=True)
    ports = by_name(prepared); ports = ports['web']['port'], ports['socks']['port']
    route_without_dns(runtime, ports, DualTcpPeer())
    pending_commit_close_stop(runtime, ports)
    routed_burst(runtime, ports)
    idle_recapture(runtime, ports)
    owner_prepare_failures(runtime, ports)
    runtime.finish()
    print('Public SDK with explicit private scheduler/clock/allocation gates: route acceptance passed', flush=True)


if __name__ == '__main__':
    test(sys.argv[1])
