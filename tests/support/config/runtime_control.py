#!/usr/bin/env python3
"""Installed public ABI: controls, admission records, close barriers and probes."""
import queue
import socket
import struct
import sys
import threading
import time
from runtime_proxy import (Runtime, Peer, echo, until, by_name, connect, socks_greet,
                           socks_request, socks_tcp, http_tunnel, udp_control,
                           udp_exchange, assert_echo)


def conf_config(http, socks, members='DIRECT, REJECT', mode='rule'):
    return (f'[General]\nconfig-version=1\nmode={mode}\n[Listener]\n'
            f'web=http,127.0.0.1,{http}\n'
            f'socks=socks5,127.0.0.1,{socks},udp-relay=true\n'
            f'[Proxy Group]\nRoute=select,{members}\n'
            '[Rule]\nFINAL,Route\n')


def u64(*values):
    return struct.pack('!' + 'Q' * len(values), *values)


def select(runtime, revision, group, node, expected=0):
    return runtime.command('X', u64(revision, group, node), expected)


def mode(runtime, revision, value, expected=0):
    return runtime.command('M', u64(revision) + struct.pack('!I', value), expected)


def live(runtime):
    return runtime.command('L')['connections']


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while True:
        result = predicate()
        if result:
            return result
        assert time.monotonic() < deadline, 'condition did not become true'
        time.sleep(.01)


def for_socket(runtime, conn):
    port = conn.getsockname()[1]
    return wait_for(lambda: next((p for p in live(runtime)
                                  if p['source']['port'] == port and p['kind'] == 1), None))


def closed(conn):
    conn.settimeout(3)
    try:
        assert conn.recv(1) == b''
    except (ConnectionResetError, BrokenPipeError):
        pass
    conn.close()


class HeadPeer:
    def __init__(self, wait=False):
        self.received = threading.Event()
        self.release = threading.Event()
        self.wait = wait
        self.requests = queue.Queue()
        self.peer = Peer(self.handle)
        self.url = f'http://127.0.0.1:{self.peer.port}/probe-private-query?token=do-not-log'

    def handle(self, conn):
        request = until(conn)
        assert request.startswith(b'HEAD /probe-private-query?token=do-not-log HTTP/1.1\r\n'), request
        self.requests.put(request)
        self.received.set()
        if self.wait:
            assert self.release.wait(10)
        try:
            conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        except (BrokenPipeError, ConnectionResetError):
            pass


def probe(runtime, revision, target, peer, timeout=5000):
    return runtime.command('B', u64(revision, target, timeout) + peer.url.encode())['operation']


def test(binary):
    runtime = Runtime(binary)
    target = Peer(echo)
    udp = Peer(None, udp=True)
    p = by_name(runtime.prepare(0, conf_config(18080, 18081), ephemeral=True))
    http, socks = p['web']['port'], p['socks']['port']
    revision = runtime.commit(0)['revision']
    state = runtime.command('G')
    nodes = {node['name']: node['id'] for node in state['nodes']}
    groups = {group['name']: group for group in state['groups']}
    route = groups['Route']['id']
    direct, reject = nodes['DIRECT'], nodes['REJECT']
    assert groups['Route']['selected'] == direct
    assert groups['Route']['members'] == [direct, reject]
    original_selection = state['selection']
    stable = mode(runtime, revision, 1)
    assert stable['selection'] == original_selection
    select(runtime, revision + 100, route, reject, -11)
    mode(runtime, 0, 1, -1)
    select(runtime, revision, route, route, -1)

    old_http = http_tunnel(http, target)
    pending = socks_greet(socks)
    pending_record = for_socket(runtime, pending)
    assert pending_record['state'] == 0 and pending_record['revision'] == revision
    assert pending_record['selection'] == original_selection
    control, bound = udp_control(socks)
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.bind(('127.0.0.1', 0))
    udp_exchange(udp_client, bound, udp, b'old-udp')
    changed = select(runtime, revision, route, reject)
    assert changed['selection'] > original_selection
    socks_request(pending, target.host, target.port)
    assert_echo(pending, b'accept-pins-control-view')
    assert_echo(old_http, b'old-http')
    udp_exchange(udp_client, bound, udp, b'old-udp-after-selection')
    with socks_greet(socks) as denied:
        socks_request(denied, target.host, target.port, success=False)
    fresh_control, fresh_bound = udp_control(socks)
    fresh_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fresh_client.bind(('127.0.0.1', 0))
    udp_exchange(fresh_client, fresh_bound, udp, b'new-udp-rejected', success=False)

    # Candidate preparation must not capture the controls it will migrate.
    runtime.prepare(1, conf_config(http, socks))
    mode(runtime, revision, 3)
    select(runtime, revision, route, direct)
    revision = runtime.commit(1)['revision']
    state = runtime.command('G')
    assert state['mode'] == 3
    group = next(g for g in state['groups'] if g['id'] == route)
    assert group['selected'] == direct and group['reason'] == 3
    select(runtime, revision, route, reject)
    runtime.prepare(2, conf_config(http, socks, members='DIRECT'))
    revision = runtime.commit(2)['revision']
    state = runtime.command('G')
    group = next(g for g in state['groups'] if g['id'] == route)
    assert group['selected'] == direct and group['previous'] == reject and group['reason'] == 4
    assert group['reason_revision'] == state['selection']
    assert_echo(old_http, b'old-config-after-reload')

    # One targeted close cannot affect a neighboring flow. Generation matters.
    current = http_tunnel(http, target)
    entry = for_socket(runtime, current)
    wrong = runtime.command('D', u64(entry['generation'] + 1, entry['id']), expected=None)
    assert wrong['status'] != 0
    assert_echo(current, b'wrong-generation-is-not-a-close')
    result = runtime.command('D', u64(entry['generation'], entry['id']))
    assert result['matched'] == 1
    closed(current)
    record = runtime.command('I', u64(entry['generation'], entry['id']))['connection']
    assert record['state'] == 3 and record['pending_requests'] == 0 and record['channels'] == 0
    assert_echo(old_http, b'neighbor-remains-open')
    handshake = connect(socks)
    for_socket(runtime, handshake)
    result = runtime.command('D')
    assert result['matched'] >= 4
    for conn in (old_http, pending, control, fresh_control, handshake):
        closed(conn)
    assert not live(runtime)
    assert runtime.command('D')['matched'] == 0
    udp_client.close(); fresh_client.close()

    # Only completed application writes/reads belong in logical USER totals.
    before = runtime.command('F')
    current = http_tunnel(http, target)
    payload = b'count-exactly-once-' * 197
    assert_echo(current, payload)
    entry = for_socket(runtime, current)
    wait_for(lambda: runtime.command('I', u64(entry['generation'], entry['id']))['connection']['read'] == len(payload))
    runtime.command('D', u64(entry['generation'], entry['id']))
    closed(current)
    after = runtime.command('F')
    for field in ('read', 'written'):
        assert after['logical'][0][field] - before['logical'][0][field] == len(payload), (before, after)
    assert after['logical'][1]['read'] == before['logical'][1]['read']
    assert after['physical']['stream_read'] >= before['physical']['stream_read'] + len(payload)
    assert after['physical']['stream_written'] >= before['physical']['stream_written'] + len(payload)

    head = HeadPeer()
    probe(runtime, revision, direct, head)
    result = runtime.command('H')
    assert result['http'] == 204 and result['revision'] == revision and result['node'] == direct
    assert result['connection'] and result['read'] and result['written'] and result['duration']
    probe(runtime, revision, route, head)
    assert runtime.command('H')['node'] == direct
    after_probe = runtime.command('F')
    assert after_probe['logical'][0]['read'] == after['logical'][0]['read']
    assert after_probe['logical'][1]['read'] > after['logical'][1]['read']
    assert after_probe['logical'][1]['active'] == 0

    slow = HeadPeer(wait=True)
    operation = probe(runtime, revision, direct, slow)
    assert slow.received.wait(5)
    runtime.command('K', u64(operation))
    runtime.command('H', expected=-9)
    slow.release.set()
    timeout = HeadPeer(wait=True)
    probe(runtime, revision, direct, timeout, 100)
    assert timeout.received.wait(5)
    runtime.command('H', expected=-6)
    timeout.release.set()

    # A running probe owns its selected config across a configuration commit.
    runtime.prepare(3, conf_config(http, socks, members='DIRECT'))
    crossing = HeadPeer(wait=True)
    probe(runtime, revision, direct, crossing)
    assert crossing.received.wait(5)
    old_revision = revision
    revision = runtime.command('c', bytes([3]))['revision']
    crossing.release.set()
    result = runtime.command('H')
    assert result['revision'] == old_revision and old_revision != revision
    stale = probe(runtime, old_revision, direct, head)
    assert stale
    runtime.command('H', expected=-11)

    # Poll bounded logs by cursor. Enough controls to force ring eviction.
    for i in range(300):
        mode(runtime, revision, 1 if i % 2 else 3)
    logs = runtime.command('J', u64(0) + struct.pack('!I', 0))
    assert logs['overwritten'] and logs['missed'] and logs['records']
    assert all('do-not-log' not in str(record) and 'probe-private' not in str(record) for record in logs['records'])
    sequences = [record['sequence'] for record in logs['records']]
    assert sequences == sorted(set(sequences))
    one = runtime.command('J', u64(sequences[-2]) + struct.pack('!I', 1))
    assert len(one['records']) == 1 and one['cursor'] == sequences[-1]
    empty = runtime.command('J', u64(one['cursor']) + struct.pack('!I', 1))
    assert not empty['records'] and empty['cursor'] == one['cursor']

    stopping = HeadPeer(wait=True)
    probe(runtime, revision, direct, stopping)
    assert stopping.received.wait(5)
    runtime.command('S')
    runtime.command('H', expected=-9)
    stopping.release.set()
    assert not live(runtime)
    # Retain nonempty immutable snapshots through actual engine destruction.
    runtime.command('N')
    runtime.prepare(4, conf_config(http, socks, members='DIRECT'))
    revision = runtime.commit(4)['revision']
    current = http_tunnel(http, target)
    assert_echo(current, b'after-restart')
    restarted = runtime.command('F')
    assert restarted['logical'][0]['created'] > after_probe['logical'][0]['created']
    runtime.command('G'); runtime.command('L', b'\x01')
    runtime.command('J', u64(0) + struct.pack('!I', 0))
    runtime.finish()
    closed(current)
    target.check()
    udp.check()
    for peer in (head, slow, timeout, crossing, stopping):
        peer.peer.check()
    print('Public control/observation: admission pins, reload migration, close barriers, USER/PROBE accounting, cancellation, logs and snapshot lifetimes passed')


if __name__ == '__main__':
    test(sys.argv[1])
