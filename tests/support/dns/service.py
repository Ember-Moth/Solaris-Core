#!/usr/bin/env python3
"""Independent numeric UDP/TCP peers for the service/coalescing C contract."""
import argparse
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loopback import tcp_udp_pair


def parse_question(query):
    identifier, flags, qd, an, ns, ar = struct.unpack('!6H', query[:12])
    assert qd == 1 and an == ns == 0 and flags == 0x100 and ar in (0, 1)
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        assert 0 < size <= 63
        labels.append(query[offset + 1:offset + 1 + size])
        offset += size + 1
    offset += 1
    kind, cls = struct.unpack('!HH', query[offset:offset + 4])
    assert cls == 1 and kind in (1, 28)
    return identifier, offset + 4, kind, b'.'.join(labels).lower()


def reply(query, ttl=60, last=42):
    identifier, end, kind, _ = parse_question(query)
    address = bytes((127, 0, 0, last)) if kind == 1 else bytes(15) + b'\1'
    return (struct.pack('!6H', identifier, 0x8180, 1, 1, 0, 0) + query[12:end]
            + b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, ttl, len(address)) + address)


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            return None
        data.extend(part)
    return bytes(data)


class Peer:
    def __init__(self, mode):
        self.mode = mode
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.queries, self.tcp_queries, self.errors = 0, 0, []
        self.clients = []
        self.tcp, self.udp, self.guard = tcp_udp_pair(socket.AF_INET)
        self.port = self.tcp.getsockname()[1]
        self.tcp.listen(16)
        self.refused = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.refused.bind(('127.0.0.1', 0))  # Reserved without listen: deterministic connect refusal.
        self.bad_port = self.refused.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)

    def response(self, query):
        _, _, kind, _ = parse_question(query)
        with self.lock:
            self.queries += 1
            sequence = self.queries
        if self.mode == 'stale_stop' and sequence > 1:
            return None
        if self.mode in ('last_cancel', 'deadline', 'network', 'stop') or self.mode == 'lookup_grace' and kind == 28:
            return None
        if self.mode in ('coalesce', 'cancel_peer', 'waiter_cap', 'inflight_cap'):
            self.stop.wait(0.06)
        return reply(query, 1 if self.mode in ('stale', 'stale_stop') and sequence == 1 else 60,
                     43 if self.mode == 'stale' and sequence > 1 else 42)

    def udp_reply(self, query, address):
        try:
            result = self.response(query)
            if result is not None:
                self.udp.sendto(result, address)
        except OSError:
            pass
        except Exception as error:
            self.errors.append(repr(error))

    def tcp_reply(self, connection):
        try:
            with connection:
                connection.settimeout(2)
                prefix = exact(connection, 2)
                if prefix is None:
                    return
                query = exact(connection, struct.unpack('!H', prefix)[0])
                if query is None:
                    return
                with self.lock:
                    self.tcp_queries += 1
                result = self.response(query)
                if result is not None:
                    data = struct.pack('!H', len(result)) + result
                    connection.sendall(data[:1])
                    connection.sendall(data[1:])
        except OSError:
            pass
        except Exception as error:
            self.errors.append(repr(error))

    def run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.udp, self.tcp], [], [], 0.01)
                if self.udp in ready:
                    query, address = self.udp.recvfrom(65536)
                    client = threading.Thread(target=self.udp_reply, args=(query, address), daemon=True)
                    self.clients.append(client)
                    client.start()
                if self.tcp in ready:
                    connection, _ = self.tcp.accept()
                    client = threading.Thread(target=self.tcp_reply, args=(connection,), daemon=True)
                    self.clients.append(client)
                    client.start()
        except Exception as error:
            self.errors.append(repr(error))

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *unused):
        self.stop.set()
        self.thread.join(3)
        for client in self.clients:
            client.join(3)
        self.tcp.close(); self.udp.close(); self.guard.close(); self.refused.close()
        assert not self.thread.is_alive() and not any(t.is_alive() for t in self.clients)


def run(binary, mode):
    with Peer(mode) as peer:
        process = subprocess.run([str(binary), mode, str(peer.port), str(peer.bad_port)],
                                 text=True, capture_output=True, timeout=12)
        assert process.returncode == 0, (mode, process.returncode, process.stdout, process.stderr)
        result = json.loads(process.stdout)
        if mode in ('last_cancel', 'system_cancel', 'system_queued_cancel', 'stop', 'queued_close'):
            assert result['status'] == -9 and result['errors'] == 1, (mode, result)
        elif mode in ('network', 'queued_network'):
            assert result['status'] == -15 and result['errors'] == 1, (mode, result)
        elif mode in ('deadline', 'system_queued_timeout'):
            assert result['status'] == -6 and result['errors'] == 1, (mode, result)
        elif mode == 'deny':
            assert result['status'] == -13 and result['errors'] == 1, (mode, result)
        elif mode == 'namespace':
            assert result['status'] == -1 and result['callbacks'] == 0, (mode, result)
        elif mode in ('cancel_peer', 'waiter_cap', 'inflight_cap'):
            assert result['successes'] == result['errors'] == 1, (mode, result)
        elif 'fail_' in mode:
            assert result['status'] in (0, -2), (mode, result)
        else:
            assert result['errors'] == 0 and result['successes'] > 0, (mode, result)
        if mode in ('hosts', 'lookup_hosts', 'deny', 'namespace') or mode.startswith(('system', 'create_fail_')):
            assert peer.queries == 0, (mode, result, peer.queries)
        elif mode in ('coalesce', 'cancel_peer', 'waiter_cap', 'inflight_cap'):
            assert peer.queries == 1, (mode, result, peer.queries)
        elif mode in ('role', 'lookup', 'lookup_grace', 'stale', 'stale_stop'):
            assert peer.queries == 2, (mode, result, peer.queries)
        elif mode in ('normal', 'tcp', 'hosts_off', 'alias', 'callback_block', 'failover', 'queued_network', 'queued_close'):
            assert peer.queries == 1, (mode, result, peer.queries)
        if mode == 'tcp':
            assert peer.tcp_queries == 1
        if mode == 'failover':
            assert result['policy'] == 2 and peer.tcp_queries == 0
    assert not peer.errors, (mode, peer.errors)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--modes', nargs='*')
    args = parser.parse_args()
    modes = args.modes or ['normal', 'tcp', 'coalesce', 'cancel_peer', 'last_cancel', 'deadline',
        'network', 'stop', 'hosts', 'hosts_off', 'lookup_hosts', 'lookup', 'lookup_grace',
        'alias', 'system', 'system_cancel', 'system_queued_cancel', 'system_queued_timeout',
        'callback_block', 'queued_network', 'queued_close', 'role', 'waiter_cap',
        'inflight_cap', 'deny', 'failover', 'stale', 'stale_stop', 'namespace', 'create_fail_1', 'create_fail_2',
        *['fail_' + str(i) for i in range(1, 33)], *['lookup_fail_' + str(i) for i in range(1, 33)],
        *['system_fail_' + str(i) for i in range(1, 17)]]
    for mode in modes:
        run(args.binary.resolve(), mode)
    print(f'DNS service: {len(modes)} independent peer/lifecycle cases passed')


if __name__ == '__main__':
    main()
