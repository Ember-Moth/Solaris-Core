#!/usr/bin/env python3
"""Independent loopback DNS peers for the C numeric UDP/TCP exchange contract."""
import argparse
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading


def question_end(query):
    assert len(query) >= 12
    identifier, flags, qd, an, ns, ar = struct.unpack('!6H', query[:12])
    assert identifier == 0x2345 and flags == 0x100 and (qd, an, ns, ar) == (1, 0, 0, 0)
    offset, labels = 12, []
    while query[offset]:
        length = query[offset]
        assert 0 < length <= 63
        labels.append(query[offset + 1:offset + 1 + length])
        offset += length + 1
    offset += 1
    assert labels == [b'wire', b'exchange', b'test']
    assert query[offset:offset + 4] == b'\0\1\0\1' and offset + 4 == len(query)
    return offset + 4


def answer(query, truncated=False):
    end = question_end(query)
    head = struct.pack('!6H', 0x2345, 0x8380 if truncated else 0x8180, 1, 0 if truncated else 1, 0, 0)
    record = b'' if truncated else b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([127, 0, 0, 42])
    return head + query[12:end] + record


def frame(payload):
    return struct.pack('!H', len(payload)) + payload


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            return None
        result.extend(part)
    return bytes(result)


class Peer:
    def __init__(self, family, mode):
        self.family, self.mode = family, mode
        self.host = '127.0.0.1' if family == socket.AF_INET else '::1'
        self.stop = threading.Event()
        self.fence_requested, self.fence_done = threading.Event(), threading.Event()
        self.errors, self.clients = [], []
        self.udp_queries = self.tcp_queries = self.tcp_connections = 0
        self.tcp = socket.socket(family, socket.SOCK_STREAM)
        self.tcp.bind((self.host, 0))
        self.port = self.tcp.getsockname()[1]
        self.tcp.listen(8)
        self.udp = socket.socket(family, socket.SOCK_DGRAM)
        self.udp.bind((self.host, self.port))
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            while not self.stop.is_set():
                fence = self.fence_requested.is_set()
                ready, _, _ = select.select([self.udp, self.tcp], [], [], 0.01)
                if self.udp in ready:
                    query, address = self.udp.recvfrom(65536)
                    question_end(query)
                    self.udp_queries += 1
                    if self.mode in ('timeout', 'cancel', 'stop'):
                        continue
                    if self.mode == 'fallback_timeout':
                        self.stop.wait(0.18)
                    if self.mode == 'wrong':
                        with socket.socket(self.family, socket.SOCK_DGRAM) as alternate:
                            alternate.bind((self.host, 0))
                            alternate.sendto(answer(query), address)
                        self.stop.wait(0.015)
                        wrong = bytearray(answer(query)); wrong[0] ^= 1
                        self.udp.sendto(wrong, address)
                        self.stop.wait(0.01)
                        wrong = bytearray(answer(query)); wrong[13] = ord('x')
                        self.udp.sendto(wrong, address)
                        self.stop.wait(0.01)
                        wrong = bytearray(answer(query)); wrong[5] = 2
                        self.udp.sendto(wrong, address)
                        self.stop.wait(0.01)
                    self.udp.sendto(answer(query, self.mode in ('fallback', 'fallback_timeout') or self.mode.startswith('fallback_fail_')), address)
                if self.tcp in ready:
                    connection, _ = self.tcp.accept()
                    self.tcp_connections += 1
                    thread = threading.Thread(target=self.handle_tcp, args=(connection,), daemon=True)
                    self.clients.append(thread)
                    thread.start()
                if fence:
                    self.fence_done.set()
        except Exception as error:
            self.errors.append(repr(error))

    def handle_tcp(self, connection):
        try:
            with connection:
                connection.settimeout(2)
                prefix = receive_exact(connection, 2)
                if prefix is None:
                    return
                length, = struct.unpack('!H', prefix)
                query = receive_exact(connection, length)
                if query is None:
                    return
                question_end(query)
                self.tcp_queries += 1
                if self.mode in ('timeout', 'cancel', 'stop'):
                    self.stop.wait(1)
                    return
                if self.mode == 'fallback_timeout':
                    self.stop.wait(0.12)
                if self.mode == 'malformed':
                    connection.sendall(b'\0\x08')
                    return
                if self.mode == 'oversize':
                    connection.sendall(struct.pack('!H', 513))
                    return
                if self.mode == 'wrongframes':
                    wrong_id = bytearray(answer(query)); wrong_id[0] ^= 1
                    wrong_question = bytearray(answer(query)); wrong_question[13] = ord('x')
                    malformed = bytearray(answer(query)); malformed[5] = 2
                    connection.sendall(frame(wrong_id) + frame(wrong_question) + frame(malformed) + frame(answer(query)))
                    return
                payload = frame(answer(query, self.mode == 'truncated'))
                if self.mode in ('split', 'fallback'):
                    for part in (payload[:1], payload[1:2], *[payload[i:i + 3] for i in range(2, len(payload), 3)]):
                        connection.sendall(part)
                        self.stop.wait(0.001)
                else:
                    connection.sendall(payload)
        except OSError:
            pass  # cancellation/allocation failure may close at any frame byte
        except Exception as error:
            self.errors.append(repr(error))

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *unused):
        self.stop.set()
        self.thread.join(3)
        for thread in self.clients:
            thread.join(3)
        self.tcp.close(); self.udp.close()
        assert not self.thread.is_alive() and not any(t.is_alive() for t in self.clients)


def run(binary, family, transport, mode, expected, timeout=1000):
    with Peer(family, mode) as peer:
        completed = subprocess.run([str(binary), peer.host, str(peer.port), transport, mode, str(timeout)],
                                   text=True, capture_output=True, timeout=8)
        assert completed.returncode == 0, (transport, mode, completed.returncode, completed.stdout, completed.stderr)
        result = json.loads(completed.stdout)
        assert result['closed'] == 1 and result['callbacks'] == result['accepted'], (mode, result)
        if 'fail_' in mode:
            assert result['status'] == (-2 if result['allocation_failures'] else 0), (mode, result)
        else:
            assert result['status'] == expected, (family, transport, mode, result)
            expected_acceptance = 0 if mode in ('invalid_domain', 'port_zero', 'expired', 'query_limit', 'tls_disabled') else 1
            assert result['accepted'] == expected_acceptance and result['callbacks'] == expected_acceptance, result
        if mode in ('deny', 'deny_deadline', 'network_changed', 'network_deadline', 'cancel_before', 'cancel_protect',
                    'deadline_protect', 'invalid_domain', 'port_zero', 'expired', 'query_limit', 'tls_disabled'):
            # The independent peer proves no packet/connect escaped protection.
            peer.fence_requested.set()
            assert peer.fence_done.wait(2), (mode, peer.errors)
            assert peer.udp_queries == 0 and peer.tcp_connections == 0, (mode, result, peer.udp_queries, peer.tcp_connections)
            assert result['bytes_written'] == 0, result
        if mode == 'wrong':
            assert result['discarded_packets'] >= 4, result
        if mode == 'wrongframes':
            assert result['discarded_frames'] == 3, result
        if mode == 'fallback':
            assert result['fallback'] == 1 and result['udp'] == 1 and result['tcp'] == 1, result
            assert peer.udp_queries == 1 and peer.tcp_queries == 1
        if mode == 'fallback_timeout':
            assert result['fallback'] == 1 and result['duration_ns'] >= timeout * 1_000_000, result
    assert not peer.errors, (mode, peer.errors)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    count = 0
    capabilities = json.loads(subprocess.check_output([str(binary), '--capabilities'], text=True))
    if not capabilities['tls']:
        run(binary, socket.AF_INET, 'tls', 'tls_disabled', -3)
        count += 1
    for family in (socket.AF_INET, socket.AF_INET6):
        for transport, mode, expected, timeout in [
            ('udp', 'normal', 0, 1000), ('udp', 'bootstrap', 0, 1000), ('udp', 'wrong', 0, 1000),
            ('udp', 'fallback', 0, 1000), ('udp', 'fallback_timeout', -6, 250),
            ('tcp', 'split', 0, 1000), ('tcp', 'wrongframes', 0, 1000),
            ('tcp', 'malformed', -1, 1000), ('tcp', 'oversize', -14, 1000), ('tcp', 'truncated', -8, 1000),
        ]:
            run(binary, family, transport, mode, expected, timeout); count += 1
        for transport in ('udp', 'tcp'):
            for mode, expected in [('deny', -13), ('deny_deadline', -13), ('network_changed', -15), ('network_deadline', -15),
                                   ('cancel_before', -9), ('cancel_protect', -9),
                                   ('deadline_protect', -6), ('cancel', -9), ('stop', -9), ('timeout', -6),
                                   ('invalid_domain', -1), ('port_zero', -1), ('expired', -6), ('query_limit', -14)]:
                run(binary, family, transport, mode, expected, 120 if mode == 'timeout' else 1000); count += 1
    failures = 0
    for transport in ('udp', 'tcp'):
        for allocation in range(1, 25):
            result = run(binary, socket.AF_INET, transport, f'fail_{allocation}', None)
            failures += result['allocation_failures']
            count += 1
    for allocation in range(1, 33):
        result = run(binary, socket.AF_INET, 'udp', f'fallback_fail_{allocation}', None)
        failures += result['allocation_failures']
        count += 1
    assert failures >= 16, failures
    print(f'{count} independent DNS exchange cases passed: IPv4/IPv6 UDP/TCP, source/ID/question filtering, TC fallback, framing, deadline/cancel/stop, protect rejection and {failures} injected allocation failures')


if __name__ == '__main__':
    main()
