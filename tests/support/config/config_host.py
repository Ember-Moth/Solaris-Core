#!/usr/bin/env python3
"""Exercise the reusable console host through only its installed public SDK."""
import argparse
import json
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time


def exact(conn, count):
    result = bytearray()
    while len(result) < count:
        data = conn.recv(count - len(result))
        assert data, (count, result)
        result.extend(data)
    return bytes(result)


def head(conn):
    result = bytearray()
    while not result.endswith(b'\r\n\r\n'):
        result.extend(exact(conn, 1))
        assert len(result) < 16384
    return bytes(result)


class Peer:
    def __init__(self, http=False):
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0)); self.socket.listen(16)
        self.port = self.socket.getsockname()[1]
        self.http = http; self.errors = queue.Queue()
        threading.Thread(target=self.listen, daemon=True).start()

    def listen(self):
        while True:
            try:
                conn, _ = self.socket.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        try:
            with conn:
                conn.settimeout(5)
                if self.http:
                    assert head(conn).startswith(b'HEAD /health?token=DO-NOT-LOG HTTP/1.1\r\n')
                    conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n')
                else:
                    while data := conn.recv(65536):
                        conn.sendall(data)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            self.errors.put(error)

    def check(self):
        if not self.errors.empty():
            raise self.errors.get()


class Host:
    def __init__(self, binary, configuration):
        self.child = subprocess.Popen([binary, str(configuration), '--ephemeral'], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.events = queue.Queue()
        def reader():
            for line in self.child.stdout:
                self.events.put(json.loads(line))
            self.events.put(None)
        threading.Thread(target=reader, daemon=True).start()
        self.ready = self.take()
        assert self.ready['command'] == 'ready' and self.ready['status'] == 0, self.ready

    def take(self):
        value = self.events.get(timeout=35)
        assert value is not None, (self.child.poll(), self.child.stderr.read().decode())
        return value

    def command(self, text, expected=0):
        self.child.stdin.write((text + '\n').encode()); self.child.stdin.flush()
        result = self.take()
        if expected is not None:
            assert result['status'] == expected, (text, result)
        return result

    def finish(self):
        self.child.stdin.close()
        assert self.take() == {'command': 'quit', 'status': 0}
        assert self.child.wait(10) == 0

    def abort(self):
        if self.child.poll() is None:
            self.child.kill(); self.child.wait(5)


def tunnel(port, peer, allowed=True):
    conn = socket.create_connection(('127.0.0.1', port), timeout=3)
    authority = f'127.0.0.1:{peer.port}'
    conn.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
    response = head(conn)
    assert response.startswith(b'HTTP/1.1 200 ') == allowed, response
    return conn


def echo(conn, payload):
    conn.sendall(payload); assert exact(conn, len(payload)) == payload


def closed(conn):
    conn.settimeout(3)
    try:
        assert not conn.recv(1)
    except ConnectionResetError:
        pass
    conn.close()


def test(args):
    checked = subprocess.run([args.client, str(args.configuration), '--check'], capture_output=True, text=True, timeout=10)
    assert checked.returncode == 0 and json.loads(checked.stdout)['status'] == 0, checked
    host = Host(args.client, args.configuration)
    echo_peer, health = Peer(), Peer(http=True)
    live_sockets = []
    try:
        initial = host.ready
        ports = {entry['name']: entry['port'] for entry in initial['listeners']}
        assert ports['web'] and ports['socks'] and len(set(ports.values())) == 2
        assert all(entry['requested_port'] == 0 and entry['configured_port'] and entry['overridden'] for entry in initial['listeners'])
        state = host.command('nodes')
        assert {entry['name'] for entry in state['nodes']} >= {'DIRECT', 'REJECT'}
        assert any(group['name'] == 'Route' for group in state['groups'])
        original = tunnel(ports['web'], echo_peer); live_sockets.append(original)
        echo(original, b'configuration-host')
        host.command('select Route REJECT')
        with tunnel(ports['web'], echo_peer, allowed=False):
            pass
        echo(original, b'old-plan-after-select')
        host.command('mode direct')
        with tunnel(ports['web'], echo_peer) as fresh:
            echo(fresh, b'direct-mode')
        host.command('mode rule'); host.command('select Route DIRECT')
        result = host.command(f'probe DIRECT http://127.0.0.1:{health.port}/health?token=DO-NOT-LOG 3000')
        assert result['http_status'] == 204 and result['revision'] == initial['revision'] and result['duration_ns']
        totals = host.command('traffic')
        assert totals['user_read'] and totals['probe_read'] and totals['physical_read']
        with tempfile.TemporaryDirectory(prefix='solaris-host-bad-') as temporary:
            invalid = Path(temporary) / 'invalid config.conf'
            invalid.write_text('[General]\nconfig-version=1\n[Rule]\nFINAL,MISSING\n')
            assert host.command('load ' + json.dumps(str(invalid)), expected=None)['status'] != 0
        assert host.command('status')['revision'] == initial['revision']
        echo(original, b'old-plan-after-invalid-load')
        updated = host.command('load ' + json.dumps(str(args.reload)))
        assert updated['revision'] > initial['revision']
        assert {entry['name']: entry['port'] for entry in updated['listeners']} == ports
        echo(original, b'old-plan-after-update')
        entries = host.command('connections')['connections']
        old = next(entry for entry in entries if entry['revision'] == initial['revision'] and entry['purpose'] == 0 and entry['state'] == 1)
        result = host.command(f'close {old["generation"]} {old["id"]}')
        assert result['matched'] == 1; closed(original); live_sockets.remove(original)
        fresh = tunnel(ports['web'], echo_peer); live_sockets.append(fresh); echo(fresh, b'close-all')
        assert host.command('close all')['matched'] >= 1; closed(fresh); live_sockets.remove(fresh)
        records = host.command('logs')
        assert records['records'] and 'DO-NOT-LOG' not in json.dumps(records)
        empty = host.command(f'logs {records["cursor"]}')
        assert not empty['records']
        host.command('stop'); assert host.command('status')['revision'] == 0
        restarted = host.command('start'); assert restarted['revision'] > updated['revision']
        port = next(entry['port'] for entry in restarted['listeners'] if entry['name'] == 'web')
        final = tunnel(port, echo_peer); live_sockets.append(final); echo(final, b'stdin-eof-drains')
        host.finish(); closed(final); live_sockets.remove(final)
        echo_peer.check(); health.check()
        print('Reusable installed C host: load, controls, probe, snapshots, rollback/update, close and EOF shutdown passed')
    finally:
        for conn in live_sockets:
            conn.close()
        host.abort()
        echo_peer.socket.close(); health.socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('client')
    parser.add_argument('configuration', type=Path)
    parser.add_argument('reload', type=Path)
    test(parser.parse_args())
