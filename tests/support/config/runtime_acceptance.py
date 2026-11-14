#!/usr/bin/env python3
"""Uninstrumented public SDK acceptance: real WS/WSS, UDP routing and listener removal."""
import argparse
import base64
import hashlib
import os
import queue
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from runtime_proxy import (Runtime, Peer, echo, config, by_name, connect, http_tunnel,
                           udp_control, udp_exchange, assert_echo, no_admission, socks_greet, socks_request,
                           address, read_address, until, exact, all_bytes)
from runtime_control import live, wait_for, for_socket, u64, closed
from websocket import frame, read_frame


def apply(runtime, conf, ephemeral=False, expected=0):
    prepared = runtime.prepare(0, conf, ephemeral=ephemeral, expected=expected)
    if prepared['status']:
        return prepared, None
    revision = runtime.commit(0)['revision']
    runtime.command('R', b'\0')
    return prepared, revision


def data_record(runtime, client):
    port = client.getsockname()[1]
    return wait_for(lambda: next((record for record in live(runtime)
                                 if record['kind'] == 2 and record['source']['port'] == port), None))


def end_control(runtime, control):
    record = for_socket(runtime, control)
    runtime.command('D', u64(record['generation'], record['id']))
    closed(control)


class SocksUdpPeer(Peer):
    """A small independent RFC 1928 relay; records each actually forwarded payload."""
    def __init__(self):
        self.forwarded = queue.Queue()
        self.controls = queue.Queue()
        super().__init__(self.control)

    def control(self, conn):
        conn.settimeout(20)
        version, count = exact(conn, 2)
        assert version == 5 and 0 in exact(conn, count)
        conn.sendall(b'\x05\x00')
        assert exact(conn, 3) == b'\x05\x03\x00'
        read_address(conn)
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        uplink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(('127.0.0.1', 0)); uplink.bind(('127.0.0.1', 0))
        relay.settimeout(.1); uplink.settimeout(2)
        done = threading.Event()
        thread = threading.Thread(target=self.forward, args=(relay, uplink, done), daemon=True)
        thread.start()
        self.controls.put(relay.getsockname()[1])
        conn.sendall(b'\x05\x00\x00' + address('127.0.0.1', relay.getsockname()[1]))
        try:
            assert not all_bytes(conn)
        finally:
            done.set(); relay.close(); uplink.close(); thread.join(3)
            assert not thread.is_alive()

    def forward(self, relay, uplink, done):
        try:
            while not done.is_set():
                try:
                    data, client = relay.recvfrom(65536)
                except socket.timeout:
                    continue
                if data[:4] != b'\0\0\0\x01' or len(data) < 10:
                    raise AssertionError(('unexpected SOCKS UDP wire', data[:20]))
                target = socket.inet_ntop(socket.AF_INET, data[4:8]), struct.unpack('!H', data[8:10])[0]
                payload = data[10:]
                self.forwarded.put((target, payload))
                uplink.sendto(payload, target)
                reply, peer = uplink.recvfrom(65536)
                relay.sendto(b'\0\0\0' + address(peer[0], peer[1]) + reply, client)
        except OSError as error:
            if not done.is_set():
                self.errors.put(error)
        except Exception as error:
            self.errors.put(error)


def routing_and_udp(runtime, ports, first, second, without_socks):
    web, socks = ports
    base = config(web, socks)
    filtering = base.replace('[Rule]\nFINAL,DIRECT',
        '[Proxy]\ntcp-only=direct,udp-relay=false\n'
        '[Rule]\nNETWORK,udp,tcp-only\nFINAL,DIRECT')
    _, revision = apply(runtime, filtering)
    direct = next(node['id'] for node in runtime.command('G')['nodes'] if node['name'] == 'DIRECT')
    control, bound = udp_control(socks)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('127.0.0.1', 0))
        udp_exchange(client, bound, first, b'capability-fallback')
        record = data_record(runtime, client)
        assert record['node'] == direct and record['rule'] == 1 and record['revision'] == revision
    end_control(runtime, control)
    _, revision = apply(runtime, base.replace('[Rule]\nFINAL,DIRECT', '[Rule]\nDOMAIN,unmatched.invalid,REJECT\nFINAL,DIRECT'))
    tcp = Peer(echo)
    with http_tunnel(web, tcp) as stream:
        assert_echo(stream, b'explicit-final-direct')
        record = for_socket(runtime, stream)
        assert record['rule'] == 1 and record['node'] == direct
    control, bound = udp_control(socks)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('127.0.0.1', 0)); udp_exchange(client, bound, first, b'udp-no-match')
        assert data_record(runtime, client)['rule'] == 1
    end_control(runtime, control); tcp.check()

    peer = SocksUdpPeer()
    routed = base.replace('[Rule]\nFINAL,DIRECT',
        f'[Proxy]\nforwarded=socks5,127.0.0.1,{peer.port},udp-relay=true\n'
        f'[Rule]\nDST-PORT,{second.port},forwarded\nFINAL,DIRECT')
    if without_socks:
        apply(runtime, routed, expected=-3)
        print('SOCKS5 outbound is intentionally disabled: reverse UDP peer case not applicable', flush=True)
    else:
        _, revision = apply(runtime, routed)
        node = next(n['id'] for n in runtime.command('G')['nodes'] if n['name'] == 'forwarded')
        control, bound = udp_control(socks)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(('127.0.0.1', 0))
            for target, data in [(first, b'direct-A'), (second, b'direct-B'), (first, b'direct-A-again')]:
                udp_exchange(client, bound, target, data)
            record = data_record(runtime, client)
            assert record['node'] == direct and record['revision'] == revision and peer.forwarded.empty()
        end_control(runtime, control)
        control, bound = udp_control(socks)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(('127.0.0.1', 0))
            for target, data in [(second, b'proxy-B'), (first, b'proxy-A'), (second, b'proxy-B-again')]:
                udp_exchange(client, bound, target, data)
                assert peer.forwarded.get(timeout=2) == ((target.host, target.port), data)
            record = data_record(runtime, client)
            assert record['node'] == node and record['rule'] == 0 and record['revision'] == revision
        end_control(runtime, control)
        peer.check()
    if without_socks:
        apply(runtime, base)
    # Malformed first fragments must neither claim the client port nor create
    # an association. A valid packet from a different source then succeeds.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong:
        client.bind(('127.0.0.1', 0)); wrong.bind(('127.0.0.1', 0)); wrong.settimeout(.15)
        control = socks_greet(socks)
        bound = socks_request(control, '127.0.0.1', client.getsockname()[1], udp=True)
        before = runtime.command('F')['logical'][0]['created']
        wrong.sendto(b'\0\0\0' + address(second.host, second.port) + b'wrong-first-source', bound)
        try:
            wrong.recv(1024); raise AssertionError('unadvertised first UDP source accepted')
        except socket.timeout:
            pass
        assert runtime.command('F')['logical'][0]['created'] == before
        client.sendto(b'\0\0\1' + address(second.host, second.port) + b'fragment', bound)
        client.settimeout(.15)
        try:
            client.recv(1024); raise AssertionError('fragment accepted')
        except socket.timeout:
            pass
        assert runtime.command('F')['logical'][0]['created'] == before
        udp_exchange(client, bound, first, b'valid-first-source')
        wrong.sendto(b'\0\0\0' + address(first.host, first.port) + b'wrong-source-port', bound)
        try:
            wrong.recv(1024); raise AssertionError('source port takeover')
        except socket.timeout:
            pass
        udp_exchange(client, bound, second, b'source-stays-pinned')
        assert runtime.command('F')['logical'][0]['created'] == before + 1
        if not without_socks:
            assert peer.forwarded.empty()
    end_control(runtime, control)
    print('SDK R02/U01: UDP capability filtering, explicit FINAL, reverse first-target routing and invalid fragment/source passed', flush=True)
    # Each old control has completed UDP ASSOCIATE but has no data association.
    # Removal/disable must deny its first valid packet, independently of auth.
    for removal in (False, True):
        apply(runtime, base)
        cold, cold_bound = udp_control(socks)
        identity = for_socket(runtime, cold)
        replacement = config(web) if removal else config(web, socks, udp=False)
        apply(runtime, replacement)
        before = runtime.command('F')['logical'][0]['created']
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(('127.0.0.1', 0))
            udp_exchange(client, cold_bound, first, b'old-control-admission-must-fail', success=False)
        closed(cold)
        wait_for(lambda: runtime.command('I', u64(identity['generation'], identity['id']))['connection']['state'] == 3)
        assert runtime.command('F')['logical'][0]['created'] == before
        if removal:
            def listener_released():
                try:
                    with socket.create_connection(('127.0.0.1', socks), timeout=3):
                        return False
                except ConnectionRefusedError:
                    return True
                except (ConnectionResetError, socket.timeout):
                    return False
            wait_for(listener_released)
    apply(runtime, base)
    print('SDK U02: existing cold controls cannot create associations after UDP disable or logical listener removal', flush=True)


def ws_handler(conn):
    conn.settimeout(20)
    request = until(conn)
    fields = {k.lower(): v.strip() for k, v in (line.split(b':', 1) for line in request.split(b'\r\n')[1:-2])}
    assert fields[b'upgrade'].lower() == b'websocket'
    accept = base64.b64encode(hashlib.sha1(fields[b'sec-websocket-key'] + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
    conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
    while True:
        try:
            fin, opcode, compressed, payload = read_frame(conn, True)
        except EOFError:
            return
        assert fin and not compressed
        if opcode == 8:
            conn.sendall(frame(8, payload)); return
        if opcode == 9:
            conn.sendall(frame(10, payload))
        else:
            assert opcode in (1, 2)
            conn.sendall(frame(opcode, payload))


def ws_connect(proxy, peer, tls=None):
    conn = http_tunnel(proxy, peer) if tls else connect(proxy)
    if tls:
        conn = tls.wrap_socket(conn, server_hostname='localhost')
    uri = '/acceptance' if tls else f'http://127.0.0.1:{peer.port}/acceptance'
    conn.sendall((f'GET {uri} HTTP/1.1\r\nHost: 127.0.0.1:{peer.port}\r\n'
                  'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n').encode())
    header = until(conn)
    assert header.startswith(b'HTTP/1.1 101 ') and b's3pPLMBiTxaQ9kYGzzhZRbK+xOo=' in header
    return conn


def ws_round(conn, data):
    conn.sendall(frame(2, data, masked=True) + frame(9, b'heartbeat', masked=True))
    assert read_frame(conn, False) == (True, 2, False, data)
    assert read_frame(conn, False) == (True, 10, False, b'heartbeat')


def ws_close(conn):
    data = struct.pack('!H', 1000)
    conn.sendall(frame(8, data, masked=True)); assert read_frame(conn, False) == (True, 8, False, data)
    assert not all_bytes(conn); conn.close()


def websocket_reload(runtime, ports):
    web, socks = ports
    with tempfile.TemporaryDirectory(prefix='solaris-sdk-wss-') as directory:
        cert, key = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
        openssl = shutil.which('openssl')
        assert openssl, 'openssl is required for the independent WSS certificate fixture'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.load_cert_chain(cert, key)
        client = ssl.create_default_context(cafile=cert)
        def secured(conn):
            with server.wrap_socket(conn, server_side=True) as tls:
                ws_handler(tls)
        plain, secure = Peer(ws_handler), Peer(secured)
        _, old_revision = apply(runtime, config(web, socks))
        ws, wss = ws_connect(web, plain), ws_connect(web, secure, client)
        old_keys = [for_socket(runtime, conn) for conn in (ws, wss)]
        for conn in (ws, wss): ws_round(conn, b'before-reload')
        _, revision = apply(runtime, config(web, socks, route='REJECT'))
        assert revision != old_revision
        for conn in (ws, wss): ws_round(conn, os.urandom(65539))
        for key in old_keys:
            record = runtime.command('I', u64(key['generation'], key['id']))['connection']
            assert record['revision'] == old_revision and record['state'] == 1
        with connect(web) as denied:
            denied.sendall(f'CONNECT 127.0.0.1:{secure.port} HTTP/1.1\r\nHost: 127.0.0.1:{secure.port}\r\n\r\n'.encode())
            assert all_bytes(denied).startswith(b'HTTP/1.1 502 ')
        ws_close(ws); ws_close(wss); plain.check(); secure.check()
    print('SDK L02: verified WSS and framed WS retain their old plan across reload; new flows use REJECT', flush=True)


def disabled_listeners(runtime, tcp):
    conf = '[General]\nconfig-version=1\nmode=direct\nhttp-listen=127.0.0.1:18080\nsocks-listen=127.0.0.1:18081\nmixed-listen=127.0.0.1:18082\n[Rule]\nFINAL,DIRECT\n'
    prepared, revision = apply(runtime, conf, ephemeral=True)
    ports = by_name(prepared)
    assert set(ports) == {'http', 'socks', 'mixed'} and all(item['port'] for item in ports.values())
    streams = [http_tunnel(ports[name]['port'], tcp) for name in ('http', 'mixed')]
    from runtime_proxy import socks_tcp
    streams.append(socks_tcp(ports['socks']['port'], tcp))
    prepared, removed = apply(runtime, '[General]\nconfig-version=1\nmode=direct\nhttp-listen=off\nsocks-listen=off\nmixed-listen=off\n[Rule]\nFINAL,DIRECT\n')
    assert removed > revision and not prepared['listeners'] and not runtime.command('Q')['listeners']
    for info in ports.values(): no_admission(info['port'])
    for stream in streams:
        assert_echo(stream, b'disabled-listener-removes-only-new-admission'); stream.close()
    print('SDK L01: HTTP/SOCKS/mixed -> off removes listeners without ephemeral substitutes or killing old streams', flush=True)


def test(binary, without_socks=False):
    runtime = Runtime(binary)
    tcp, first, second = Peer(echo), Peer(None, udp=True), Peer(None, udp=True)
    prepared, _ = apply(runtime, config(18080, 18081), ephemeral=True)
    listeners = by_name(prepared); ports = listeners['web']['port'], listeners['socks']['port']
    routing_and_udp(runtime, ports, first, second, without_socks)
    websocket_reload(runtime, ports)
    disabled_listeners(runtime, tcp)
    runtime.finish(); tcp.check(); first.check(); second.check()
    print('Uninstrumented public SDK route/listener acceptance passed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('binary'); parser.add_argument('--without-socks', action='store_true')
    args = parser.parse_args(); test(args.binary, args.without_socks)
