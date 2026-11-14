#!/usr/bin/env python3
"""SOCKS5 interoperability and independent loopback protocol peers."""
import argparse
import io
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time

PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


def exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("truncated SOCKS message")
        data.extend(chunk)
    return bytes(data)


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack("!H", port)
    except ValueError:
        data = host.encode(); return b"\3" + bytes([len(data)]) + data + struct.pack("!H", port)


def read_address(read):
    kind = read(1)[0]
    if kind == 1:
        host = str(ipaddress.ip_address(read(4)))
    elif kind == 4:
        host = str(ipaddress.ip_address(read(16)))
    elif kind == 3:
        host = read(read(1)[0]).decode()
    else:
        raise ValueError("invalid address type")
    return host, struct.unpack("!H", read(2))[0], kind


def associate(port, username="", password="", host="127.0.0.1"):
    control = socket.create_connection((host, port), timeout=2); control.settimeout(2)
    method = 2 if username else 0; control.sendall(bytes([5, 1, method]))
    if exact(control, 2) != bytes([5, method]):
        raise AssertionError("independent control method refused")
    if username:
        user, secret = username.encode(), password.encode(); control.sendall(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
        if exact(control, 2) != b"\1\0":
            raise AssertionError("independent control auth refused")
    control.sendall(b"\5\3\0" + address("0.0.0.0", 0))
    if exact(control, 3) != b"\5\0\0":
        raise AssertionError("independent control associate refused")
    relay, relay_port, kind = read_address(lambda n: exact(control, n))
    if kind != 3 and ipaddress.ip_address(relay).is_unspecified:
        relay = control.getpeername()[0]
    if kind == 3:
        relay = socket.getaddrinfo(relay, relay_port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    family = socket.AF_INET6 if ":" in relay else socket.AF_INET
    udp = socket.socket(family, socket.SOCK_DGRAM); udp.settimeout(1)
    return control, udp, (relay, relay_port)


def control_probe(port, targets, username="", password=""):
    control, udp, relay = associate(port, username, password)

    def exchange(host, target, payload):
        udp.sendto(b"\0\0\0" + address(host, target) + payload, relay)
        wire, _ = udp.recvfrom(65536)
        if wire[:3] != b"\0\0\0":
            raise AssertionError("bad control UDP response")
        reader = io.BytesIO(wire[3:]); source = read_address(reader.read)
        if reader.read() != payload:
            raise AssertionError("independent control payload changed")
        return source

    try:
        exchange("127.0.0.1", targets[0], b"control")
        try:
            exchange("127.0.0.1", targets[0], b""); empty = True
        except (socket.timeout, ConnectionResetError):
            empty = False
        try:
            source = exchange("localhost", targets[0], b"mixed-domain"); mixed_domain = True; numeric_mixed = source[2] != 3
        except (socket.timeout, ConnectionResetError):
            mixed_domain = False; numeric_mixed = False
        try:
            exchange("::1", targets[2], b"mixed-v6"); mixed_v6 = True
        except (socket.timeout, ConnectionResetError):
            mixed_v6 = False
    finally:
        udp.close(); control.close()
    control, udp, relay = associate(port, username, password)
    try:
        source = exchange("localhost", targets[0], b"domain-first"); numeric_first = source[2] != 3
    finally:
        udp.close(); control.close()
    result = dict(empty=empty, mixed=mixed_domain and mixed_v6, mixed_domain=mixed_domain, mixed_v6=mixed_v6,
                  numeric_first=numeric_first, numeric_mixed=numeric_mixed)
    print("Independent same-peer SOCKS5 control:", result)
    return result


class ControlledServer:
    def __init__(self, stop, failures, tcp_targets, mode="normal", host="127.0.0.1", relay_mode="numeric"):
        self.stop, self.failures, self.tcp_targets, self.mode, self.host, self.relay_mode = stop, failures, tcp_targets, mode, host, relay_mode
        self.socket = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
        if ":" in host:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.socket.bind((host, 0)); self.socket.listen(32); self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]; self.threads = []
        threading.Thread(target=self.listen, daemon=True).start()

    def listen(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.socket.accept(); thread = threading.Thread(target=self.connection, args=(conn,), daemon=True)
                self.threads.append(thread); thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def connection(self, conn):
        relay = None; upstreams = {}
        try:
            conn.settimeout(5)
            header = exact(conn, 2)
            if header[0] != 5:
                raise AssertionError("wrong greeting")
            methods = exact(conn, header[1]); method = 2 if methods == b"\2" else 0
            if methods not in [b"\0", b"\2"]:
                raise AssertionError("unexpected authentication offer")
            if self.mode == "stall":
                while conn.recv(1024):
                    pass
                return
            if self.mode in ["method-version", "downgrade"]:
                conn.sendall(b"\4\0" if self.mode == "method-version" else b"\5\0")
                if conn.recv(1024):
                    raise AssertionError("client continued after rejected method")
                return
            for byte in bytes([5, method]):
                conn.sendall(bytes([byte]))
            if method == 2:
                if exact(conn, 1) != b"\1":
                    raise AssertionError("wrong auth version")
                username = exact(conn, exact(conn, 1)[0]); password = exact(conn, exact(conn, 1)[0])
                if username != b"solaris" or password != b"password":
                    conn.sendall(b"\1\1"); return
                conn.sendall(b"\5\0" if self.mode == "auth-version" else b"\1\0")
                if self.mode == "auth-version":
                    return
            command = exact(conn, 3)
            if command[0] != 5 or command[2] != 0:
                raise AssertionError("wrong request header")
            host, port, kind = read_address(lambda n: exact(conn, n))
            if self.mode in ["reply-version", "reserved", "address", "partial", "refused"]:
                replies = {"reply-version": b"\4\0\0\1" + bytes(6), "reserved": b"\5\0\1\1" + bytes(6),
                           "address": b"\5\0\0\xff", "partial": b"\5\0\0\4\0", "refused": b"\5\2\0\1" + bytes(6)}
                conn.sendall(replies[self.mode]); return
            if command[1] == 1:
                if host not in ["127.0.0.1", "::1", "localhost"] or port not in self.tcp_targets:
                    raise AssertionError("unexpected TCP target")
                target = socket.create_connection((host, port), timeout=3)
                with target:
                    # A zero BND port is valid metadata for this CONNECT peer.
                    reply = b"\5\0\0" + address("0.0.0.0", 0)
                    for byte in reply:
                        conn.sendall(bytes([byte]))
                    def copy(source, destination):
                        try:
                            while data := source.recv(4093):
                                destination.sendall(data)
                            destination.shutdown(socket.SHUT_WR)
                        except (OSError, ConnectionError):
                            pass
                    upload = threading.Thread(target=copy, args=(conn, target), daemon=True); upload.start(); copy(target, conn); upload.join(timeout=5)
                return
            if command[1] != 3 or port != 0 or not ipaddress.ip_address(host).is_unspecified:
                raise AssertionError("invalid UDP associate source hint")
            relay_host = "::1" if self.relay_mode == "ipv6" or ":" in self.host else "127.0.0.1"
            relay = socket.socket(socket.AF_INET6 if ":" in relay_host else socket.AF_INET, socket.SOCK_DGRAM)
            relay.bind((relay_host, 0)); relay.settimeout(3)
            advertised = "localhost" if self.relay_mode == "domain" else "::" if ":" in relay_host and self.relay_mode == "wildcard" else "0.0.0.0" if self.relay_mode == "wildcard" else relay_host
            conn.sendall(b"\5\0\0" + address(advertised, relay.getsockname()[1]))
            if self.mode == "early-close":
                return
            first = True
            while not self.stop.is_set():
                readable, _, _ = select.select([conn, relay], [], [], 0.1)
                if conn in readable:
                    if not conn.recv(1024):
                        break
                    raise AssertionError("unexpected data on UDP control connection")
                if relay not in readable:
                    continue
                wire, client = relay.recvfrom(65536)
                if wire[:3] != bytes(3):
                    raise AssertionError("client emitted fragmented/reserved UDP")
                reader = io.BytesIO(wire[3:]); remote, remote_port, kind = read_address(reader.read); payload = reader.read()
                family = socket.AF_INET6 if kind == 4 else socket.AF_INET
                if family not in upstreams:
                    upstreams[family] = socket.socket(family, socket.SOCK_DGRAM); upstreams[family].settimeout(3)
                upstreams[family].sendto(payload, (remote, remote_port)); reply, source = upstreams[family].recvfrom(65536)
                packet = bytes(3) + address(source[0], source[1]) + reply
                if self.mode == "bad-packets" and first:
                    for malformed in [b"\1" + packet[1:], b"\0\0\1" + packet[3:], packet[:6], b"\0\0\0\xff"]:
                        relay.sendto(malformed, client)
                    with socket.socket(relay.family, socket.SOCK_DGRAM) as spoof:
                        spoof.bind((relay_host, 0)); spoof.sendto(packet, client)
                relay.sendto(packet, client); first = False
                if self.mode == "control-close":
                    time.sleep(0.02); return
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as exc:
            self.failures.append(repr(exc))
        finally:
            conn.close()
            if relay:
                relay.close()
            for upstream in upstreams.values():
                upstream.close()

    def close(self):
        self.socket.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--udp-client", required=True)
    parser.add_argument("--association-client", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.peer, "version"], text=True).splitlines()[0]
    if args.version.removeprefix("v") not in version:
        raise RuntimeError(version)
    print(version)
    stop = threading.Event(); sockets, threads, failures, echoes, controlled = [], [], [], [], []
    process = None; expected = 0

    def tcp_echo(conn):
        received = bytearray()
        try:
            with conn:
                conn.settimeout(5)
                while data := conn.recv(3011):
                    received.extend(data); conn.sendall(data)
                conn.shutdown(socket.SHUT_WR)
                if received:
                    if received != PAYLOAD:
                        failures.append(f"TCP payload changed: {len(received)}")
                    else:
                        echoes.append(True)
        except (ConnectionError, OSError):
            if received:
                failures.append(f"incomplete TCP echo: {len(received)}")

    def tcp_listen(sock):
        while not stop.is_set():
            try:
                conn, _ = sock.accept(); thread = threading.Thread(target=tcp_echo, args=(conn,), daemon=True); threads.append(thread); thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def udp_echo(sock, alternate=None):
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(65536); (alternate or sock).sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    with tempfile.TemporaryDirectory(prefix="solaris-socks5-") as directory:
        root = Path(directory)
        try:
            tcp_targets = []
            for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                sock = socket.socket(family)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, 0)); sock.listen(32); sock.settimeout(0.1); sockets.append(sock); tcp_targets.append(sock.getsockname()[1])
                threading.Thread(target=tcp_listen, args=(sock,), daemon=True).start()
            udp_sockets = []
            for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")]:
                sock = socket.socket(family, socket.SOCK_DGRAM)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, 0)); sock.settimeout(0.1); sockets.append(sock); udp_sockets.append(sock)
                threading.Thread(target=udp_echo, args=(sock, udp_sockets[1] if len(udp_sockets) == 4 else None), daemon=True).start()
            udp_targets = [s.getsockname()[1] for s in udp_sockets[:3]]
            reservations = [socket.socket(), socket.socket()]
            for sock in reservations:
                sock.bind(("127.0.0.1", 0)); sockets.append(sock)
            ports = [s.getsockname()[1] for s in reservations]
            inbounds = [{"type": "socks", "listen": "127.0.0.1", "listen_port": port} for port in ports]
            inbounds[1]["users"] = [{"username": "solaris", "password": "password"}]
            path = root / "config.json"; path.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}))
            for sock in reservations:
                sock.close()
            with (root / "peer.log").open("w+") as log:
                process = subprocess.Popen([args.peer, "run", "-c", str(path)], stdout=log, stderr=log)
                until = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        log.seek(0); raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= until:
                            raise RuntimeError("peer startup timeout")
                        time.sleep(0.01)

                def run_tcp(port, host="127.0.0.1", username="", password="", mode=0, proxy_host="127.0.0.1", timeout=None):
                    nonlocal expected
                    environment = {**os.environ, "SOLARIS_TEST_SERVER": proxy_host}
                    if timeout:
                        environment["SOLARIS_TEST_OPEN_TIMEOUT_MS"] = str(timeout)
                    result = subprocess.run([args.client, "socks5", str(port), host, str(tcp_targets[1 if host == "::1" else 0]),
                                             password or "-", username or "-", "-", str(mode)], capture_output=True, text=True, timeout=15, env=environment)
                    if result.returncode:
                        log.seek(0); raise RuntimeError(f"TCP {host} mode{mode}: {result.stderr}\n{log.read()}")
                    expected += 2 if mode == 0 else 0; print(result.stdout, end="")

                def run_udp(port, mode, username="", password="", peer_info=None, client=None, proxy_host="localhost", targets=None):
                    info = peer_info or dict(empty=True, numeric_first=True, numeric_mixed=True)
                    env = dict(os.environ)
                    if not info["empty"]:
                        env["SOLARIS_TEST_SKIP_EMPTY"] = "1"
                    numeric = info["numeric_first"] if client or mode == 5 else info["numeric_mixed"] if mode == 6 else False
                    if numeric:
                        env["SOLARIS_TEST_NUMERIC_REPLIES"] = "1"
                    result = subprocess.run([client or args.udp_client, "socks5", str(port), password or "-", username or "-",
                                             *map(str, targets or udp_targets), str(mode), proxy_host, "native"], capture_output=True, text=True, timeout=15, env=env)
                    if result.returncode:
                        log.seek(0); raise RuntimeError(f"UDP mode{mode}: {result.stderr}\n{log.read()}")
                    print(result.stdout, end="")

                for port, username, password in [(ports[0], "", ""), (ports[1], "solaris", "password")]:
                    for host in ["127.0.0.1", "::1", "localhost"]:
                        run_tcp(port, host, username, password)
                    run_tcp(port, username=username, password=password, proxy_host="localhost")
                    run_tcp(port, username=username, password=password, mode=1)
                    run_tcp(port, username=username, password=password, mode=2)
                    info = control_probe(port, udp_targets, username, password)
                    for mode in [0, 4, 5, 1, 2]:
                        run_udp(port, mode, username, password, info)
                    if info["mixed"]:
                        run_udp(port, 6, username, password, info)
                    run_udp(port, 6, username, password, info, args.association_client)
                run_tcp(ports[1], username="solaris", password="wrong", mode=3)
                run_udp(ports[1], 3, "solaris", "wrong")
                for mode in ["normal", "method-version", "downgrade", "auth-version", "reply-version", "reserved", "address", "partial", "refused", "stall"]:
                    server = ControlledServer(stop, failures, tcp_targets, mode); controlled.append(server)
                    run_tcp(server.port, username="solaris", password="password", mode=0 if mode == "normal" else 3, timeout=50 if mode == "stall" else None)
                for relay_mode in ["numeric", "wildcard", "domain", "ipv6"]:
                    server = ControlledServer(stop, failures, tcp_targets, relay_mode=relay_mode); controlled.append(server)
                    for mode in [0, 4, 5, 6, 7]:
                        targets = [udp_sockets[3].getsockname()[1], udp_targets[1], udp_targets[2]] if mode == 7 else None
                        run_udp(server.port, mode, targets=targets)
                    run_udp(server.port, 6, client=args.association_client)
                ipv6 = ControlledServer(stop, failures, tcp_targets, host="::1", relay_mode="wildcard"); controlled.append(ipv6)
                run_udp(ipv6.port, 6, proxy_host="localhost")
                run_udp(ipv6.port, 6, client=args.association_client, proxy_host="::1")
            for thread in threads:
                thread.join(timeout=1)
            if failures or len(echoes) != expected:
                raise AssertionError(f"peer evidence: {failures}; echoes={len(echoes)}, expected={expected}")
            print("SOCKS5: fixed peer/control, CONNECT/UDP, authentication, DNS/dual stack, relay addresses, source preservation and malformed handshakes passed")
        finally:
            stop.set()
            for server in controlled:
                server.close()
            for sock in sockets:
                sock.close()
            if process:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


if __name__ == "__main__":
    main()
