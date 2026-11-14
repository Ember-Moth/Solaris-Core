#!/usr/bin/env python3
"""Shadowsocks TCP/native UDP against a pinned independent implementation."""
import argparse
import base64
import json
import os
import sys
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from child_process import run as run_child
from loopback import tcp_udp_pair, udp_pair

METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
           "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
           "2022-blake3-aes-128-gcm:multi", "2022-blake3-aes-256-gcm:multi",
           "2022-blake3-aes-128-gcm:relay", "2022-blake3-aes-256-gcm:relay"]
PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


def method_name(case):
    return case.split(":")[0]


def key(case, value):
    return base64.b64encode(bytes([value]) * (16 if "128" in case else 32)).decode()


def password(method, wrong=False):
    if method.startswith("2022-"):
        parts = []
        if method.endswith(":relay"):
            parts.append(key(method, 0x31))
        if ":" in method:
            parts.append(key(method, 0x32))
        parts.append(key(method, 94 if wrong else 73))
        return ":".join(parts)
    return "wrong-password" if wrong else "solaris-independent-peer"


def identity_credentials(method):
    parts = password(method).split(":")
    if len(parts) == 1:
        return []
    result = [(":".join(parts[:-1] + [key(method, 74)]), 0)]
    for index in range(len(parts) - 1):
        wrong = list(parts)
        wrong[index] = key(method, 0x5e)
        result.append((":".join(wrong), 3))
    result.append((":".join(reversed(parts)), 3))
    return result


def run_udp(args, ports, log):
    stop = threading.Event()
    sockets, guards, observations, threads = [], [], [], []
    lock = threading.Lock()

    def echo(sock):
        while not stop.is_set():
            try:
                payload, source = sock.recvfrom(65536)
                if payload and payload[0] <= 6:
                    with lock:
                        observations.append((source, payload[0]))
                sock.sendto(payload, source)
            except socket.timeout:
                pass
            except OSError:
                break
    try:
        for family in (socket.AF_INET, socket.AF_INET, socket.AF_INET6):
            sock, guard = udp_pair(family)
            guards.append(guard)
            sockets.append(sock)
            thread = threading.Thread(target=echo, args=(sock,), daemon=True)
            thread.start()
            threads.append(thread)
        if args.control:
            for mode in ["mixed", "fresh-v6", "domain"]:
                result = subprocess.run([args.control, f"127.0.0.1:{ports[0]}", password(METHODS[0]),
                    f"127.0.0.1:{sockets[0].getsockname()[1]}", (f"localhost:{sockets[0].getsockname()[1]}" if mode == "domain" else f"[::1]:{sockets[2].getsockname()[1]}"), mode],
                    capture_output=True, text=True, timeout=5)
                print(result.stdout, end="")
                if result.returncode:
                    raise RuntimeError(f"same-peer control failed: {result.stderr}")
        for transport in ("native", "uot"):
            for method, port in zip(METHODS, ports):
                for mode, host in [(0, "127.0.0.1"), (0, "localhost"), (4, "127.0.0.1"), (5, "127.0.0.1"), (1, "localhost"), (2, "127.0.0.1"), (3, "127.0.0.1")]:
                    with lock:
                        before = len(observations)
                    result = subprocess.run([args.udp_client, "shadowsocks", str(port), password(method, mode == 3), method_name(method),
                        *(str(sock.getsockname()[1]) for sock in sockets), str(mode), host, transport], capture_output=True, text=True, timeout=15)
                    print(transport, method, mode, host, result.stdout.strip())
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f"UDP {transport} {method}: {result.stderr}\npeer: {log.read()}")
                    if mode in (0, 4, 5):
                        # Ports can be reused after a previous case closes.
                        # Assert A/B/A reuse within this live pair of channels.
                        seen = {}
                        with lock:
                            for source, index in observations[before:]:
                                seen.setdefault(source, set()).add(index)
                        stable = sum({0, 1, 2, 4, 6}.issubset(packets) for packets in seen.values())
                        if stable != 2:
                            raise AssertionError(f"{transport}/{method}/{mode}/{host}: expected two stable mappings, got {stable}: {seen}")
                for credentials, mode in identity_credentials(method):
                    result = subprocess.run([args.udp_client, "shadowsocks", str(port), credentials, method_name(method),
                        *(str(sock.getsockname()[1]) for sock in sockets), str(mode), "127.0.0.1", transport],
                        capture_output=True, text=True, timeout=15)
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f"identity UDP {transport} {method} mode {mode}: {result.stderr}\npeer: {log.read()}")
                if args.association_client:
                    result = run_child([args.association_client, "shadowsocks", str(port), password(method), method_name(method),
                        *(str(sock.getsockname()[1]) for sock in sockets), "6", "localhost", transport],
                        capture_output=True, text=True, timeout=15, env={**os.environ, "SOLARIS_TEST_TRACE": "1"})
                    print(transport, method, "association", result.stdout.strip())
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f"association {transport} {method}: {result.stderr}\npeer: {log.read()}")
    finally:
        stop.set()
        for sock in [*sockets, *guards]:
            sock.close()
        for thread in threads:
            thread.join(timeout=1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--udp-client")
    parser.add_argument("--control")
    parser.add_argument("--association-client")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.peer, "version"], text=True).splitlines()[0]
    if args.version.removeprefix("v") not in version:
        raise RuntimeError(f"wrong peer: {version}")
    stop = threading.Event()
    listeners, threads, received, failures, ports = [], [], [], [], []
    peer = None

    def echo(conn):
        data = bytearray()
        try:
            with conn:
                conn.settimeout(5)
                while chunk := conn.recv(3029):
                    data.extend(chunk)
                    conn.sendall(chunk)
                conn.shutdown(socket.SHUT_WR)
                if data:
                    if data != PAYLOAD:
                        failures.append(f"bad payload ({len(data)})")
                    else:
                        received.append(True)
        except (OSError, ConnectionError):
            if data:
                failures.append("incomplete echo")

    def listen(sock):
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                thread = threading.Thread(target=echo, args=(conn,), daemon=True)
                threads.append(thread)
                thread.start()
            except socket.timeout:
                pass
            except OSError:
                break

    with tempfile.TemporaryDirectory(prefix="solaris-ss-") as directory:
        root = Path(directory)
        try:
            for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                sock = socket.socket(family)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, 0))
                sock.listen(32)
                sock.settimeout(0.1)
                listeners.append(sock)
                threading.Thread(target=listen, args=(sock,), daemon=True).start()
            # Keep all reservations open until the complete set is allocated.
            reservations = []
            def reserve_port():
                tcp, udp, guard = tcp_udp_pair(socket.AF_INET)
                reservations.extend((tcp, udp))
                listeners.append(guard)
                return tcp.getsockname()[1]
            for _ in METHODS:
                ports.append(reserve_port())
            inbounds = []
            for method, port in zip(METHODS, ports):
                inbound = {"type": "shadowsocks", "tag": method, "listen": "127.0.0.1",
                           "listen_port": port, "method": method_name(method), "password": key(method, 0x32) if ":" in method else password(method)}
                if ":" in method:
                    inbound["users"] = [{"name": "primary", "password": key(method, 73)},
                                        {"name": "alternate", "password": key(method, 74)}]
                if method.endswith(":relay"):
                    terminal = reserve_port()
                    inbound["listen_port"] = terminal
                    inbound["tag"] += "-terminal"
                    inbounds.append({"type": "shadowsocks", "tag": method, "listen": "127.0.0.1",
                        "listen_port": port, "method": method_name(method), "password": key(method, 0x31),
                        "destinations": [{"name": "terminal", "password": key(method, 0x32),
                                          "server": "127.0.0.1", "server_port": terminal}]})
                inbounds.append(inbound)
            config = {"log": {"level": "warn"}, "inbounds": inbounds,
                      "outbounds": [{"type": "direct", "tag": "direct", "domain_strategy": "ipv4_only"}], "route": {"final": "direct"}}
            path = root / "config.json"
            path.write_text(json.dumps(config))
            for sock in reservations:
                sock.close()
            with (root / "peer.log").open("w+") as log:
                peer = subprocess.Popen([args.peer, "run", "-c", str(path)], stdout=log, stderr=log)
                deadline = time.monotonic() + 5
                while True:
                    if peer.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("peer startup timed out")
                        time.sleep(0.02)
                for method, port in zip(METHODS, ports):
                    for host, target, mode in [("127.0.0.1", 0, 0), ("::1", 1, 0), ("localhost", 0, 0),
                                               ("127.0.0.1", 0, 1), ("127.0.0.1", 0, 2), ("127.0.0.1", 0, 3)]:
                        result = subprocess.run([args.client, "shadowsocks", str(port), host,
                            str(listeners[target].getsockname()[1]), password(method, mode == 3), method_name(method), "-", str(mode)],
                            capture_output=True, text=True, timeout=15)
                        print(method, result.stdout.strip())
                        if result.returncode:
                            log.seek(0)
                            raise RuntimeError(f"{method} mode {mode}: {result.stderr}\npeer: {log.read()}")
                    for credentials, mode in identity_credentials(method):
                        result = subprocess.run([args.client, "shadowsocks", str(port), "127.0.0.1",
                            str(listeners[0].getsockname()[1]), credentials, method_name(method), "-", str(mode)],
                            capture_output=True, text=True, timeout=15)
                        if result.returncode:
                            log.seek(0)
                            raise RuntimeError(f"identity TCP {method} mode {mode}: {result.stderr}\npeer: {log.read()}")
                for thread in threads:
                    thread.join(timeout=1)
                if failures or len(received) != len(METHODS) * 6 + 2 * sum(":" in method for method in METHODS):
                    raise AssertionError(f"echo integrity: {failures}; echoes={len(received)}")
                if args.udp_client:
                    run_udp(args, ports, log)
                print(f"{version}: six Shadowsocks methods plus AES multi-user and two-layer relay, TCP dual-stack/domain/cancellation/credentials passed")
        finally:
            stop.set()
            for sock in listeners:
                sock.close()
            if peer is not None:
                peer.terminate()
                try:
                    peer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.wait()


if __name__ == "__main__":
    main()
