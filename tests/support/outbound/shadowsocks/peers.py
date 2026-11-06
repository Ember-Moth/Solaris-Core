#!/usr/bin/env python3
"""Shadowsocks TCP/native UDP against a pinned independent implementation."""
import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
           "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"]
PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


def password(method, wrong=False):
    if method.startswith("2022-"):
        return base64.b64encode(bytes([94 if wrong else 73]) * (16 if "128" in method else 32)).decode()
    return "wrong-password" if wrong else "solaris-independent-peer"


def run_udp(args, ports, log):
    stop = threading.Event()
    sockets, observations, threads = [], [], []
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
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, 0))
            sock.settimeout(0.1)
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
                    result = subprocess.run([args.udp_client, "shadowsocks", str(port), password(method, mode == 3), method,
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
                if args.association_client:
                    result = subprocess.run([args.association_client, "shadowsocks", str(port), password(method), method,
                        *(str(sock.getsockname()[1]) for sock in sockets), "6", "localhost", transport],
                        capture_output=True, text=True, timeout=15)
                    print(transport, method, "association", result.stdout.strip())
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f"association {transport} {method}: {result.stderr}\npeer: {log.read()}")
    finally:
        stop.set()
        for sock in sockets:
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
            for _ in METHODS:
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                reservations.append(sock)
                ports.append(sock.getsockname()[1])
            inbounds = [{"type": "shadowsocks", "tag": method, "listen": "127.0.0.1",
                         "listen_port": port, "method": method, "password": password(method)}
                        for method, port in zip(METHODS, ports)]
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
                            str(listeners[target].getsockname()[1]), password(method, mode == 3), method, "-", str(mode)],
                            capture_output=True, text=True, timeout=15)
                        print(method, result.stdout.strip())
                        if result.returncode:
                            log.seek(0)
                            raise RuntimeError(f"{method} mode {mode}: {result.stderr}\npeer: {log.read()}")
                for thread in threads:
                    thread.join(timeout=1)
                if failures or len(received) != 30:
                    raise AssertionError(f"echo integrity: {failures}; echoes={len(received)}")
                if args.udp_client:
                    run_udp(args, ports, log)
                print(f"{version}: five Shadowsocks methods, TCP dual-stack/domain/cancellation/credentials passed")
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
