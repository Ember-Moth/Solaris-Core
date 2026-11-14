#!/usr/bin/env python3
"""Independent loopback peers: echo TCP through half-close, UDP plus alternate replies."""
import argparse
import json
import socket
from pathlib import Path
import sys
import subprocess
import threading


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from child_process import run as run_child

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()
    stop = threading.Event()
    lock = threading.Lock()
    sockets = []
    observed = {b"A": [], b"B": [], b"A2": [], b"V6": []}
    early_replies = []
    early_received = threading.Event()

    def bind(family, kind):
        sock = socket.socket(family, kind)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        sock.settimeout(0.1)
        sockets.append(sock)
        return sock

    def tcp_connection(conn):
        with conn:
            try:
                prefix = b""
                mode = None
                late = b""
                while not stop.is_set():
                    try:
                        data = conn.recv(65536)
                    except socket.timeout:
                        continue
                    if not data:
                        if mode == "early":
                            with lock:
                                early_replies.append(late)
                            early_received.set()
                        else:
                            if prefix:
                                conn.sendall(prefix)
                            conn.sendall(b"TAIL")
                            conn.shutdown(socket.SHUT_WR)
                        break
                    if mode is None:
                        prefix += data
                        if len(prefix) < 5:
                            continue
                        if prefix.startswith(b"EARLY"):
                            mode = "early"
                            late = prefix[5:]
                            conn.sendall(b"HELLO")
                            conn.shutdown(socket.SHUT_WR)
                        else:
                            mode = "echo"
                            conn.sendall(prefix)
                        prefix = b""
                    elif mode == "early":
                        late += data
                    else:
                        conn.sendall(data)
            except OSError:
                pass  # cancellation tests intentionally close before the echo

    def tcp_listener(sock):
        sock.listen(32)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                conn.settimeout(0.1)
                threading.Thread(target=tcp_connection, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def udp_listener(sock, alternate=None):
        while not stop.is_set():
            try:
                data, address = sock.recvfrom(65536)
                with lock:
                    if data in observed:
                        observed[data].append(address[1])
                sock.sendto(data, address)
                if data == b"A" and alternate is not None:
                    sock.sendto(b"", address)
                    alternate.sendto(b"ALT", address)
            except (socket.timeout, ConnectionResetError):
                # Winsock can report a previous send to a cancelled UDP client.
                continue
            except OSError:
                break

    try:
        tcp4 = bind(socket.AF_INET, socket.SOCK_STREAM)
        tcp6 = bind(socket.AF_INET6, socket.SOCK_STREAM)
        while tcp6.getsockname()[1] == tcp4.getsockname()[1]:
            tcp6.close()
            tcp6 = bind(socket.AF_INET6, socket.SOCK_STREAM)
        a = bind(socket.AF_INET, socket.SOCK_DGRAM)
        b = bind(socket.AF_INET, socket.SOCK_DGRAM)
        alternate = bind(socket.AF_INET, socket.SOCK_DGRAM)
        udp6 = bind(socket.AF_INET6, socket.SOCK_DGRAM)
        # listen before launching the client, independently of thread scheduling.
        tcp4.listen(32)
        tcp6.listen(32)
        for sock in [tcp4, tcp6]:
            threading.Thread(target=tcp_listener, args=(sock,), daemon=True).start()
        for sock, alt in [(a, alternate), (b, None), (udp6, None)]:
            threading.Thread(target=udp_listener, args=(sock, alt), daemon=True).start()
        ports = [sock.getsockname()[1] for sock in [tcp4, tcp6, a, b, alternate, udp6]]
        result = run_child([args.client, *map(str, ports)], text=True, capture_output=True, timeout=30)
        print(result.stdout, end="")
        if result.returncode:
            raise RuntimeError(f"client failed ({result.returncode}):\n{result.stderr}")
        report = json.loads(result.stdout.strip().splitlines()[-1])
        if not early_received.wait(timeout=5):
            raise AssertionError("TCP peer did not receive the post-EOF write")
        with lock:
            for key in [b"A", b"B", b"A2"]:
                if observed[key] != [report["udp4_port"]]:
                    raise AssertionError(f"wrong source mapping for {key!r}: {observed[key]}")
            if observed[b"V6"] != [report["udp6_port"]]:
                raise AssertionError("wrong IPv6 source mapping")
            if early_replies != [b"LATE"]:
                raise AssertionError(f"TCP half-close discarded reverse-direction writes: {early_replies}")
        print("Independent TCP/UDP peers verified source mapping, half-close, IPv6, empty and alternate replies")
    finally:
        stop.set()
        for sock in sockets:
            sock.close()


if __name__ == "__main__":
    main()
