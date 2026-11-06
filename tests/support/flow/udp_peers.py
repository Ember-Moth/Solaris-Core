#!/usr/bin/env python3
"""UDP peers independently verify association source-port reuse/isolation."""
import json
import socket
import subprocess
import sys
import threading


def main():
    sockets = []
    stop = threading.Event()
    lock = threading.Lock()
    observed = {}

    def bind(family):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        sock.settimeout(0.1)
        sockets.append(sock)
        return sock

    def receive(sock, alternate=None):
        while not stop.is_set():
            try:
                data, address = sock.recvfrom(65536)
                with lock:
                    observed.setdefault(data, []).append(address[1])
                sock.sendto(data, address)
                if data == b"A" and alternate is not None:
                    sock.sendto(b"", address)
                    alternate.sendto(b"ALT", address)
            except socket.timeout:
                continue
            except OSError:
                return

    try:
        a, b, alternate = [bind(socket.AF_INET) for _ in range(3)]
        ipv6 = bind(socket.AF_INET6)
        for sock, alt in [(a, alternate), (b, None), (ipv6, None)]:
            threading.Thread(target=receive, args=(sock, alt), daemon=True).start()
        result = subprocess.run([sys.argv[1], *[str(sock.getsockname()[1]) for sock in sockets]],
                                capture_output=True, text=True, timeout=30)
        print(result.stdout, end="")
        if result.returncode:
            raise RuntimeError(f"association client failed ({result.returncode}):\n{result.stderr}")
        report = json.loads(result.stdout.strip().splitlines()[-1])
        with lock:
            for message in [b"A", b"B", b"A2", b"PIN", b"DNS"]:
                assert observed.get(message) == [report["first_port"]], (message, observed)
            assert observed.get(b"C") == [report["second_port"]] * 3, observed
            assert observed.get(b"ENG") == [report["engine_port"]], observed
            assert observed.get(b"") == [report["ipv6_port"]], observed
            assert observed.get(b"NEW") == [report["new_port"]], observed
            assert len({report["first_port"], report["second_port"], report["engine_port"], report["new_port"]}) == 4
        print("Independent UDP peers verified A/B/A, namespaces, worker pinning, DNS, IPv6 and alternate sources")
    finally:
        stop.set()
        for sock in sockets:
            sock.close()


if __name__ == "__main__":
    main()
