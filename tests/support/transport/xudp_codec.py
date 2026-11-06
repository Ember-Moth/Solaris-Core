#!/usr/bin/env python3
"""Independent Mux.Cool / Single XUDP wire fixtures."""
import ipaddress
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        data = bytes([1 if ip.version == 4 else 3]) + ip.packed
    except ValueError:
        data = bytes([2, len(host)]) + host.encode()
    return struct.pack("!H", port) + data


def frame(host, port, payload, status=2):
    metadata = struct.pack("!HBBB", 0, status, 1, 2) + address(host, port)
    return struct.pack("!H", len(metadata)) + metadata + struct.pack("!H", len(payload)) + payload


def main():
    cases = [("127.0.0.1", 53, 17), ("::1", 443, 1025),
             ("example.com", 8443, 31), ("127.0.0.1", 53, 0),
             ("::1", 65535, 65535), ("a" * 255, 443, 9)]
    with tempfile.TemporaryDirectory(prefix="solaris-xudp-") as directory:
        root = Path(directory)
        for i, (host, port, length) in enumerate(cases):
            payload = bytes((i + n * 17) & 255 for n in range(length))
            (root / f"first-{i}.bin").write_bytes(frame(host, port, payload, 1))
            (root / f"frame-{i}.bin").write_bytes(frame(host, port, payload))
        subprocess.run([sys.argv[1], str(root), *sys.argv[2:]], check=True, timeout=15)


if __name__ == "__main__":
    main()
