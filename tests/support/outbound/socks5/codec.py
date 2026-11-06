#!/usr/bin/env python3
"""Independent SOCKS5 wire fixtures (RFC 1928/1929)."""
import ipaddress
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack("!H", port)
    except ValueError:
        text = host.encode(); return b"\3" + bytes([len(text)]) + text + struct.pack("!H", port)


with tempfile.TemporaryDirectory(prefix="solaris-socks5-codec-") as directory:
    root = Path(directory)
    root.joinpath("greeting-none").write_bytes(b"\5\1\0")
    root.joinpath("greeting-auth").write_bytes(b"\5\1\2")
    root.joinpath("auth").write_bytes(b"\1\7solaris\x08password")
    root.joinpath("auth-max").write_bytes(b"\1\xff" + b"a" * 255 + b"\xff" + b"b" * 255)
    for index, host in enumerate(["1.2.3.4", "::1", "example.com", "d" * 255]):
        root.joinpath(f"connect-{index}").write_bytes(b"\5\1\0" + address(host, 443))
        root.joinpath(f"reply-{index}").write_bytes(b"\5\0\0" + address(host, 1080))
        payload = b"" if index == 1 else bytes((i * 19) & 255 for i in range(65000)) if index == 3 else b"hello"
        root.joinpath(f"packet-{index}").write_bytes(bytes(3) + address(host, 443) + payload)
    root.joinpath("associate").write_bytes(b"\5\3\0" + address("0.0.0.0", 0))
    root.joinpath("reply-zero").write_bytes(b"\5\0\0" + address("0.0.0.0", 0))
    subprocess.run([sys.argv[1], directory], check=True, timeout=20)
