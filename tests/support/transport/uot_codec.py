#!/usr/bin/env python3
"""Independent UoT v2 wire fixtures, generated without the Solaris codec."""
import ipaddress
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def main():
    cases = [("127.0.0.1", 53, 17), ("::1", 443, 1025),
             ("example.com", 8443, 31), ("127.0.0.1", 53, 0),
             ("::1", 65535, 65535), ("a" * 255, 443, 9)]
    with tempfile.TemporaryDirectory(prefix="solaris-uot-") as directory:
        root = Path(directory)
        for i, (host, port, length) in enumerate(cases):
            try:
                address = ipaddress.ip_address(host)
                data = address.packed
                standard, uot = (1, 0) if address.version == 4 else (4, 1)
            except ValueError:
                data = bytes([len(host)]) + host.encode()
                standard, uot = 3, 2
            address = data + struct.pack("!H", port)
            payload = bytes((i + n * 17) & 255 for n in range(length))
            frame = bytes([uot]) + address + struct.pack("!H", length) + payload
            request = bytes([0, standard]) + address
            (root / f"first-{i}.bin").write_bytes(request + frame)
            (root / f"frame-{i}.bin").write_bytes(frame)
        subprocess.run([sys.argv[1], str(root)], check=True, timeout=15)


if __name__ == "__main__":
    main()
