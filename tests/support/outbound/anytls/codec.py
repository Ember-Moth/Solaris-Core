#!/usr/bin/env python3
"""Independent AnyTLS wire fixtures, using Python's hashlib and struct only."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

POLICY = b'stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000'


def frame(command, stream, data=b''):
    return struct.pack('!BIH', command, stream, len(data)) + data


with tempfile.TemporaryDirectory(prefix='solaris-anytls-codec-') as directory:
    root = Path(directory)
    digest = hashlib.sha256(b'solaris-anytls-independent-peer').digest()
    (root / 'auth').write_bytes(digest + struct.pack('!H', 30) + bytes(30))
    md5 = hashlib.md5(POLICY).hexdigest().encode()
    (root / 'first').write_bytes(frame(4, 0, b'v=2\nclient=Solaris/0.1.0\npadding-md5=' + md5)
                                + frame(1, 1) + frame(2, 1, b'\x01\x01\x02\x03\x04\x01\xbb'))
    payload = bytes((i * 13 + 7) & 255 for i in range(65541))
    (root / 'data').write_bytes(frame(2, 1, payload[:65535]) + frame(2, 1, payload[65535:]))
    for name, data in {
        'settings': frame(10, 0, b'v=2\n'), 'ack': frame(7, 1),
        'reply': frame(2, 1, b'hello'), 'fin': frame(3, 1),
        'error': frame(7, 1, b'dial refused'), 'heart': frame(8, 19),
        'heart-response': frame(9, 19),
        'update': frame(6, 0, b'stop=2\n0=41-41\n1=42-42'),
        'bad-update': frame(6, 0, b'stop=90000'),
        'bad-fin': frame(3, 1, b'x'), 'bad-version': frame(10, 0, b'v=1'),
        'bad-command': frame(255, 0), 'alert': frame(5, 0, b'rejected'),
    }.items():
        (root / name).write_bytes(data)
    subprocess.run([sys.argv[1], directory], check=True)
