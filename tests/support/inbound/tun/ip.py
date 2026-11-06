#!/usr/bin/env python3
"""Independent RFC packet/checksum vectors for the C codec."""
import ipaddress
import pathlib
import struct
import subprocess
import sys
import tempfile


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def packet(version, protocol, payload=b'', rewritten=False, options=b'', extension=b''):
    hosts = (('10.89.0.11', '10.89.0.12') if rewritten else ('10.0.0.3', '10.0.0.7')) if version == 4 else (
        ('fd00:89::11', 'fd00:89::12') if rewritten else ('fd00::3', 'fd00::7'))
    src, dst = [ipaddress.ip_address(h).packed for h in hosts]
    sp, dp = (5011, 5012) if rewritten else (1234, 1235)
    if protocol == 17:
        segment = struct.pack('!HHHH', sp, dp, len(payload) + 8, 0) + payload
        where = 6
    elif protocol == 6:
        segment = struct.pack('!HHIIBBHHH', sp, dp, 37, 19, 0x60, 0x18, 8192, 0, 0) + b'\x01\x01\x01\x01' + payload
        where = 16
    else:
        segment = struct.pack('!BBHHH', 8 if version == 4 else 128, 0, 0, 123, 45) + payload
        where = 2
    pseudo = b'' if protocol == 1 else src + dst + (struct.pack('!BBH', 0, protocol, len(segment)) if version == 4 else struct.pack('!I3xB', len(segment), protocol))
    value = checksum(pseudo + segment)
    if protocol == 17 and value == 0:
        value = 65535
    segment = segment[:where] + struct.pack('!H', value) + segment[where + 2:]
    if version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45 + len(options) // 4, 0, 20 + len(options) + len(segment), 0, 0, 64, protocol, 0, src, dst) + options
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, len(extension) + len(segment), 0 if extension else protocol, 64, src, dst) + extension
    return header + segment


def main():
    cases = []
    def add(p, status=0, mode=0, expected=b''):
        cases.append((mode, p, expected, status))
    for version in (4, 6):
        for proto in (17, 6, 1 if version == 4 else 58):
            for length in (0, 1, 17, 1023):
                data = bytes(i % 251 for i in range(length))
                p = packet(version, proto, data)
                add(p, mode=1, expected=packet(version, proto, data, True))
                for n in (0, 1, len(p) // 2, len(p) - 1):
                    add(p[:n], -1)
                bad = bytearray(p); bad[-1] ^= 1; add(bytes(bad), -1)
                add(p + b'\0', -1)
                if proto == 17:
                    add(p, mode=2, expected=p)
        for length in (65507 if version == 4 else 65527,):
            p = packet(version, 17, b'x' * length)
            add(p, mode=2, expected=p)
    for options in (b'\x01\x01\x00\x00', b'\x82\x04\x00\x00'):
        add(packet(4, 6, b'options', options=options), mode=1, expected=packet(4, 6, b'options', True, options))
    for options in (b'\x83\x04\0\0', b'\x89\x04\0\0'):
        add(packet(4, 6, options=options), -3)
    add(packet(4, 6, options=b'\x82\x05\0\0'), -1)
    for extension in (b'\x11\0\0\0\0\0\0\0', b'\x11\0\x01\x04\0\0\0\0'):
        add(packet(6, 17, b'extension', extension=extension), mode=1, expected=packet(6, 17, b'extension', True, extension=extension))
    add(packet(6, 17, extension=b'\x11\0\x80\x04\0\0\0\0'), -3)
    add(packet(6, 17, extension=b'\x11\0\x01\x09\0\0\0\0'), -1)
    p = bytearray(packet(4, 17)); p[26:28] = b'\0\0'; add(bytes(p))
    p = bytearray(packet(6, 17)); p[46:48] = b'\0\0'; add(bytes(p), -1)
    for flags in (1, 0x2000):
        p = bytearray(packet(4, 17)); p[6:8] = struct.pack('!H', flags); p[10:12] = b'\0\0'; p[10:12] = struct.pack('!H', checksum(bytes(p[:20]))); add(bytes(p), -3)
    for next_header in (43, 44, 50, 51, 59):
        p = bytearray(packet(6, 17)); p[6] = next_header; add(bytes(p), -3)
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / 'fixtures.bin'
        with path.open('wb') as file:
            file.write(struct.pack('!I', len(cases)))
            for mode, data, expected, status in cases:
                file.write(struct.pack('!IIIi', mode, len(data), len(expected), status)); file.write(data); file.write(expected)
        subprocess.run([sys.argv[1], str(path)], check=True)

if __name__ == '__main__':
    main()
