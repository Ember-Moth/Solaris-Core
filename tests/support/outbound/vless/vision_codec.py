#!/usr/bin/env python3
"""Independent wire fixtures for Vision framing and TLS ServerHello recognition."""
import argparse
import base64
from pathlib import Path
import struct
import subprocess
import tempfile

UUID = bytes(range(16))


def record(kind, data):
    return bytes([kind, 3, 3]) + struct.pack("!H", len(data)) + data


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def server_hello(cipher=0x1301, extensions=b"\0+\0\2\3\4", random=None, sid=b"", sid_length=None):
    body = b"\3\3" + (random or bytes(range(32))) + bytes([len(sid) if sid_length is None else sid_length]) + sid
    body += struct.pack("!HBH", cipher, 0, len(extensions)) + extensions
    return handshake(2, body)


def fragmented_handshake(data):
    pieces = [data[:1], data[1:3], data[3:6]]
    pieces.extend(data[i:i + 16384] for i in range(6, len(data), 16384))
    return b"".join(record(22, p) for p in pieces)


def frame(data, command=0, padding=3):
    return struct.pack("!BHH", command, len(data), padding) + data + bytes(padding)


def frames(data):
    return b"\0\0" + UUID + b"".join(frame(data[i:i + 2000], padding=i % 7) for i in range(0, len(data), 2000))


def decode_frames(data):
    result, commands = bytearray(), []
    while data:
        if len(data) < 5:
            raise AssertionError("short Vision frame")
        command, size, padding = struct.unpack("!BHH", data[:5])
        if command > 2 or len(data) < 5 + size + padding:
            raise AssertionError("bad Vision frame bounds")
        result.extend(data[5:5 + size]); commands.append(command)
        data = data[5 + size + padding:]
        if command:
            result.extend(data); break
    return bytes(result), commands


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()
    retry = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
    valid = b"\0+\0\2\3\4"
    large_extensions = struct.pack("!HH", 1234, 65525) + bytes(65525) + valid
    variants = [fragmented_handshake(server_hello()),
                fragmented_handshake(server_hello(random=retry)) + fragmented_handshake(server_hello()),
                fragmented_handshake(server_hello(extensions=large_extensions)),
                fragmented_handshake(server_hello(cipher=0xc02f, extensions=b"")),
                fragmented_handshake(server_hello(cipher=0x1305)),
                fragmented_handshake(server_hello(extensions=struct.pack("!HH", 1234, 6) + valid)),
                fragmented_handshake(server_hello(extensions=valid + valid)),
                fragmented_handshake(server_hello(sid=b"x" * 33)),
                fragmented_handshake(server_hello(cipher=0x1306)),
                fragmented_handshake(server_hello(extensions=b"\0+\0\3\3\4"))]
    application = record(23, bytes(range(64))) + record(23, bytes(range(64, 128)))
    client_hello = record(22, handshake(1, b"\3\3" + bytes(32) + b"\0\0\2\x13\1\1\0\0\0"))
    with tempfile.TemporaryDirectory(prefix="solaris-vision-codec-") as directory:
        root = Path(directory)
        root.joinpath("client-hello.bin").write_bytes(client_hello)
        root.joinpath("application.bin").write_bytes(application)
        for index, hello in enumerate(variants):
            root.joinpath(f"hello-{index}.bin").write_bytes(hello)
            root.joinpath(f"response-{index}.bin").write_bytes(frames(hello))
            root.joinpath(f"tail-{index}.bin").write_bytes(frame(application, 2 if index < 3 else 1) + application)
        for name, payload in {"command": UUID + frame(b"", 3), "uuid": bytes([99]) + UUID[1:] + frame(b""),
                              "early-direct": UUID + frame(application, 2)}.items():
            root.joinpath(f"bad-{name}.bin").write_bytes(b"\0\0" + payload)
        maximum = bytes((i * 19) & 255 for i in range(65535))
        root.joinpath("maximum.bin").write_bytes(b"\0\0" + UUID + frame(maximum, 1, 65535))
        public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        root.joinpath("encryption.txt").write_text("mlkem768x25519plus.native.1rtt." + base64.urlsafe_b64encode(public).decode().rstrip("="))
        subprocess.run([args.client, str(root)], check=True, timeout=20)
        start = root.joinpath("start.bin").read_bytes()
        if start[:17] != b"\0" + UUID or start[17:36] != b"\x12\x0a\x10xtls-rprx-vision" or start[36:44] != b"\1\1\xbb\1\x7f\0\0\1":
            raise AssertionError("VLESS flow request mismatch")
        if start[44:60] != UUID:
            raise AssertionError("first Vision UUID missing")
        decoded, commands = decode_frames(start[60:])
        if decoded or commands != [0] or not 900 <= len(start) - 65 <= 1399:
            raise AssertionError("initial cover padding mismatch")
        for index in range(len(variants)):
            first, commands = decode_frames(root.joinpath(f"first-{index}.bin").read_bytes())
            second, later = decode_frames(root.joinpath(f"second-{index}.bin").read_bytes())
            if first + second != application or commands != [0] or later != [2 if index < 3 else 1]:
                raise AssertionError(f"TLS boundary/direct decision mismatch: {index}: {commands}/{later}")
        print("Independent Vision framing, split TLS/ServerHello, HRR, maximum extensions, raw boundary and UDP/443 fixtures passed")


if __name__ == "__main__":
    main()
