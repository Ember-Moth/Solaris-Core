#!/usr/bin/env python3
"""Seed coverage-guided parsing with independent protocol/crypto fixtures."""
import argparse
import base64
import importlib.util
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--ss-control")
    parser.add_argument("--encryption-control")
    parser.add_argument("--encryption-client")
    parser.add_argument("--tls-peer")
    parser.add_argument("--tls-client")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    count = 0

    def seed(kind, data, mode=0, name=""):
        nonlocal count
        args.output.joinpath(f"{kind:02}-{mode:02}-{count:04}-{name}").write_bytes(bytes([kind, mode, 0]) + data)
        count += 1

    ip_path = Path(__file__).resolve().parents[1] / "support/inbound/tun/ip.py"
    ip_spec = importlib.util.spec_from_file_location("ip_fixtures", ip_path)
    ip_module = importlib.util.module_from_spec(ip_spec); ip_spec.loader.exec_module(ip_module)
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            for size in (0, 1, 1200):
                seed(20, ip_module.packet(version, protocol, bytes(i % 251 for i in range(size))), name="ip")

    address = b"\x01\x7f\0\0\1\0\x35"
    vmess = b"\0\x35\1\x7f\0\0\1"
    for raw in [address, b"\3\x09localhost\1\xbb", b"\4" + bytes(15) + b"\1\1\xbb", b"\3\0\0\0"]:
        seed(0, raw)
    seed(1, vmess)
    seed(2, b"\0\x7f\0\0\1\0\x35\0\0")
    seed(2, b"\2\x09localhost\0\x35\0\5hello")
    seed(3, b"\0\x0c\0\0\2\1\2" + vmess + b"\0\5hello")
    seed(3, b"\0\4\0\0\3\1\0\0")
    seed(4, b"\0\0payload")
    seed(4, b"\0\3\x0a\x01xhello")
    path = Path(__file__).resolve().parents[1] / "support/outbound/vless/vision_codec.py"
    spec = importlib.util.spec_from_file_location("vision_fixtures", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    hello = module.fragmented_handshake(module.server_hello())
    app = module.record(23, bytes(range(64)))
    seed(5, module.frames(hello) + module.frame(app, 2))
    seed(5, b"\0\0" + module.UUID + module.frame(bytes(65535), 1, 65535))
    seed(6, module.record(22, module.handshake(1, bytes(64))) + app)
    response = module.frames(hello)
    seed(6, struct.pack("!H", len(response)) + response + app)
    for text in [b"stop=2\n0=41-41\n1=42-42", b"stop=90000", b"stop=2\n0=30-30\n1=100-400,c,500-1000"]:
        seed(9, text)
    frame = lambda command, stream, data=b"": struct.pack("!BIH", command, stream, len(data)) + data
    settings = frame(10, 0, b"v=2\n")
    for data in [settings + frame(7, 1) + frame(2, 1, b"hello") + frame(3, 1), settings + frame(8, 19),
                 frame(6, 0, b"stop=2\n0=41-41\n1=42-42"), frame(255, 0), frame(5, 0, b"rejected")]:
        seed(10, data)
    public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    key = base64.urlsafe_b64encode(public).rstrip(b"=")
    for appearance in [b"native", b"xorpub", b"random"]:
        seed(11, b"mlkem768x25519plus." + appearance + b".0rtt.100-35-35." + key)
    for mode in range(8):
        seed(12, bytes([255]) * 12 + b"rekey payload", mode)
    for url in [b"http://example.com/", b"https://[::1]:443?query=1#fragment", b"http://host:65536/", b"http://user:pass@host/"]:
        seed(14, url)
    for header in [b"HTTP/1.1 204 No Content\r\n\r\n", b"HTTP/1.0 503 Bad\r\nContent-Length: 0\r\n\r\n", b"HTTP/1.1 200 OK\r\nX: a\r\n\r\n"]:
        seed(15, header)
    for mode in range(54):
        seed(16, b"mlkem768x25519plus.native.1rtt." + key, mode)
    for mode in range(4):
        greeting = b"\5\2\1\0" if mode & 1 else b"\5\0"
        seed(17, greeting + b"\5\0\0" + address, mode)
        seed(17, greeting + b"\5\0\0\3\x09localhost\1\xbb", mode)
    for raw in [b"\0\0\0" + address, b"\0\0\0" + address + b"payload", b"\0\0\1" + address, b"\0\0\0\xff"]:
        seed(18, raw)
    for mode in (0, 1, 31, 63):
        for request in (
            b"GET http://example.com/a?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Test: tail\r\n\r\nGET /next HTTP/1.0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcGET /next HTTP/1.0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n" + b"X:y\r\n" * 700 + b"\r\n",
        ):
            seed(21, request, mode, "http-inbound")
    for mode in (0, 31, 63):
        seed(21, b"GET ws://example.com/chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", mode, "websocket")
        for response in (
            b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n\x81\x02hi",
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno!PIPELINED",
            b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nno!\r\n0\r\nX-Trailer: good\r\n\r\n",
            b"HTTP/1.1 403 Forbidden\r\n\r\nclosed body",
        ):
            seed(22, response, mode, "upgrade-response")
    if args.ss_control:
        with tempfile.TemporaryDirectory(prefix="solaris-fuzz-ss-") as directory:
            subprocess.run([args.ss_control, "fixtures", directory], check=True, timeout=20)
            for file in sorted(Path(directory).glob("*.bin")):
                # Request/EIH fixtures exercise the independent server decoder
                # in codec tests. This fuzzer consumes client-side responses.
                if re.fullmatch(r"request-(stream|packet)-[3-5]-(0|1|2|8)", file.stem):
                    continue
                match = re.fullmatch(r"(stream|packet)-([0-5])-([0-9]+)", file.stem)
                if match is None:
                    raise ValueError(f"unrecognized Shadowsocks response fixture: {file.name}")
                seed(7 if match[1] == "stream" else 8, file.read_bytes(), int(match[2]), file.stem)
    if bool(args.encryption_control) != bool(args.encryption_client):
        raise ValueError("encryption control and client must be provided together")
    if args.encryption_control:
        with tempfile.TemporaryDirectory(prefix="solaris-fuzz-encryption-") as directory:
            subprocess.run([args.encryption_control, "prepare", directory], check=True, timeout=10)
            subprocess.run([args.encryption_client, "emit", directory], check=True, timeout=10)
            with subprocess.Popen([args.encryption_control, "fixtures", directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) as peer:
                try:
                    if peer.stdout.readline().strip() != "FULL_READY":
                        raise RuntimeError(peer.stderr.read())
                    for mode in range(6):
                        for name in ["response", "bad-length", "bad-point"]:
                            seed(13, Path(directory, f"{name}-{mode}.bin").read_bytes(), mode, name)
                finally:
                    peer.terminate(); peer.wait(timeout=5)
    if bool(args.tls_peer) != bool(args.tls_client):
        raise ValueError("TLS peer and client must be provided together")
    if args.tls_peer:
        with tempfile.TemporaryDirectory(prefix="solaris-fuzz-tls-") as directory:
            driver = Path(__file__).resolve().parents[1] / "support/transport/tls_profiles.py"
            subprocess.run([sys.executable, str(driver), args.tls_client, "--peer", args.tls_peer,
                            "--seed-dir", directory], check=True, timeout=180)
            for file in sorted(Path(directory).glob("*.session")):
                seed(19, file.read_bytes(), name=file.stem)
    print(f"Created {count} independent parser seeds in {args.output}")


if __name__ == "__main__":
    main()
