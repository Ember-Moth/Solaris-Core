#!/usr/bin/env python3
"""XUDP: pinned external implementations and an independent wire/UDP peer."""
import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from loopback import udp_pair

UUID = "7b4bb031-41b5-4d1d-b062-1ea0cab957c1"
WRONG = "e003355b-2523-4e85-9567-345bdbe7e506"


def exact(conn, n):
    data = bytearray()
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            raise EOFError()
        data += part
    return bytes(data)


def encode_address(host, port):
    ip = ipaddress.ip_address(host)
    return struct.pack("!HB", port, 1 if ip.version == 4 else 3) + ip.packed


def frame(address, payload):
    metadata = b"\0\0\2\1\2" + address
    return struct.pack("!H", len(metadata)) + metadata + struct.pack("!H", len(payload)) + payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--xray", required=True)
    parser.add_argument("--xray-version", required=True)
    parser.add_argument("--control", required=True)
    parser.add_argument("--association-client")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    for executable, version in [(args.peer, args.version), (args.xray, args.xray_version)]:
        line = subprocess.check_output([executable, "version"], text=True).splitlines()[0]
        if version.removeprefix("v") not in line:
            raise RuntimeError(f"unexpected reference version: {line}")
        print(line)
    stop = threading.Event()
    sockets, processes, threads, failures, observations = [], [], [], [], []

    def udp_echo(sock, reply=None):
        while not stop.is_set():
            try:
                data, sender = sock.recvfrom(65536)
                if sender[1] == sock.getsockname()[1]:
                    failures.append("loopback UDP source collided with echo port")
                    return
                observations.append((sock.getsockname(), sender, len(data)))
                (reply or sock).sendto(data, sender)
            except socket.timeout:
                pass
            except OSError:
                break

    def controlled(conn, mode, tls_context):
        udp = {}
        try:
            conn.settimeout(5)
            if tls_context:
                conn = tls_context.wrap_socket(conn, server_side=True)
            request = exact(conn, 19)
            credential = UUID if mode == "echo" else WRONG
            if request != b"\0" + bytes.fromhex(credential.replace("-", "")) + b"\0\3":
                raise AssertionError("invalid VLESS Mux request")
            conn.sendall(b"\0")
            conn.sendall(b"\3\x0a\x01x")
            first = True
            while True:
                length = struct.unpack("!H", exact(conn, 2))[0]
                header = exact(conn, length)
                if header[:5] != b"\0\0" + bytes([1 if first else 2, 1, 2]):
                    raise AssertionError(f"invalid XUDP metadata: {header.hex()}")
                first = False
                port = struct.unpack("!H", header[5:7])[0]
                kind = header[7]
                if kind in (1, 3):
                    host = str(ipaddress.ip_address(header[8:]))
                elif kind == 2 and header[8] == len(header) - 9:
                    host = header[9:].decode()
                else:
                    raise AssertionError("invalid XUDP address")
                payload = exact(conn, struct.unpack("!H", exact(conn, 2))[0])
                if mode != "echo":
                    responses = {"partial": b"\0\x0c\0", "length": b"\xff\xff",
                                 "id": b"\0\4\0\1\2\0", "end": b"\0\4\0\0\3\0",
                                 "error": b"\0\4\0\0\3\2"}
                    conn.sendall(responses[mode]); conn.shutdown(socket.SHUT_WR)
                    while conn.recv(65536):
                        pass
                    break
                family = socket.AF_INET6 if kind == 3 else socket.AF_INET
                if family not in udp:
                    udp[family] = socket.socket(family, socket.SOCK_DGRAM)
                    udp[family].settimeout(3)
                udp[family].sendto(payload, (host, port))
                reply, source = udp[family].recvfrom(65536)
                # Domain replies can carry the original domain in this wire
                # format. Numeric packets preserve the actual reply endpoint.
                address = header[5:] if kind == 2 else encode_address(source[0], source[1])
                response = b"\0\4\x12\x34\4\1\0\3xyz" + frame(address, reply)
                # A control frame followed by a packet, fragmented across reads.
                for n in range(0, min(len(response), 31), 3):
                    conn.sendall(response[n:min(n + 3, 31)])
                if len(response) > 31:
                    conn.sendall(response[31:])
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as exc:
            failures.append(str(exc))
        finally:
            conn.close()
            for sock in udp.values():
                sock.close()

    def listen(sock, mode, tls_context):
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                thread = threading.Thread(target=controlled, args=(conn, mode, tls_context), daemon=True)
                threads.append(thread); thread.start()
            except socket.timeout:
                pass
            except OSError:
                break

    def run(port, destinations, mode, transport, cert=None, client=None):
        before = len(observations)
        command = [client or args.client, "vless", str(port), WRONG if mode == 3 else UUID, "-",
                   *(str(p) for p in destinations), str(mode), "localhost", transport]
        if cert:
            command.append(str(cert))
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError(f"{transport} mode={mode} tls={bool(cert)}: {result.stdout}\n{result.stderr}\nUDP target observations: {observations[before:]}")
        print(transport, mode, "TLS" if cert else "plain", result.stdout.strip())

    with tempfile.TemporaryDirectory(prefix="solaris-xudp-peer-") as directory:
        root = Path(directory)
        try:
            udp_sockets = []
            for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")]:
                sock, guard = udp_pair(family)
                udp_sockets.append(sock); sockets.extend((sock, guard))
                reply = udp_sockets[1] if len(udp_sockets) == 4 else None
                thread = threading.Thread(target=udp_echo, args=(sock, reply), daemon=True)
                threads.append(thread); thread.start()
            targets = [sock.getsockname()[1] for sock in udp_sockets[:3]]
            alternate = [udp_sockets[3].getsockname()[1], targets[1], targets[2]]
            key, cert = root / "key.pem", root / "cert.pem"
            subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls_context.load_cert_chain(cert, key)
            for name, executable in [("sing", args.peer), ("xray", args.xray)]:
                reservations = [socket.socket(), socket.socket()]
                for sock in reservations:
                    sock.bind(("127.0.0.1", 0))
                ports = [sock.getsockname()[1] for sock in reservations]
                if name == "sing":
                    inbounds = [{"type": "vless", "listen": "127.0.0.1", "listen_port": p, "users": [{"uuid": UUID}]} for p in ports]
                    inbounds[1]["tls"] = {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}
                    config = {"log": {"level": "warn"}, "inbounds": inbounds,
                              "outbounds": [{"type": "direct", "domain_strategy": "ipv4_only"}]}
                else:
                    inbounds = [{"listen": "127.0.0.1", "port": p, "protocol": "vless", "settings": {
                        "clients": [{"id": UUID}], "decryption": "none"}, "streamSettings": {"network": "raw"}} for p in ports]
                    inbounds[1]["streamSettings"].update({"security": "tls", "tlsSettings": {"certificates": [
                        {"certificateFile": str(cert), "keyFile": str(key)}]}})
                    config = {"log": {"loglevel": "warning"}, "inbounds": inbounds,
                              "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}},
                                  "settings": {"finalRules": [{"action": "allow", "network": "udp", "ip": ["127.0.0.1/32", "::1/128"],
                                      "port": ",".join(str(s.getsockname()[1]) for s in udp_sockets)}]}}]}
                path = root / f"{name}.json"; path.write_text(json.dumps(config))
                for sock in reservations:
                    sock.close()
                with (root / f"{name}.log").open("w+") as log:
                    process = subprocess.Popen([executable, "run", "-c", str(path)], stdout=log, stderr=log); processes.append(process)
                    deadline = time.monotonic() + 5
                    while True:
                        if process.poll() is not None:
                            log.seek(0); raise RuntimeError(log.read())
                        try:
                            with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.1):
                                break
                        except OSError:
                            if time.monotonic() > deadline:
                                raise RuntimeError("peer startup timed out")
                            time.sleep(0.01)
                    control = subprocess.run([args.control, f"127.0.0.1:{ports[0]}", UUID, f"127.0.0.1:{targets[0]}"], timeout=5)
                    if control.returncode:
                        log.seek(0); raise RuntimeError(log.read())
                    mixed = subprocess.run([args.control, f"127.0.0.1:{ports[0]}", UUID, f"127.0.0.1:{targets[0]}", f"[::1]:{targets[2]}"],
                                           check=True, capture_output=True, text=True, timeout=5)
                    print(mixed.stdout, end="")
                    try:
                        for mode in [0, 4, 5, 6, 7, 1, 2, 3]:
                            if mode == 6 and "unavailable" in mixed.stdout:
                                continue
                            run(ports[0], alternate if mode == 7 else targets, mode, f"xudp-{name}")
                        run(ports[1], targets, 0, f"xudp-{name}", cert)
                        if args.association_client:
                            run(ports[1], targets, 6, f"xudp-{name}", cert, args.association_client)
                        for _ in range(1, args.repeat):
                            run(ports[0], targets, 0, f"xudp-{name}")
                            if "unavailable" not in mixed.stdout:
                                run(ports[0], targets, 6, f"xudp-{name}")
                    except Exception:
                        log.seek(0); print(log.read()); raise
            for mode in ["echo", "partial", "length", "id", "end", "error"]:
                sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen(16); sock.settimeout(0.1); sockets.append(sock)
                thread = threading.Thread(target=listen, args=(sock, mode, tls_context), daemon=True)
                threads.append(thread); thread.start()
                if mode == "echo":
                    for case in [0, 4, 5, 6, 7]:
                        run(sock.getsockname()[1], alternate if case == 7 else targets, case, "xudp", cert)
                    if args.association_client:
                        run(sock.getsockname()[1], targets, 6, "xudp", cert, args.association_client)
                else:
                    # Bad response with a valid request (mode 3 normally uses
                    # bad credentials, so this scripted peer accepts either).
                    run(sock.getsockname()[1], targets, 3, "xudp", cert)
                    if args.association_client:
                        run(sock.getsockname()[1], targets, 3, "xudp", cert, args.association_client)
            if failures:
                raise AssertionError(failures)
            if sum(length == 0 for _, _, length in observations) < 10:
                raise AssertionError("empty datagrams did not reach independent UDP echo targets")
            print("XUDP dual-worker interop, multi-destination, empty packet, source and malformed-session tests passed")
        finally:
            stop.set()
            for sock in sockets:
                sock.close()
            for process in processes:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            for thread in threads:
                thread.join(timeout=0.2)


if __name__ == "__main__":
    main()
