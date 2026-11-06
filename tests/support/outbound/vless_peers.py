#!/usr/bin/env python3
"""Protocol interop against pinned sing-box and independent TCP/UDP echo peers."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

UUID = "7b4bb031-41b5-4d1d-b062-1ea0cab957c1"
WRONG_UUID = "e003355b-2523-4e85-9567-345bdbe7e506"
PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.peer, "version"], text=True)
    if args.version.removeprefix("v") not in version.splitlines()[0]:
        raise RuntimeError(f"wrong reference peer version: {version}")
    print(version.splitlines()[0])
    stop = threading.Event()
    sockets = []
    received = []
    failures = []
    threads = []
    peer = None

    def echo(conn):
        data = bytearray()
        try:
            with conn:
                conn.settimeout(5)
                while True:
                    chunk = conn.recv(3029)
                    if not chunk:
                        break
                    data.extend(chunk)
                    conn.sendall(chunk)
                conn.shutdown(socket.SHUT_WR)
                if data:
                    if data != PAYLOAD:
                        failures.append(f"echo payload length/integrity: {len(data)}")
                    else:
                        received.append(True)
        except (ConnectionError, OSError):
            if data:
                failures.append("unexpected data on cancelled/incomplete echo")

    def controlled(conn, mode):
        try:
            conn.settimeout(5)
            def exact(size):
                value = bytearray()
                while len(value) < size:
                    chunk = conn.recv(size - len(value))
                    if not chunk:
                        raise EOFError("incomplete VLESS request")
                    value.extend(chunk)
                return bytes(value)
            header = exact(18)
            if header[0] != 0 or header[1:17] != bytes.fromhex(UUID.replace("-", "")) or header[17] != 0:
                raise AssertionError("incorrect VLESS preface at controlled peer")
            command = exact(4)
            if command[0] != 1:
                raise AssertionError("expected TCP command")
            family = command[3]
            exact(4 if family == 1 else 16 if family == 3 else exact(1)[0])
            if mode == "fragment":
                # Split the header/addons across reads, then include normal
                # payload. Unknown addons are length-delimited and skipped.
                for chunk in [b"\0", b"\3\x0a", b"\x01x"]:
                    conn.sendall(chunk)
                    time.sleep(0.002)
                echo(conn)
                return
            response = {"version": b"\1\0", "partial": b"\0\5xx", "empty": b""}[mode]
            conn.sendall(response)
            conn.shutdown(socket.SHUT_WR)
            while conn.recv(65536):
                pass
        except (ConnectionError, OSError, EOFError):
            pass
        except Exception as exc:
            failures.append(str(exc))
        finally:
            conn.close()

    def listen(sock, mode=None):
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                thread = threading.Thread(target=echo if mode is None else controlled,
                                          args=(conn,) if mode is None else (conn, mode), daemon=True)
                threads.append(thread)
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    with tempfile.TemporaryDirectory(prefix="solaris-interop-") as directory:
        root = Path(directory)
        try:
            for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                sock = socket.socket(family, socket.SOCK_STREAM)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, 0))
                sock.listen(32)
                sock.settimeout(0.1)
                sockets.append(sock)
                threading.Thread(target=listen, args=(sock,), daemon=True).start()
            key, cert = root / "peer.key", root / "peer.pem"
            openssl = shutil.which("openssl")
            if not openssl:
                raise RuntimeError("OpenSSL CLI required for local peer certificates")
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, capture_output=True)
            ports = [reserve_port(), reserve_port()]
            if ports[0] == ports[1]:
                raise RuntimeError("port allocation collision")
            inbounds = []
            for index, port in enumerate(ports):
                inbound = {"type": "vless", "tag": f"vless-{index}", "listen": "127.0.0.1",
                           "listen_port": port, "users": [{"uuid": UUID}]}
                if index:
                    inbound["tls"] = {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}
                inbounds.append(inbound)
            config = {"log": {"level": "warn"}, "inbounds": inbounds,
                      "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config))
            log = (root / "peer.log").open("w+")
            peer = subprocess.Popen([args.peer, "run", "-c", str(config_path)], stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            while True:
                if peer.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"reference peer exited: {log.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("reference peer startup timed out")
                    time.sleep(0.02)
            cases = [(ports[0], "127.0.0.1", 0, "-", 0, UUID),
                     (ports[0], "::1", 1, "-", 0, UUID),
                     (ports[0], "localhost", 0, "-", 0, UUID),
                     (ports[1], "127.0.0.1", 0, str(cert), 0, UUID),
                     (ports[1], "127.0.0.1", 0, str(cert), 1, UUID),
                     (ports[1], "127.0.0.1", 0, str(cert), 2, UUID),
                     (ports[0], "127.0.0.1", 0, "-", 3, WRONG_UUID)]
            for port, host, target, ca, mode, credential in cases:
                command = [args.client, "vless", str(port), host, str(sockets[target].getsockname()[1]),
                           credential, "-", ca, str(mode)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                print(result.stdout, end="")
                if result.returncode:
                    log.seek(0)
                    raise RuntimeError(f"client failed ({result.returncode}):\n{result.stderr}\npeer:\n{log.read()}")
            for mode in ["fragment", "version", "partial", "empty"]:
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                sock.listen(8)
                sock.settimeout(0.1)
                sockets.append(sock)
                threading.Thread(target=listen, args=(sock, mode), daemon=True).start()
                result = subprocess.run([args.client, "vless", str(sock.getsockname()[1]), "127.0.0.1",
                                         str(sockets[0].getsockname()[1]), UUID, "-", "-",
                                         "0" if mode == "fragment" else "3"],
                                        capture_output=True, text=True, timeout=15)
                print(result.stdout, end="")
                if result.returncode:
                    raise RuntimeError(f"controlled response {mode} failed: {result.stderr}")
            for thread in threads:
                thread.join(timeout=1)
            if failures or len(received) != 10:
                raise AssertionError(f"peer validation failed: {failures}; completed echoes={len(received)}")
            print("VLESS bare TCP/TLS IPv4/IPv6/domain interop, cancellation and malformed response checks passed")
        finally:
            stop.set()
            for sock in sockets:
                sock.close()
            if peer:
                peer.terminate()
                try:
                    peer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.wait()


if __name__ == "__main__":
    main()
