#!/usr/bin/env python3
"""Independent Python/OpenSSL TLS peers, ephemeral certificates, loopback only."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import ssl
import sys
import subprocess
import tempfile
import threading


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from child_process import run as run_child

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL CLI is required for ephemeral test certificates")
    stop = threading.Event()
    listeners = []
    errors = []
    successes = []

    with tempfile.TemporaryDirectory(prefix="solaris-tls-") as directory:
        root = Path(directory)
        contexts = []
        for name in ["trusted", "untrusted"]:
            key, cert = root / f"{name}.key", root / f"{name}.pem"
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, capture_output=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            contexts.append(ctx)

        def connection(conn, mode):
            secured = None
            try:
                conn.settimeout(3)
                if mode == 2:
                    while not stop.is_set():
                        if not conn.recv(65536):
                            break
                    return
                secured = contexts[1 if mode == 1 else 0].wrap_socket(conn, server_side=True)
                if mode == 3:
                    # Deliberately omit close_notify, even though handshake succeeded.
                    socket.close(secured.detach())
                    return
                received = bytearray()
                while True:
                    chunk = secured.recv(4093)
                    if not chunk:
                        break
                    received.extend(chunk)
                    secured.sendall(chunk)
                if received:
                    expected = bytes((i * 37 + 17) & 255 for i in range(196613))
                    if bytes(received) != expected:
                        errors.append("incorrect or incomplete plaintext at peer")
                    else:
                        successes.append(True)
                raw = secured.unwrap()
                raw.close()
            except (ConnectionError, ssl.SSLError, OSError):
                pass  # Intentional certificate failures and cancellation.
            finally:
                if secured:
                    secured.close()
                conn.close()

        def listen(sock, mode):
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                    threading.Thread(target=connection, args=(conn, mode), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        try:
            for mode in range(4):
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                sock.listen(16)
                sock.settimeout(0.1)
                listeners.append(sock)
                threading.Thread(target=listen, args=(sock, mode), daemon=True).start()
            result = run_child([args.client, str(root / "trusted.pem"),
                                     *(str(s.getsockname()[1]) for s in listeners)],
                                    capture_output=True, text=True, timeout=20)
            print(result.stdout, end="")
            if result.returncode:
                raise RuntimeError(f"client failed ({result.returncode}):\n{result.stderr}")
            if errors or len(successes) != 1:
                raise AssertionError(f"peer validation: {errors}, complete transfers={len(successes)}")
            print(f"Independent TLS peer passed ({ssl.OPENSSL_VERSION})")
        finally:
            stop.set()
            for sock in listeners:
                sock.close()


if __name__ == "__main__":
    main()
