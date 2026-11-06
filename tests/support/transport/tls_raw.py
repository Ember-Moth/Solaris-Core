#!/usr/bin/env python3
"""Independent TLS peer stops its TLS layer at an application boundary."""
import argparse
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading


def pattern(size, offset=0):
    return bytes(((i + offset) * 43 + 69) & 255 for i in range(size))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="solaris-tls-raw-") as directory:
        root = Path(directory)
        key, cert, config = root / "key.pem", root / "cert.pem", root / "cert.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n"
                          "[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", "1", "-config", str(config)], check=True, capture_output=True)
        for version, fragment, cancel in [(ssl.TLSVersion.TLSv1_3, False, False), (ssl.TLSVersion.TLSv1_2, False, False),
                                          (ssl.TLSVersion.TLSv1_3, True, False), (ssl.TLSVersion.TLSv1_3, False, True)]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = version
            context.load_cert_chain(cert, key)
            failures = []
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0)); listener.listen(4); listener.settimeout(5)

                def peer():
                    try:
                        conn, _ = listener.accept()
                        with conn:
                            conn.settimeout(5)
                            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                            secured = context.wrap_bio(incoming, outgoing, server_side=True)
                            pending = bytearray()

                            def flush():
                                if outgoing.pending:
                                    conn.sendall(outgoing.read())

                            def exact(size):
                                while len(pending) < size:
                                    chunk = conn.recv(65536)
                                    if not chunk:
                                        raise EOFError("peer closed")
                                    pending.extend(chunk)
                                value = bytes(pending[:size]); del pending[:size]; return value

                            def record():
                                header = exact(5)
                                incoming.write(header + exact(int.from_bytes(header[3:5], "big")))

                            while True:
                                try:
                                    secured.do_handshake(); flush(); break
                                except ssl.SSLWantReadError:
                                    flush(); record()
                            wrapped = bytearray()
                            while len(wrapped) < 32:
                                try:
                                    wrapped.extend(secured.read(32 - len(wrapped)))
                                except ssl.SSLWantReadError:
                                    flush(); record()
                            if wrapped != pattern(32):
                                raise AssertionError("wrapped upload changed")
                            # One authenticated TLS record leaves 1000 bytes in
                            # SSL_pending after the client's seven-byte read.
                            # Its ciphertext and raw tail share one TCP write.
                            secured.write(b"SWITCH!" + bytes((i * 31 + 19) & 255 for i in range(1000)))
                            reply = outgoing.read() + pattern(20003)
                            if fragment:
                                for i in range(0, len(reply), 13):
                                    conn.sendall(reply[i:i + 13])
                            else:
                                conn.sendall(reply)
                            if exact(65541) != pattern(65541, 32):
                                raise AssertionError("raw upload was wrapped, reordered or corrupted")
                            if pending or conn.recv(1):
                                raise AssertionError("outer close_notify or extra bytes after raw half-close")
                            conn.shutdown(socket.SHUT_WR)
                    except (EOFError, ConnectionError) as exc:
                        if not cancel:
                            failures.append(str(exc))
                    except Exception as exc:
                        failures.append(repr(exc))

                thread = threading.Thread(target=peer, daemon=True); thread.start()
                result = subprocess.run([args.client, str(listener.getsockname()[1]), str(cert), "1" if cancel else "0"],
                                        capture_output=True, text=True, timeout=15)
                thread.join(timeout=6)
                if thread.is_alive() or failures or result.returncode:
                    raise RuntimeError(f"{version}/{fragment}/{cancel}: {failures}\n{result.stdout}\n{result.stderr}")
                print(version.name, "fragment" if fragment else "coalesced", "cancel" if cancel else "handoff", "passed")


if __name__ == "__main__":
    main()
