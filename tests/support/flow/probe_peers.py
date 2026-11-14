#!/usr/bin/env python3
"""Real HTTP/HTTPS health requests through each enabled outbound family."""
import argparse
import base64
import json
from pathlib import Path
import shutil
import socket
import ssl
import sys
import subprocess
import tempfile
import threading
import time

UUID = "7b4bb031-41b5-4d1d-b062-1ea0cab957c1"


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from child_process import run as run_child
from loopback import tcp_udp_pair
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "inbound/proxy"))
from inbound import exact

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--types", nargs="+", required=True)
    parser.add_argument("--peer")
    parser.add_argument("--version")
    parser.add_argument("--xray")
    parser.add_argument("--xray-version")
    args = parser.parse_args()
    stop = threading.Event()
    sockets, threads, processes, failures, requests = [], [], [], [], []
    expected = 0
    with tempfile.TemporaryDirectory(prefix="solaris-probe-") as directory:
        root = Path(directory)
        key, cert, conf = root / "key.pem", root / "cert.pem", root / "cert.cnf"
        conf.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n"
                        "[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n")
        subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", "1", "-config", str(conf)], check=True, capture_output=True)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls_context.load_cert_chain(cert, key)

        def connection(conn, tls):
            secured = None
            try:
                conn.settimeout(5)
                if tls:
                    secured = tls_context.wrap_socket(conn, server_side=True)
                channel = secured or conn; header = bytearray()
                while b"\r\n\r\n" not in header:
                    data = channel.recv(4096)
                    if not data:
                        raise EOFError("request truncated")
                    header.extend(data)
                    if len(header) > 4096:
                        raise AssertionError("oversized request")
                first = bytes(header).split(b"\r\n", 1)[0]
                if first not in [b"HEAD /ok HTTP/1.1", b"HEAD /fail HTTP/1.1"] or b"\r\nHost: " not in header:
                    raise AssertionError(f"unexpected request: {first!r}")
                requests.append(first)
                status = b"204 No Content" if b" /ok " in first else b"503 Unavailable"
                response = b"HTTP/1.1 103 Early Hints\r\nLink: </test>\r\n\r\nHTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n\r\n"
                for i in range(0, len(response), 3):
                    channel.sendall(response[i:i + 3])
                if secured:
                    try:
                        secured.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass  # Probe closes as soon as the complete header is verified.
                else:
                    conn.shutdown(socket.SHUT_WR)
            except Exception as exc:
                failures.append(repr(exc))
            finally:
                if secured:
                    secured.close()
                conn.close()

        def listen(sock, tls):
            while not stop.is_set():
                try:
                    conn, _ = sock.accept(); thread = threading.Thread(target=connection, args=(conn, tls), daemon=True)
                    threads.append(thread); thread.start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        def launch(executable, config, name, port):
            path = root / f"{name}.json"; path.write_text(json.dumps(config))
            log = (root / f"{name}.log").open("w+")
            process = subprocess.Popen([executable, "run", "-c", str(path)], stdout=log, stderr=log); processes.append((process, log))
            until = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    log.seek(0); raise RuntimeError(log.read())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return
                except OSError:
                    if time.monotonic() >= until:
                        raise RuntimeError("reference peer startup timed out")
                    time.sleep(0.01)

        try:
            targets = {}
            for family, host, tls in [(socket.AF_INET, "127.0.0.1", False), (socket.AF_INET, "127.0.0.1", True), (socket.AF_INET6, "::1", False)]:
                sock = socket.socket(family)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, 0)); sock.listen(64); sock.settimeout(0.1); sockets.append(sock)
                targets[(host, tls)] = sock.getsockname()[1]
                threading.Thread(target=listen, args=(sock, tls), daemon=True).start()

            def run(kind, port=0, credential="-", cipher="-", ca="-", tls=False, host="localhost", failure=0, extra=()):
                nonlocal expected
                target = targets[("::1" if host == "[::1]" else "127.0.0.1", tls)]
                base = f"{'https' if tls else 'http'}://{host}:{target}"
                result = run_child([args.client, kind, str(port), credential, cipher, str(ca), str(cert) if tls else "-",
                                         base + "/ok", base + "/fail", str(failure), *extra], capture_output=True, text=True, timeout=20)
                if result.returncode:
                    logs = []
                    for _, log in processes:
                        log.seek(0); logs.append(log.read())
                    raise RuntimeError(f"{kind} TLS={tls}: {result.stderr}\n" + "\n".join(logs)[-20000:])
                expected += 0 if failure else 6
                print(result.stdout, end="")

            if "direct" in args.types:
                run("direct"); run("direct", tls=True); run("direct", host="[::1]")
            if "block" in args.types:
                run("block", failure=-13)
            inbounds, cases, reservations = [], [], []
            if "vless" in args.types:
                cases += [("vless", UUID, "-", False), ("vless", UUID, "-", True)]
            if "shadowsocks" in args.types:
                for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"]:
                    password = base64.b64encode(b"I" * (16 if "128" in method else 32)).decode() if method.startswith("2022") else "solaris-probe"
                    cases.append(("shadowsocks", password, method, False))
            if "anytls" in args.types:
                cases.append(("anytls", "solaris-probe", "-", True))
            if "socks5" in args.types:
                cases += [("socks5", "-", "-", False), ("socks5", "password", "solaris", False)]
            for kind, credential, cipher, tls in cases:
                sock, udp, guard = tcp_udp_pair(socket.AF_INET)
                sockets.extend((sock, udp, guard)); reservations.extend((sock, udp))
                inbound = {"type": "socks" if kind == "socks5" else kind, "listen": "127.0.0.1", "listen_port": sock.getsockname()[1]}
                if kind == "vless":
                    inbound["users"] = [{"uuid": credential}]
                elif kind == "anytls":
                    inbound["users"] = [{"password": credential}]
                elif kind == "socks5":
                    if cipher != "-":
                        inbound["users"] = [{"username": cipher, "password": credential}]
                else:
                    inbound.update({"method": cipher, "password": credential})
                if tls:
                    inbound["tls"] = {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}
                inbounds.append(inbound)
            if cases:
                version = subprocess.check_output([args.peer, "version"], text=True).splitlines()[0]
                if args.version.removeprefix("v") not in version:
                    raise RuntimeError(version)
                for sock in reservations:
                    sock.close()
                launch(args.peer, {"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}, "sing-box", inbounds[0]["listen_port"])
                for (kind, credential, cipher, outer_tls), inbound in zip(cases, inbounds):
                    run(kind, inbound["listen_port"], credential, cipher, cert if outer_tls else "-", tls=True)
                    if kind == "socks5" and cipher != "-":
                        # An independent client records whether this peer sent the
                        # denial bytes or closed before a complete reply arrived.
                        with socket.create_connection(("127.0.0.1", inbound["listen_port"]), timeout=3) as control:
                            control.sendall(b"\x05\x01\x02")
                            assert exact(control, 2) == b"\x05\x02"
                            control.sendall(b"\x01\x07solaris\x05wrong")
                            try:
                                reply = exact(control, 2)
                            except (EOFError, ConnectionResetError, ConnectionAbortedError):
                                reply = None
                            assert reply is None or (reply[0] == 1 and reply[1] != 0), reply
                            print("SOCKS5 negative control:", "disconnect" if reply is None else "explicit denial", flush=True)
                        run(kind, inbound["listen_port"], "wrong", cipher, failure="auth-denial-or-disconnect")
                        # Verify each exact error on a peer that controls the wire
                        # boundary for all six probes, including both workers.
                        for reply_bytes, status in [(b"\x01\x01", -13), (b"\x01", -8)]:
                            with socket.socket() as listener:
                                listener.bind(("127.0.0.1", 0)); listener.listen(8)
                                listener.settimeout(5)
                                errors = []
                                def deny():
                                    try:
                                        for _ in range(6):
                                            peer_sock, _ = listener.accept()
                                            with peer_sock:
                                                peer_sock.settimeout(3)
                                                assert exact(peer_sock, 3) == b"\x05\x01\x02"
                                                peer_sock.sendall(b"\x05\x02")
                                                assert exact(peer_sock, 15) == b"\x01\x07solaris\x05wrong"
                                                peer_sock.sendall(reply_bytes)
                                                peer_sock.shutdown(socket.SHUT_WR)
                                                assert not peer_sock.recv(1)
                                    except Exception as exc:
                                        errors.append(exc)
                                thread = threading.Thread(target=deny, daemon=True); thread.start()
                                run(kind, listener.getsockname()[1], "wrong", cipher, failure=status)
                                thread.join(5)
                                assert not thread.is_alive() and not errors, errors
            if "vless" in args.types:
                version = subprocess.check_output([args.xray, "version"], text=True).splitlines()[0]
                if args.xray_version.removeprefix("v") not in version:
                    raise RuntimeError(version)
                fields = dict(line.split(": ", 1) for line in subprocess.check_output([args.xray, "x25519"], text=True).splitlines() if ": " in line)
                reservations = [socket.socket(), socket.socket()]
                for sock in reservations:
                    sock.bind(("127.0.0.1", 0)); sockets.append(sock)
                ports = [sock.getsockname()[1] for sock in reservations]
                inbounds = [{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {
                    "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none" if i == 0 else f"mlkem768x25519plus.random.600s.100-35-35.{fields['PrivateKey']}"},
                    "streamSettings": {"network": "raw"}} for i, port in enumerate(ports)]
                inbounds[0]["streamSettings"].update({"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}})
                for sock in reservations:
                    sock.close()
                config = {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}},
                    "settings": {"finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32", "::1/128"], "port": ",".join(map(str, targets.values()))}]}}]}
                launch(args.xray, config, "xray", ports[0])
                run("vless", ports[0], UUID, ca=cert, tls=True, extra=("none", "xtls-rprx-vision"))
                run("vless", ports[1], UUID, tls=True, extra=(f"mlkem768x25519plus.random.0rtt.100-35-35.{fields['Password (PublicKey)']}", "xtls-rprx-vision"))
            for thread in threads:
                thread.join(timeout=1)
            if failures or len(requests) != expected:
                raise AssertionError(f"HTTP peer evidence: failures={failures}, requests={len(requests)}, expected={expected}")
            print("Independent HTTP/HTTPS probes passed for every enabled outbound family")
        finally:
            stop.set()
            for sock in sockets:
                sock.close()
            for process, log in processes:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                log.close()


if __name__ == "__main__":
    main()
