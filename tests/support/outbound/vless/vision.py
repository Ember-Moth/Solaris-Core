#!/usr/bin/env python3
"""Vision interop with real TLS inside the proxy and explicit raw transitions."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from loopback import udp_pair

from encryption import keys, UUID, WRONG_UUID, PAYLOAD


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--udp-client", required=True)
    parser.add_argument("--association-client", required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.peer, "version"], text=True).splitlines()[0]
    if args.version.removeprefix("v") not in version:
        raise RuntimeError(version)
    print(version)
    sockets, threads, successes, failures = [], [], [], []
    stop = threading.Event()
    process = None
    with tempfile.TemporaryDirectory(prefix="solaris-vision-") as directory:
        root = Path(directory)
        key, cert, conf = root / "key.pem", root / "cert.pem", root / "cert.cnf"
        conf.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n"
                        "[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", "1", "-config", str(conf)], check=True, capture_output=True)
        inner_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        inner_context.minimum_version = inner_context.maximum_version = ssl.TLSVersion.TLSv1_3
        inner_context.load_cert_chain(cert, key)

        def echo(conn, tls):
            data = bytearray()
            secured = None
            try:
                conn.settimeout(5)
                if tls:
                    secured = inner_context.wrap_socket(conn, server_side=True)
                channel = secured or conn
                while chunk := channel.recv(3011):
                    data.extend(chunk); channel.sendall(chunk)
                if data:
                    if data != PAYLOAD:
                        failures.append(f"echo payload length/integrity {len(data)}")
                    else:
                        successes.append(tls)
                if secured:
                    secured.unwrap().close()
                else:
                    conn.shutdown(socket.SHUT_WR)
            except (ConnectionError, ssl.SSLError, OSError) as exc:
                if data and data != PAYLOAD:
                    failures.append(f"incomplete echo {len(data)}: {exc}")
            finally:
                if secured:
                    secured.close()
                conn.close()

        def listen(sock, tls):
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                    thread = threading.Thread(target=echo, args=(conn, tls), daemon=True)
                    threads.append(thread); thread.start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        def udp_echo(sock):
            while not stop.is_set():
                try:
                    data, peer = sock.recvfrom(65536)
                    if peer[1] == sock.getsockname()[1]:
                        failures.append("loopback UDP source collided with echo port")
                        return
                    sock.sendto(data, peer)
                except socket.timeout:
                    continue
                except OSError:
                    break

        try:
            targets = {}
            for tls in [False, True]:
                for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                    sock = socket.socket(family)
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((address, 0)); sock.listen(32); sock.settimeout(0.1); sockets.append(sock)
                    targets[(tls, address)] = sock.getsockname()[1]
                    threading.Thread(target=listen, args=(sock, tls), daemon=True).start()
            udp_targets = []
            for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                sock, guard = udp_pair(family); sockets.extend((sock, guard))
                udp_targets.append(sock.getsockname()[1]); threading.Thread(target=udp_echo, args=(sock,), daemon=True).start()
            secret, public = keys(args.peer, "x25519")
            cases, inbounds, reservations = [], [], []
            for name, appearance, tls in [("tls13", None, "1.3"), ("encryption-native", "native", None),
                                           ("encryption-xorpub", "xorpub", None), ("encryption-random", "random", None),
                                           ("encryption-over-tls12", "random", "1.2"), ("reject-tls12", None, "1.2")]:
                sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sockets.append(sock); reservations.append(sock)
                port = sock.getsockname()[1]
                decryption = "none" if appearance is None else f"mlkem768x25519plus.{appearance}.600s.100-35-35.{secret}"
                encryption = "none" if appearance is None else f"mlkem768x25519plus.{appearance}.0rtt.100-35-35.{public}"
                inbound = {"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {
                    "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": decryption}, "streamSettings": {"network": "raw"}}
                if tls:
                    inbound["streamSettings"].update({"security": "tls", "tlsSettings": {"minVersion": tls, "maxVersion": tls,
                        "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}})
                inbounds.append(inbound); cases.append((name, port, encryption, str(cert) if tls else "-"))
            config = {"log": {"loglevel": "debug"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom",
                "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}, "settings": {"finalRules": [
                    {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32", "::1/128"], "port": ",".join(map(str, targets.values()))},
                    {"action": "allow", "network": "udp", "ip": ["127.0.0.1/32", "::1/128"], "port": ",".join(map(str, udp_targets))}]}}]}
            path = root / "xray.json"; path.write_text(json.dumps(config))
            for sock in reservations:
                sock.close()
            expected = 0
            with (root / "xray.log").open("w+") as log:
                process = subprocess.Popen([args.peer, "run", "-c", str(path)], stdout=log, stderr=log)
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        log.seek(0); raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", cases[0][1]), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("peer startup timed out")
                        time.sleep(0.01)

                def run(case, inner=False, host="127.0.0.1", rounds=1, mode=0, credential=UUID):
                    nonlocal expected
                    name, port, encryption, ca = case
                    command = [args.client, "vless", str(port), host, str(targets[(inner, "::1" if host == "::1" else "127.0.0.1")]),
                               credential, "-", ca, str(mode), str(rounds), encryption, "xtls-rprx-vision"]
                    if inner:
                        command.append(str(cert))
                    try:
                        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    except subprocess.TimeoutExpired as exc:
                        log.seek(0); raise RuntimeError(f"{name} inner={inner}: {exc.stderr}\n{log.read()[-20000:]}") from exc
                    if result.returncode:
                        log.seek(0); raise RuntimeError(f"{name} inner={inner} mode={mode}: {result.stderr}\n{log.read()[-20000:]}")
                    if mode == 0:
                        expected += rounds * 2
                    print(f"Vision {name}, inner TLS={inner}, {host}, mode={mode}, rounds={rounds}: passed")

                for case in cases[:-1]:
                    run(case)
                    run(case, inner=True, rounds=3)
                    for client in [args.udp_client, args.association_client]:
                        result = subprocess.run([client, "vless", str(case[1]), UUID, "-", *map(str, udp_targets), "6", "localhost",
                                                 "xudp-xray", case[3], case[2], "xtls-rprx-vision"],
                                                capture_output=True, text=True, timeout=20)
                        if result.returncode:
                            log.seek(0); raise RuntimeError(f"Vision XUDP {case[0]}: {result.stderr}\n{log.read()[-20000:]}")
                        print(f"Vision {case[0]}: {result.stdout.strip()}")
                run(cases[0], inner=True, host="::1")
                run(cases[1], inner=True, host="localhost")
                run(cases[0], inner=True, mode=1)
                run(cases[3], inner=True, mode=2)
                run(cases[0], mode=3, credential=WRONG_UUID)
                run(cases[-1], mode=3)
            for thread in threads:
                thread.join(timeout=1)
            if failures or len(successes) != expected:
                raise AssertionError(f"echo validation: {failures}, completed={len(successes)}, expected={expected}")
            print("Vision plaintext/TLS, actual bidirectional raw transitions, TLS/encryption carriers, XUDP/association, and cancellation passed")
        finally:
            stop.set()
            for sock in sockets:
                sock.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


if __name__ == "__main__":
    main()
