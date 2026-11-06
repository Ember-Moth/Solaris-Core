#!/usr/bin/env python3
"""VLESS encryption against the pinned, independently built Xray peer."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from loopback import udp_pair

UUID = "7b4bb031-41b5-4d1d-b062-1ea0cab957c1"
WRONG_UUID = "e003355b-2523-4e85-9567-345bdbe7e506"
PAYLOAD = bytes((i * 17 + 29) & 255 for i in range(65541))


def keys(peer, kind):
    result = subprocess.check_output([peer, kind], text=True)
    fields = dict(line.split(": ", 1) for line in result.splitlines() if ": " in line)
    if kind == "x25519":
        return fields["PrivateKey"], fields["Password (PublicKey)"]
    return fields["Seed"], fields["Client"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--udp-client")
    parser.add_argument("--association-client")
    parser.add_argument("--only-udp", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--control")
    parser.add_argument("--control-rounds", type=int, default=1)
    args = parser.parse_args()
    version = subprocess.check_output([args.peer, "version"], text=True).splitlines()[0]
    if args.version.removeprefix("v") not in version:
        raise RuntimeError(f"wrong Xray version: {version}")
    print(version)
    stop = threading.Event()
    sockets, threads, completed, failures, observations = [], [], [], [], []
    process = None

    def echo(conn):
        data = bytearray()
        try:
            with conn:
                conn.settimeout(5)
                while chunk := conn.recv(4093):
                    data.extend(chunk)
                    conn.sendall(chunk)
                conn.shutdown(socket.SHUT_WR)
                if data:
                    if data != PAYLOAD:
                        failures.append(f"payload length/integrity: {len(data)}")
                    else:
                        completed.append(True)
        except (ConnectionError, OSError) as exc:
            if data:
                failures.append(f"incomplete echo: {len(data)}: {exc}")

    def listen(sock):
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                thread = threading.Thread(target=echo, args=(conn,), daemon=True)
                threads.append(thread)
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def udp_echo(sock):
        while not stop.is_set():
            try:
                payload, source = sock.recvfrom(65536)
                if source[1] == sock.getsockname()[1]:
                    failures.append("loopback UDP source collided with echo port")
                    return
                observations.append((sock.getsockname()[1], source, len(payload), payload[0] if payload else None))
                sock.sendto(payload, source)
            except socket.timeout:
                continue
            except OSError:
                break

    with tempfile.TemporaryDirectory(prefix="solaris-encryption-") as directory:
        root = Path(directory)
        try:
            for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                sock = socket.socket(family)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, 0)); sock.listen(32); sock.settimeout(0.1); sockets.append(sock)
                threading.Thread(target=listen, args=(sock,), daemon=True).start()
            targets = [s.getsockname()[1] for s in sockets]
            udp_targets = []
            for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                sock, guard = udp_pair(family); sockets.extend((sock, guard))
                udp_targets.append(sock.getsockname()[1])
                threading.Thread(target=udp_echo, args=(sock,), daemon=True).start()
            key, cert = root / "tls.key", root / "tls.pem"
            openssl = shutil.which("openssl")
            if not openssl:
                raise RuntimeError("OpenSSL CLI required")
            certificate_config = root / "certificate.cnf"
            certificate_config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                                          "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "1", "-config", str(certificate_config)], check=True, capture_output=True)
            xkey, kemkey, relaykey = keys(args.peer, "x25519"), keys(args.peer, "mlkem768"), keys(args.peer, "x25519")
            configurations = []
            inbounds = []
            reservations = []
            for appearance in ["native", "xorpub", "random"]:
                for name, chain in [("x25519", [xkey]), ("mlkem768", [kemkey]), ("relay", [relaykey, kemkey, xkey])]:
                    reservation = socket.socket(); reservation.bind(("127.0.0.1", 0)); sockets.append(reservation)
                    reservations.append(reservation)
                    port = reservation.getsockname()[1]
                    decryption = f"mlkem768x25519plus.{appearance}.600s.100-35-35." + ".".join(k[0] for k in chain)
                    encryption = f"mlkem768x25519plus.{appearance}.{{rtt}}.100-35-35.100-5-5.100-37-37." + ".".join(k[1] for k in chain)
                    inbound = {"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {
                        "clients": [{"id": UUID}], "decryption": decryption}, "streamSettings": {"network": "raw"}}
                    configurations.append((port, encryption, "-", appearance, name))
                    inbounds.append(inbound)
            reservation = socket.socket(); reservation.bind(("127.0.0.1", 0)); sockets.append(reservation)
            reservations.append(reservation)
            port = reservation.getsockname()[1]
            inbounds.append({"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {
                "clients": [{"id": UUID}], "decryption": f"mlkem768x25519plus.random.600s.{xkey[0]}"},
                "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {
                    "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}}})
            configurations.append((port, f"mlkem768x25519plus.random.{{rtt}}.{xkey[1]}", str(cert), "random", "TLS"))
            config = {"log": {"loglevel": "debug" if args.only_udp else "warning"}, "inbounds": inbounds,
                      "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}},
                                     "settings": {"finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32", "::1/128"],
                                                                  "port": ",".join(map(str, targets))},
                                                                 {"action": "allow", "network": "udp", "ip": ["127.0.0.1/32", "::1/128"],
                                                                  "port": ",".join(map(str, udp_targets))}]}}]}
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
                        with socket.create_connection(("127.0.0.1", configurations[0][0]), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Xray startup timeout")
                        time.sleep(0.01)

                def run(item, rtt="1rtt", rounds=1, host="127.0.0.1", mode=0, credential=UUID):
                    nonlocal expected
                    port, encryption, ca, appearance, name = item
                    target = targets[1 if host == "::1" else 0]
                    command = [args.client, "vless", str(port), host, str(target), credential, "-", ca,
                               str(mode), str(rounds), encryption.format(rtt=rtt)]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f"{appearance}/{name}/{rtt}/{host}/mode{mode}: {result.stderr}\npeer:\n{log.read()}")
                    if mode == 0:
                        expected += rounds * 2
                    print(f"{appearance}/{name}/{rtt}/{host}/mode{mode}: {rounds} rounds, two workers passed")

                if not args.only_udp:
                    for item in configurations:
                        run(item)
                        run(item, rtt="0rtt", rounds=3)
                    run(configurations[0], host="::1")
                    run(configurations[0], host="localhost")
                    run(configurations[-1], mode=1)
                    run(configurations[-1], mode=2)
                    run(configurations[0], mode=3, credential=WRONG_UUID)
                    wrong = list(configurations[0]); wrong[1] = wrong[1].replace(xkey[1], relaykey[1])
                    run(wrong, mode=3)
                selected = [configurations[i] for i in [0, 3, 6, 9]]

                def control(item, rounds):
                    port, encryption, ca, _, _ = item
                    command = [args.control, "probe", f"127.0.0.1:{port}", encryption.format(rtt="0rtt"), ca,
                               f"127.0.0.1:{udp_targets[0]}", f"127.0.0.1:{udp_targets[1]}", f"[::1]:{udp_targets[2]}", str(rounds)]
                    return subprocess.run(command, capture_output=True, text=True, timeout=max(20, rounds * 2))

                if args.control:
                    for item in selected:
                        result = control(item, args.control_rounds)
                        if result.returncode:
                            log.seek(0)
                            raise RuntimeError(f"independent same-peer client failed: {result.stderr}\n{log.read()[-20000:]}")
                        print(result.stdout, end="")
                for item in selected * args.repeat:
                    port, encryption, ca, appearance, name = item
                    for client in [args.udp_client, args.association_client]:
                        if client is None:
                            continue
                        before = len(observations)
                        try:
                            result = subprocess.run([client, "vless", str(port), UUID, "-", *map(str, udp_targets),
                                                     "6", "localhost", "xudp-xray", ca, encryption.format(rtt="0rtt")],
                                                    capture_output=True, text=True, timeout=20,
                                                    env={**os.environ, **({"SOLARIS_TEST_TRACE": "1"} if args.trace else {})})
                        except subprocess.TimeoutExpired as exc:
                            failed_observations = observations[before:].copy()
                            log.seek(0); failed_log = log.read()[-20000:]
                            control_result = control(item, 20) if args.control else None
                            raise RuntimeError(f"XUDP timeout {appearance}/{name}: {exc.stderr}\nUDP observations: {failed_observations}\n"
                                               f"same-peer control: {control_result}\npeer before control:\n{failed_log}") from exc
                        if result.returncode:
                            log.seek(0)
                            raise RuntimeError(f"encryption XUDP {appearance}/{name}: {result.stderr}\n{log.read()}")
                        print(f"{appearance}/{name}: {result.stdout.strip()}")
            for thread in threads:
                thread.join(timeout=1)
            if failures or len(completed) != expected:
                raise AssertionError(f"echo validation: {failures}, completed={len(completed)}, expected={expected}")
            print("VLESS encryption UDP/association repetitions passed" if args.only_udp else
                  "VLESS encryption: all appearances, X25519/ML-KEM/relay authentication, resumption, TLS, dual-stack and cancellation passed")
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
