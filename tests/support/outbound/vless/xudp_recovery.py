#!/usr/bin/env python3
"""Pinned Xray: stable UDP source mapping after actual TCP carrier loss."""
import argparse
import json
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from loopback import udp_pair
from encryption import keys

UUID = "7b4bb031-41b5-4d1d-b062-1ea0cab957c1"


def close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


class Bridge:
    def __init__(self, backend):
        self.backend = backend
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.active = []
        self.connections = 0
        self.threads = []
        self.listener_thread = threading.Thread(target=self.listen, daemon=True)
        self.listener_thread.start()

    def listen(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
                upstream = socket.create_connection(("127.0.0.1", self.backend), timeout=2)
                with self.lock:
                    self.connections += 1
                    self.active.append((client, upstream))
                thread = threading.Thread(target=self.relay, args=(client, upstream), daemon=True)
                self.threads.append(thread)
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def relay(self, client, upstream):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([client, upstream], [], [], 0.1)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            close_socket(client)
            close_socket(upstream)
            with self.lock:
                if (client, upstream) in self.active:
                    self.active.remove((client, upstream))

    def drop(self):
        with self.lock:
            active = list(self.active)
        for pair in active:
            for sock in pair:
                close_socket(sock)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.drop()
        self.listener_thread.join(timeout=2)
        for thread in self.threads:
            thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--xray", required=True)
    parser.add_argument("--xray-version", required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.xray, "version"], text=True).splitlines()[0]
    if args.xray_version.removeprefix("v") not in version:
        raise RuntimeError(version)
    print(version, flush=True)
    udp, guard = udp_pair(socket.AF_INET)
    stop = threading.Event()
    current = {"bridge": None, "observations": []}
    failures = []
    timers = []

    def echo():
        while not stop.is_set():
            try:
                data, source = udp.recvfrom(65536)
                bridge = current["bridge"]
                if bridge is None or len(data) != 16:
                    failures.append("unexpected application datagram")
                    continue
                current["observations"].append((bytes(data), source))
                udp.sendto(struct.pack("!H", source[1]) + data, source)
                if data[1] < 3:
                    # Let the response traverse every protocol filter before
                    # causing an actual transport EOF on both bridge ends.
                    timer = threading.Timer(0.12, bridge.drop)
                    timers.append(timer)
                    timer.start()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    process = None
    bridge = None
    reservations = []
    with tempfile.TemporaryDirectory(prefix="solaris-xudp-recovery-") as directory:
        root = Path(directory)
        key, cert = root / "key.pem", root / "cert.pem"
        subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
        secret, public = keys(args.xray, "x25519")
        cases, inbounds = [], []
        combinations = [("plain", None, False, False), ("tls", None, True, False),
                        ("vision-tls", None, True, True)]
        for appearance in ("native", "xorpub", "random"):
            combinations.extend([(f"encryption-{appearance}", appearance, False, False),
                                 (f"vision-{appearance}", appearance, False, True)])
        combinations.extend([("encryption-tls", "random", True, False),
                             ("vision-encryption-tls", "random", True, True)])
        for name, appearance, tls, vision in combinations:
            reservation = socket.socket()
            reservation.bind(("127.0.0.1", 0))
            reservations.append(reservation)
            port = reservation.getsockname()[1]
            decryption = "none" if appearance is None else f"mlkem768x25519plus.{appearance}.600s.100-35-35.{secret}"
            encryption = "none" if appearance is None else f"mlkem768x25519plus.{appearance}.0rtt.100-35-35.{public}"
            user = {"id": UUID}
            if vision:
                user["flow"] = "xtls-rprx-vision"
            inbound = {"listen": "127.0.0.1", "port": port, "protocol": "vless",
                       "settings": {"clients": [user], "decryption": decryption}, "streamSettings": {"network": "raw"}}
            if tls:
                inbound["streamSettings"].update({"security": "tls", "tlsSettings": {
                    "minVersion": "1.3", "maxVersion": "1.3", "certificates": [
                        {"certificateFile": str(cert), "keyFile": str(key)}]}})
            inbounds.append(inbound)
            cases.append((name, port, encryption, str(cert) if tls else "-", "xtls-rprx-vision" if vision else "-"))
        config = {"log": {"loglevel": "debug"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom",
                  "settings": {"finalRules": [{"action": "allow", "network": "udp", "ip": ["127.0.0.1/32"],
                                "port": str(udp.getsockname()[1])}]}}]}
        path = root / "xray.json"
        path.write_text(json.dumps(config))
        for reservation in reservations:
            reservation.close()
        try:
            with (root / "xray.log").open("w+") as log:
                process = subprocess.Popen([args.xray, "run", "-c", str(path)], stdout=log, stderr=log)
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", cases[0][1]), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError("Xray startup timed out")
                        time.sleep(0.01)
                mappings = set()
                for name, port, encryption, ca, flow in cases:
                    for worker in (0, 1):
                        bridge = Bridge(port)
                        current.update(bridge=bridge, observations=[])
                        try:
                            result = subprocess.run([args.client, str(bridge.port), str(udp.getsockname()[1]),
                                                     ca, encryption, flow, str(worker)], text=True, capture_output=True, timeout=10)
                            observations = current["observations"]
                            if result.returncode or len(observations) != 4 or bridge.connections != 4:
                                log.seek(0)
                                raise RuntimeError(f"{name}/{worker}: rc={result.returncode} carriers={bridge.connections} "
                                                   f"observations={observations}\n{result.stdout}\n{result.stderr}\n{log.read()}")
                            source_ports = {source[1] for _, source in observations}
                            if len(source_ports) != 1 or source_ports & mappings:
                                raise AssertionError("GlobalID mapping was lost or reused across logical channels")
                            mappings |= source_ports
                            if [data[1] for data, _ in observations] != list(range(4)):
                                raise AssertionError("accepted data was replayed or reordered")
                            print(name, result.stdout.strip(), "carriers=4", flush=True)
                        finally:
                            bridge.close()
                            bridge = None
                            current["bridge"] = None
                log.seek(0)
                hits = log.read().count("XUDP hit")
                if hits != len(cases) * 2 * 3:
                    raise AssertionError(f"expected Xray migration hits, got {hits}")
                if failures:
                    raise AssertionError(failures)
                print(f"XUDP recovery: {len(cases) * 2} channels, {hits} migrations, stable UDP mappings, no replay; passed")
        finally:
            if bridge is not None:
                bridge.close()
            if process is not None:
                process.terminate()
                process.wait(timeout=5)
            stop.set()
            udp.close()
            guard.close()
            for timer in timers:
                timer.join(timeout=1)
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
