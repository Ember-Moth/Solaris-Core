#!/usr/bin/env python3
"""Exercise the private TLS seams against pinned independent protocol servers."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--seed-dir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="solaris-tls-profiles-") as temp:
        root = Path(temp); cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        with (root / "peer.log").open("w+") as log:
            peer = subprocess.Popen([args.peer, str(cert), str(key)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
            try:
                line = peer.stdout.readline()
                if not line:
                    log.seek(0); raise RuntimeError(f"peer failed to start: {log.read()}")
                endpoints = json.loads(line)
                count = 0

                def run(kind, endpoint, variant="ok", read="-", write="-", expected="full", action="-"):
                    nonlocal count
                    command = [args.client, kind, variant, str(endpoints[endpoint]), str(cert),
                               str(root / read) if read != "-" else "-", str(root / write) if write != "-" else "-",
                               action, expected, endpoints["reality_public_key"]]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    if result.returncode:
                        log.seek(0)
                        raise RuntimeError(f"{kind}/{endpoint}/{variant}/{expected}: {result.stdout}\n{result.stderr}\npeer:\n{log.read()[-8000:]}")
                    print(result.stdout, end="", flush=True); count += 1

                run("ordinary", "ordinary", write="ordinary.session")
                run("ordinary", "ordinary_bad_signature", expected="reject")
                run("jls", "jls", write="jls.session")
                run("jls", "jls", read="jls.session", expected="resume")
                run("jls", "jls", variant="copy", read="jls.session", expected="resume")
                run("jls", "jls", variant="generation2", read="jls.session")
                run("jls", "jls", variant="other", read="jls.session")
                run("jls", "jls", variant="name2", read="jls.session")
                run("jls", "jls", variant="localname", read="ordinary.session", write="jls-local.session")
                run("ordinary", "ordinary", read="jls-local.session")
                run("jls", "jls", variant="shedding", write="shed.session")
                run("jls", "jls", read="shed.session", expected="resume")
                run("jls", "jls", action="clear")
                for endpoint, variant in [("jls", "wrong"), ("jls", "reject-peer"), ("jls", "tls12"),
                                          ("jls_bad_hello", "ok"), ("jls_empty_signature", "ok"), ("ordinary", "ok")]:
                    run("jls", endpoint, variant=variant, expected="reject")
                run("jls", "jls_bad_signature")
                run("jls", "jls_bad_finished", variant="bad-finished", expected="reject")
                run("jls", "jls_bad_algorithm", variant="bad-algorithm", expected="reject")
                session = bytearray((root / "jls.session").read_bytes())
                marker = b"\xbf\x64\x22\x04\x20"  # Versioned private ASN.1 binding, 32 octets.
                if session.count(marker) != 1:
                    raise AssertionError("missing or duplicate session authentication binding")
                offset = session.index(marker); session[offset + len(marker)] ^= 1
                (root / "wrong-binding.session").write_bytes(session)
                run("jls", "jls", read="wrong-binding.session")
                session[offset + 4] = 31
                (root / "malformed.session").write_bytes(session)
                run("jls", "jls", read="malformed.session", expected="bad-session")
                for endpoint in ["restls13", "restls12_x25519", "restls12_p256", "restls12_p384"]:
                    kind = "restls13" if endpoint == "restls13" else "restls12"
                    run(kind, endpoint, write=endpoint + ".session")
                    run(kind, endpoint, read=endpoint + ".session", expected="resume")
                    run(kind, endpoint, variant="wrong", expected="reject")
                    run(kind, endpoint, variant="wrong-name", expected="reject")
                    run(kind, endpoint, variant="fallback", expected="fallback")
                run("shadowtls3", "shadowtls3")
                run("shadowtls3", "shadowtls3", variant="wrong", expected="reject")
                run("shadowtls3", "shadowtls3", variant="wrong-name", expected="reject")
                run("reality", "reality")
                run("reality", "reality", variant="hybrid")
                for variant in ["wrong", "bad-short", "expired", "no-ed"]:
                    run("reality", "reality", variant=variant, expected="reject")
                if args.seed_dir:
                    args.seed_dir.mkdir(parents=True, exist_ok=True)
                    for session in root.glob("*.session"):
                        # All tickets belong to this synthetic loopback fixture.
                        (args.seed_dir / session.name).write_bytes(session.read_bytes())
                print(f"{count} independent TLS profile scenarios passed")
            finally:
                peer.terminate()
                try:
                    peer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill(); peer.wait()


if __name__ == "__main__":
    main()
