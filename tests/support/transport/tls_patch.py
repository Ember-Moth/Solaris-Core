#!/usr/bin/env python3
"""Create an ephemeral trust root for the private TLS patch contract."""
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="solaris-tls-patch-") as tmp:
    cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    subprocess.run([sys.argv[1], str(cert), str(key)], check=True)
