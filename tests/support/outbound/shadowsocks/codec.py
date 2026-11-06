#!/usr/bin/env python3
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="solaris-ss-codec-") as directory:
    subprocess.run([sys.argv[1], "fixtures", directory], check=True, timeout=10)
    subprocess.run([sys.argv[2], directory], check=True, timeout=15)
