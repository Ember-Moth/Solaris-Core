#!/usr/bin/env python3
"""Keep independent SS response seeds when request/EIH fixtures are present."""
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="solaris-seed-contract-") as directory:
    output = Path(directory)
    generator = Path(__file__).resolve().parents[2] / "fuzz/seeds.py"
    subprocess.run([sys.executable, str(generator), str(output), "--ss-control", sys.argv[1]],
                   check=True, timeout=30)
    streams = list(output.glob("07-*-stream-*"))
    packets = list(output.glob("08-*-packet-*"))
    assert len(streams) == 60 and len(packets) == 114, (len(streams), len(packets))
    for kind, files, per_method in ((7, streams, 10), (8, packets, 19)):
        for method in range(6):
            selected = [path for path in files if path.read_bytes()[:3] == bytes([kind, method, 0])]
            assert len(selected) == per_method, (kind, method, len(selected))
    assert not list(output.glob("*-request-*")), "server request fixtures must not feed client response decoders"
print("SS seed generation: all 174 response fixtures preserved; request fixtures kept separate")
