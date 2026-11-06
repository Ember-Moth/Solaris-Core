#!/usr/bin/env python3
"""Keep the independent Go server state alive between C codec fixture phases."""
import argparse
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--control", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="solaris-encryption-codec-") as root:
        subprocess.run([args.control, "prepare", root], check=True, timeout=10)
        subprocess.run([args.client, "emit", root], check=True, timeout=10)
        with subprocess.Popen([args.control, "fixtures", root], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as peer:
            try:
                line = peer.stdout.readline().strip()
                if line != "FULL_READY":
                    raise RuntimeError(f"fixture peer: {line}: {peer.stderr.read()}")
                subprocess.run([args.client, "verify", root], check=True, timeout=20)
                peer.stdin.write("resume\n"); peer.stdin.flush()
                line = peer.stdout.readline().strip()
                if line != "RESUME_READY":
                    raise RuntimeError(f"fixture peer: {line}: {peer.stderr.read()}")
                subprocess.run([args.client, "resumed", root], check=True, timeout=10)
                stdout, stderr = peer.communicate("done\n", timeout=10)
                if peer.returncode:
                    raise RuntimeError(stderr)
                print(stdout, end="")
            finally:
                if peer.poll() is None:
                    peer.kill(); peer.wait()


if __name__ == "__main__":
    main()
