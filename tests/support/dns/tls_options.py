#!/usr/bin/env python3
"""ALPN option ownership and rejected TLS cleanup against independent peers."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile

from dot import TLSPeer, certificates, server_context


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    count = 0
    with tempfile.TemporaryDirectory(prefix='solaris-alpn-') as temporary:
        (cert, key), _ = certificates(Path(temporary))
        h2 = server_context(cert, key, ['h2', 'http/1.1'])
        absent = server_context(cert, key, [])
        for family in (socket.AF_INET, socket.AF_INET6):
            for mode, expected, context in [('owned', 0, h2), ('legacy', 0, h2), ('optional', 0, absent),
                                            ('required', -3, absent), ('deny', -13, h2), ('expired', -6, h2),
                                            ('parent_closed', -5, h2), ('invalid_zero', -1, h2),
                                            ('invalid_truncated', -1, h2), ('invalid_oversize', -1, h2),
                                            ('invalid_null', -1, h2), ('invalid_required', -1, h2)]:
                with TLSPeer(family, mode, context) as peer:
                    result = subprocess.run([str(args.binary.resolve()), peer.host, str(peer.port), str(cert), mode],
                                            capture_output=True, text=True, timeout=5)
                    assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
                    value = json.loads(result.stdout)
                    assert value['status'] == expected and value['opens'] == value['closes'], (mode, value)
                    if mode in ('owned', 'legacy', 'optional', 'required'):
                        assert value['opens'] == 1, (mode, value)
                        if mode == 'owned':
                            assert value['alpn_length'] == 2, value
                    else:
                        assert value['opens'] == 0, (mode, value)
                        peer.fence_requested.set(); assert peer.fence_done.wait(2)
                        assert peer.tcp_connections == 0, (mode, value)
                assert not peer.errors, (mode, peer.errors)
                count += 1
    print(f'{count} TLS ALPN/parent contracts passed: owned offers/identity/trust, selected bytes, no-offer legacy, strict requirement and rejected native cleanup')


if __name__ == '__main__':
    main()
