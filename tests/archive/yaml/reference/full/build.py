#!/usr/bin/env python3
"""Build the fixed full-loader oracle with checked, observation-only overlays."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    pinned = json.loads((here / 'overlay/manifest.json').read_text())
    module = json.loads(subprocess.check_output([args.go, 'mod', 'download', '-json',
        'github.com/Herta-Network/mihomo@' + pinned['version']], cwd=here, text=True))
    assert module['Version'] == pinned['version'], module
    if module.get('Origin', {}).get('Hash'):
        assert module['Origin']['Hash'] == pinned['revision'], module
    assert module['Sum'] == pinned['sum'] and module['GoModSum'] == pinned['go_mod_sum'], module
    subprocess.run([args.go, 'mod', 'verify'], cwd=here, check=True,
                   stdout=subprocess.DEVNULL)
    upstream = Path(module['Dir'])
    for path, digest in pinned['sources'].items():
        assert sha((upstream / path).read_bytes()) == digest, path
    output = args.output.resolve()
    directory = output.parent / (output.name + '-overlay')
    directory.mkdir(parents=True, exist_ok=True)
    # Go forbids overlays below GOMODCACHE. Keep the checksum-verified original
    # cache immutable and use a private build copy plus a private modfile.
    copied = directory / 'upstream'
    if copied.exists():
        for path in [copied, *copied.rglob('*')]:
            if path.is_dir():
                path.chmod(0o755)
        shutil.rmtree(copied)
    shutil.copytree(upstream, copied)
    for path in [copied, *copied.rglob('*')]:
        if path.is_dir():
            path.chmod(0o755)
    upstream = copied
    modfile = directory / 'reference.mod'
    shutil.copyfile(here / 'go.mod', modfile)
    shutil.copyfile(here / 'go.sum', modfile.with_suffix('.sum'))
    subprocess.run([args.go, 'mod', 'edit', '-modfile=' + str(modfile),
                    '-replace=github.com/metacubex/mihomo=' + str(copied)], cwd=here, check=True)
    original = upstream / 'transport/anytls/util/routine.go'
    content = original.read_text()
    anchor = 'func StartRoutine(ctx context.Context, d time.Duration, f func()) {\n'
    assert content.count(anchor) == 1
    patched = content.replace(anchor, anchor + '\tsolarisReferenceObserve(ctx, d)\n', 1)
    target = directory / 'routine.go'
    target.write_text(patched)
    replace = {str(original): str(target)}
    for source, destination in [('observer.go.txt', 'transport/anytls/util/solaris_reference.go'),
                                ('listener.go.txt', 'listener/solaris_reference.go'),
                                ('inbound.go.txt', 'adapter/inbound/solaris_reference.go'),
                                ('tunnel.go.txt', 'tunnel/solaris_reference.go')]:
        replace[str(upstream / destination)] = str(here / 'overlay' / source)
    overlay = directory / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': replace}, indent=2) + '\n')
    environment = dict(os.environ, CGO_ENABLED='0')
    subprocess.run([args.go, 'build', '-mod=readonly', '-modfile=' + str(modfile),
                    '-trimpath', '-overlay=' + str(overlay),
                    '-o', str(output), '.'], cwd=here, env=environment, check=True)
    evidence = dict(pinned)
    evidence['origin_metadata_provided'] = bool(module.get('Origin', {}).get('Hash'))
    evidence['routine_overlay_sha256'] = sha(patched.encode())
    evidence['observer_bridge_sha256'] = {p.name: sha(p.read_bytes()) for p in (here / 'overlay').glob('*.txt')}
    evidence['helper_sha256'] = sha((here / 'main.go').read_bytes())
    output.with_name(output.name + '-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('Built exact full-loader reference ' + pinned['revision'])


if __name__ == '__main__':
    main()
