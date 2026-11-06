#!/usr/bin/env python3
"""Verify a pristine locked BoringSSL tree and prepare our private patch series."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def tree_hash(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if rel.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise ValueError(f"unexpected symlink: {rel}")
        if path.is_file():
            digest.update(rel.as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def prepare(project, source, output):
    lock = json.loads((project / "dependencies/lock.json").read_text())["boringssl"]
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("pristine and patched trees must be separate siblings")
    if tree_hash(source) != lock["source_tree_sha256"]:
        raise ValueError("BoringSSL source differs from the locked pristine tree; "
                         "remove stale FETCHCONTENT_SOURCE_DIR_SOLARIS_BSSL overrides")
    patches = []
    for item in lock["patches"]:
        path = (project / item["path"]).resolve()
        if project not in path.parents or not path.is_file():
            raise ValueError("patch must be a regular file within the project")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"patch checksum mismatch: {item['path']}")
        patches.append(path)
    identity = hashlib.sha256(json.dumps(lock, sort_keys=True).encode()).hexdigest()
    stamp = output.with_name(output.name + ".json")
    if output.exists() and stamp.exists():
        previous = json.loads(stamp.read_text())
        if previous.get("identity") == identity:
            if tree_hash(output) != previous.get("tree"):
                raise ValueError("patched BoringSSL tree was modified; remove the "
                                 "build-local patched tree and reconfigure")
            return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="solaris-bssl-", dir=output.parent) as tmp:
        stage = Path(tmp) / "source"
        shutil.copytree(source, stage, ignore=shutil.ignore_patterns(".git"))
        for patch in patches:
            for mode in ("--check", "--apply"):
                subprocess.run(["git", "apply", "--whitespace=error-all", mode,
                                str(patch)], cwd=stage, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = {"identity": identity, "tree": tree_hash(stage)}
        # Only replace a tree previously created by this recipe. Never remove
        # an arbitrary caller-owned source directory.
        if output.exists():
            if not stamp.exists():
                raise ValueError("refusing to replace an unowned output directory")
            shutil.rmtree(output)
        stage.rename(output)
        stamp.write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        prepare(args.project.resolve(), args.source.resolve(), args.output.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"")
        raise SystemExit(f"BoringSSL preparation failed: {error}\n{detail.decode()}") from error


if __name__ == "__main__":
    main()
