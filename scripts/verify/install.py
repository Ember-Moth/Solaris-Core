#!/usr/bin/env python3
"""Install, relocate, and build/run independent consumers of Solaris::core."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(command, env=None):
    subprocess.run(command, check=True, env=env)


def paired_cxx_compiler(compiler):
    """Keep sanitizer runtimes from two unrelated Clang installs out of one host."""
    path = Path(compiler)
    name = path.name
    if name.lower() in {"cl.exe", "clang-cl.exe", "clang-cl"}:
        return str(path)
    for pattern, replacement in [(r"clang(?=(-[\d.]+)?(?:\.exe)?$)", "clang++"),
                                  (r"gcc(?=(-[\d.]+)?(?:\.exe)?$)", "g++")]:
        candidate = path.with_name(re.sub(pattern, replacement, name))
        if candidate != path and candidate.is_file():
            return str(candidate)
    if name == "cc" and path.with_name("c++").is_file():
        return str(path.with_name("c++"))
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--config", default="Debug")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--compiler", required=True)
    args = parser.parse_args()
    build = Path(args.build).resolve()
    manifest = json.loads((Path(__file__).resolve().parents[2] / "modules/builtin.json").read_text())
    with tempfile.TemporaryDirectory(prefix="solaris-sdk-consumer-", dir=build) as directory:
        work = Path(directory)
        original = work / "install-original"
        relocated = work / "relocated"
        run([args.cmake, "--install", str(build), "--config", args.config,
             "--prefix", str(original)])
        original.rename(relocated)
        expected = {Path(header).relative_to("include").as_posix()
                    for header in manifest["public_headers"]}
        actual = {path.relative_to(relocated / "include").as_posix()
                  for path in (relocated / "include").rglob("*") if path.is_file()}
        if expected != actual:
            raise SystemExit(f"unexpected installed headers: expected={expected}, actual={actual}")
        source = work / "consumer"
        shutil.copytree(args.source, source)
        consumer_build = work / "consumer-build"
        command = [args.cmake, "-S", str(source), "-B", str(consumer_build),
             f"-DCMAKE_PREFIX_PATH={relocated}", f"-DCMAKE_BUILD_TYPE={args.config}",
             f"-DCMAKE_C_COMPILER={args.compiler}",
             "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
             "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"]
        cxx = paired_cxx_compiler(args.compiler)
        if cxx is not None:
            command.append(f"-DCMAKE_CXX_COMPILER={cxx}")
        run(command)
        run([args.cmake, "--build", str(consumer_build), "--config", args.config])
        environment = os.environ.copy()
        environment["PATH"] = str(relocated / "bin") + os.pathsep + environment.get("PATH", "")
        ctest = str(Path(args.cmake).with_name("ctest.exe" if os.name == "nt" else "ctest"))
        run([ctest, "--test-dir", str(consumer_build), "--build-config", args.config,
             "--output-on-failure"], env=environment)
        c_only = work / "c-only-build"
        c_command = [args.cmake, "-S", str(source), "-B", str(c_only),
                     f"-DCMAKE_PREFIX_PATH={relocated}", f"-DCMAKE_BUILD_TYPE={args.config}",
                     f"-DCMAKE_C_COMPILER={args.compiler}", "-DSOLARIS_CONSUMER_C_ONLY=ON",
                     "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
                     "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"]
        run(c_command)
        run([args.cmake, "--build", str(c_only), "--config", args.config])
        run([ctest, "--test-dir", str(c_only), "--build-config", args.config,
             "--output-on-failure"], env=environment)
        print("Relocated Solaris package consumed successfully by independent C and C++ hosts")


if __name__ == "__main__":
    main()
