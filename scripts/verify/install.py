#!/usr/bin/env python3
"""Install, relocate, and build/run independent consumers of Solaris::core."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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


def apple_consumer_options(build):
    """Match an explicitly selected Apple architecture and deployment target."""
    values = {}
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        if line.startswith(("CMAKE_OSX_ARCHITECTURES:", "CMAKE_OSX_DEPLOYMENT_TARGET:")):
            name = line.split(":", 1)[0]
            values[name] = line.split("=", 1)[1]
    return [f"-D{name}={value}" for name, value in values.items() if value]


def executable_path(build, config, name):
    filename = name + (".exe" if os.name == "nt" else "")
    configured = build / config / filename
    return configured if configured.is_file() else build / filename


def configured_modules(build):
    header = (build / "generated/solaris_builtin_modules.h").read_text()
    return {name: value == "1" for name, value in
            re.findall(r"^#define SOLARIS_HAS_([A-Z0-9_]+) ([01])$", header, re.MULTILINE)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--config", default="Debug")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--runtime-proxy", action="store_true")
    parser.add_argument("--runtime-protocols", action="store_true")
    parser.add_argument("--runtime-advanced", action="store_true")
    parser.add_argument("--peer")
    parser.add_argument("--peer-version")
    parser.add_argument("--xray")
    parser.add_argument("--xray-version")
    parser.add_argument("--vless-control")
    parser.add_argument("--encryption-control")
    args = parser.parse_args()
    if (args.runtime_protocols or args.runtime_advanced) and (
            not args.runtime_proxy or not args.peer or not args.peer_version):
        parser.error("protocol acceptance requires the runtime host and fixed peer/version")
    if args.runtime_advanced and (not args.xray or not args.xray_version or not args.vless_control or not args.encryption_control):
        parser.error("advanced protocol acceptance requires the fixed Xray peer/version and same-peer control")
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
        for relative in ["THIRD_PARTY_NOTICES.md", "lock.json", "licenses/libyaml/License",
                         "licenses/libuv/LICENSE", "licenses/libuv/LICENSE-extra"]:
            license_file = relocated / "share/Solaris" / relative
            if not license_file.is_file() or not license_file.stat().st_size:
                raise SystemExit(f"missing installed dependency notice: {relative}")
        source = work / "consumer"
        shutil.copytree(args.source, source)
        if args.runtime_proxy:
            shutil.copy2(Path(args.source).resolve().parent / "sdk/runtime_proxy.c", source / "runtime_proxy.c")
        consumer_build = work / "consumer-build"
        command = [args.cmake, "-S", str(source), "-B", str(consumer_build),
             f"-DCMAKE_PREFIX_PATH={relocated}", f"-DCMAKE_BUILD_TYPE={args.config}",
             f"-DCMAKE_C_COMPILER={args.compiler}",
             "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
             "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"]
        command.extend(apple_consumer_options(build))
        cxx = paired_cxx_compiler(args.compiler)
        if cxx is not None:
            command.append(f"-DCMAKE_CXX_COMPILER={cxx}")
        if args.runtime_proxy:
            command.append("-DSOLARIS_CONSUMER_RUNTIME_PROXY=ON")
        run(command)
        run([args.cmake, "--build", str(consumer_build), "--config", args.config])
        environment = os.environ.copy()
        environment["PATH"] = str(relocated / "bin") + os.pathsep + environment.get("PATH", "")
        ctest = str(Path(args.cmake).with_name("ctest.exe" if os.name == "nt" else "ctest"))
        run([ctest, "--test-dir", str(consumer_build), "--build-config", args.config,
             "--output-on-failure"], env=environment)
        if args.runtime_proxy:
            executable = executable_path(consumer_build, args.config, "runtime_proxy")
            run([sys.executable, str(Path(args.source).resolve().parent / "support/config/runtime_proxy.py"),
                 str(executable)], env=environment)
            run([sys.executable, str(Path(args.source).resolve().parent / "support/config/runtime_control.py"),
                 str(executable)], env=environment)
            acceptance = [sys.executable,
                          str(Path(args.source).resolve().parent / "support/config/runtime_acceptance.py"),
                          str(executable)]
            if not configured_modules(build)["SOCKS5"]:
                acceptance.append("--without-socks")
            run(acceptance, env=environment)
            if args.runtime_protocols:
                run([sys.executable, str(Path(args.source).resolve().parent / "support/config/runtime_protocol.py"),
                     str(executable), "--peer", args.peer, "--version", args.peer_version], env=environment)
            if args.runtime_advanced:
                run([sys.executable, str(Path(args.source).resolve().parent / "support/config/runtime_advanced.py"),
                     str(executable), "--peer", args.peer, "--version", args.peer_version,
                     "--xray", args.xray, "--xray-version", args.xray_version,
                     "--control", args.vless_control,
                     "--encryption-control", args.encryption_control], env=environment)
        # Build the shipped example from the relocated installation, without a
        # repository source fallback or an internal-header include directory.
        installed_example = relocated / "share/Solaris/examples/config-host"
        example_source = work / "standalone-config-host"
        shutil.copytree(installed_example, example_source)
        example_build = work / "standalone-config-host-build"
        example_command = [args.cmake, "-S", str(example_source), "-B", str(example_build),
                           f"-DCMAKE_PREFIX_PATH={relocated}", f"-DCMAKE_BUILD_TYPE={args.config}",
                           f"-DCMAKE_C_COMPILER={args.compiler}",
                           "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
                           "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"]
        example_command.extend(apple_consumer_options(build))
        run(example_command)
        run([args.cmake, "--build", str(example_build), "--config", args.config])
        if args.runtime_proxy:
            run([sys.executable, str(Path(args.source).resolve().parent / "support/config/config_host.py"),
                 str(executable_path(example_build, args.config, "solaris_config_host")),
                 str(example_source / "config_host.yaml"),
                 str(example_source / "config_host_reload.yaml")], env=environment)
        c_only = work / "c-only-build"
        c_command = [args.cmake, "-S", str(source), "-B", str(c_only),
                     f"-DCMAKE_PREFIX_PATH={relocated}", f"-DCMAKE_BUILD_TYPE={args.config}",
                     f"-DCMAKE_C_COMPILER={args.compiler}", "-DSOLARIS_CONSUMER_C_ONLY=ON",
                     "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
                     "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"]
        c_command.extend(apple_consumer_options(build))
        run(c_command)
        run([args.cmake, "--build", str(c_only), "--config", args.config])
        run([ctest, "--test-dir", str(c_only), "--build-config", args.config,
             "--output-on-failure"], env=environment)
        print("Relocated Solaris package consumed successfully by independent C and C++ hosts")


if __name__ == "__main__":
    main()
