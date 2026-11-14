#!/usr/bin/env python3
"""Verify native resolver roles through the independently consumable C host."""
import argparse
from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading

from config_host import Host, Peer as EchoPeer
from runtime_proxy import assert_echo, socks_request, socks_greet
from inbound import exact, read_address
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dns"))
from service import Peer as DnsPeer, parse_question, reply


class Resolver(DnsPeer):
    def __init__(self, allowed_names, tcp=False, absent=()):
        super().__init__("native-roles")
        self.allowed_names = allowed_names
        self.expect_tcp = tcp
        self.absent = absent
        self.names = []

    def response(self, query):
        identifier, end, kind, name = parse_question(query)
        name = name.decode("ascii")
        with self.lock:
            self.names.append(name)
        assert kind == 1 and name in self.allowed_names, (kind, name, self.allowed_names)
        if name in self.absent:
            return struct.pack("!6H", identifier, 0x8183, 1, 0, 0, 0) + query[12:end]
        return reply(query, last=1)

    def __exit__(self, *exc):
        super().__exit__(*exc)
        assert not self.errors, self.errors
        assert self.tcp_queries == (len(self.names) if self.expect_tcp else 0), self.names


@contextmanager
def proxy_endpoint():
    received, errors = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(.1)
        stop = threading.Event()

        def serve():
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(5)
                        assert exact(conn, 3) == b"\x05\x01\x00"
                        conn.sendall(b"\x05\x00")
                        assert exact(conn, 3) == b"\x05\x01\x00"
                        received.append(read_address(conn))
                        conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                        while data := conn.recv(65536):
                            conn.sendall(data)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield listener.getsockname()[1], received
        finally:
            stop.set()
            thread.join(6)
            assert not thread.is_alive() and not errors, errors


def test(binary, proxy):
    with ExitStack() as stack:
        default = stack.enter_context(Resolver({"route.test"}))
        route = stack.enter_context(Resolver({"route.test"}))
        direct = stack.enter_context(Resolver({"direct.test", "shared.test", "node.test", "missing.test", "rollback.test"},
                                                 tcp=True, absent={"missing.test"}))
        replacement = stack.enter_context(Resolver({"shared.test"}))
        bootstrap = stack.enter_context(Resolver(set()))
        node = stack.enter_context(Resolver({"node.test"}))
        origin = EchoPeer()
        stack.callback(origin.socket.close)
        echo_port = origin.port
        proxy_record = proxy_rule = ""
        if proxy:
            server_port, forwarded = stack.enter_context(proxy_endpoint())
            proxy_record = f"[Proxy]\nForward = socks5, node.test, {server_port}\n"
            proxy_rule = "DOMAIN,remote.test,Forward\n"
        profile = (f"[General]\nconfig-version=1\nsocks-listen=127.0.0.1:7891\n"
                   f"{proxy_record}[DNS]\nenabled=true\nuse-system-hosts=false\nipv6=false\n"
                   f"upstream=127.0.0.1:{default.port}\nroute-upstream=127.0.0.1:{route.port}\n"
                   f"direct-upstream=tcp://127.0.0.1:{direct.port}\nproxy-upstream=127.0.0.1:{node.port}\n"
                   f"bootstrap-upstream=127.0.0.1:{bootstrap.port}\n"
                   "[Host]\nlocal.test=127.0.0.1\nalias.test=local.test\n"
                   "[Rule]\nDOMAIN,direct.test,DIRECT\nDOMAIN,shared.test,DIRECT\nDOMAIN,alias.test,DIRECT\nDOMAIN,node.test,DIRECT\nDOMAIN,missing.test,DIRECT\nDOMAIN,rollback.test,DIRECT\n"
                   f"{proxy_rule}IP-CIDR,127.0.0.1/32,DIRECT\nFINAL,REJECT\n")
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="solaris-dns-roles-")))
        path = directory / "roles.conf"
        path.write_text(profile)
        host = Host(binary, path)
        stack.callback(host.abort)
        port = host.ready["listeners"][0]["port"]

        def connect(name, listener):
            conn = socks_greet(listener)
            try:
                socks_request(conn, name, echo_port)
                return conn
            except BaseException:
                conn.close()
                raise

        for name in ("alias.test", "direct.test", "route.test", *(("node.test", "remote.test") if proxy else ())):
            with connect(name, port) as conn:
                assert_echo(conn, name.encode())
        with socks_greet(port) as denied:
            socks_request(denied, "missing.test", echo_port, success=False)
        with connect("shared.test", port) as old:
            assert_echo(old, b"old resolver")
            # The host supplied no system snapshot. A rejected DNS candidate
            # must preserve this publication and its resolver binding.
            path.write_text(profile.replace("use-system-hosts=false", "use-system-hosts=true"))
            host.command("load " + json.dumps(str(path)), expected=-3)
            assert host.command("status")["revision"] == host.ready["revision"]
            with connect("rollback.test", port) as still_active:
                assert_echo(still_active, b"previous resolver after rejected prepare")
            updated_profile = profile.replace(f"direct-upstream=tcp://127.0.0.1:{direct.port}",
                                              f"direct-upstream=127.0.0.1:{replacement.port}")
            path.write_text(updated_profile.replace(f"route-upstream=127.0.0.1:{route.port}\n", ""))
            updated = host.command("load " + json.dumps(str(path)))
            with connect("route.test", updated["listeners"][0]["port"]) as inherited:
                assert_echo(inherited, b"inherited route upstream")
            with connect("shared.test", updated["listeners"][0]["port"]) as fresh:
                assert_echo(fresh, b"new resolver")
            assert_echo(old, b"retained stream")
        host.finish()
        origin.check()
        assert bootstrap.names == [], bootstrap.names
        assert default.names == ["route.test"], default.names
        assert route.names == ["route.test"], route.names
        assert direct.names == (["direct.test", "node.test", "missing.test", "shared.test", "rollback.test"] if proxy else
                                ["direct.test", "missing.test", "shared.test", "rollback.test"]), direct.names
        assert replacement.names == ["shared.test"], replacement.names
        assert node.names == (["node.test"] if proxy else []), node.names
        if proxy:
            assert forwarded == [("remote.test", echo_port)], forwarded
    print("Native DNS roles: host alias, CIDR route, Direct, resolver reload and retained stream passed"
          + ("; proxy-server lookup and original remote destination passed" if proxy else ""))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--socks5-outbound", action="store_true")
    args = parser.parse_args()
    test(args.host, args.socks5_outbound)
