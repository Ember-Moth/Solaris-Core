#!/usr/bin/env python3
"""Independent raw IPv4/IPv6 TCP peer for the in-memory lwIP stream bridge."""
import ipaddress
import queue
import threading
import struct
import subprocess
import sys
import time


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(source, destination, sport, dport, seq, ack, flags, payload=b""):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    options = b"\x02\x04\x05\x50" if flags & 2 else b""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, ((20 + len(options)) // 4) << 4,
                      flags, 65535, 0, 0) + options + payload
    pseudo = src.packed + dst.packed + (struct.pack("!BBH", 0, 6, len(tcp)) if src.version == 4 else struct.pack("!I3xB", len(tcp), 6))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    if src.version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src.packed, dst.packed)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), 6, 64, src.packed, dst.packed)
    return header + tcp


def decode(wire):
    version = wire[0] >> 4
    if version == 4:
        offset = (wire[0] & 15) * 4
        assert checksum(wire[:offset]) == 0
        assert struct.unpack_from("!H", wire, 2)[0] == len(wire)
        source, destination = wire[12:16], wire[16:20]
        pseudo = source + destination + struct.pack("!BBH", 0, 6, len(wire) - offset)
    else:
        assert version == 6 and wire[6] == 6
        offset = 40
        assert struct.unpack_from("!H", wire, 4)[0] + 40 == len(wire)
        source, destination = wire[8:24], wire[24:40]
        pseudo = source + destination + struct.pack("!I3xB", len(wire) - offset, 6)
    tcp = wire[offset:]
    assert checksum(pseudo + tcp) == 0, "bad emitted TCP checksum"
    sport, dport, seq, ack = struct.unpack_from("!HHII", tcp)
    return str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination)), sport, dport, seq, ack, tcp[13], tcp[(tcp[12] >> 4) * 4:]


class Harness:
    def __init__(self, binary):
        self.process = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.chunks = queue.Queue()
        self.reader = threading.Thread(target=self._read_pipe, daemon=True)
        self.reader.start()
        self.buffer = bytearray()
        self.events = []
        self.history = []

    def _read_pipe(self):
        while True:
            chunk = self.process.stdout.read(65536)
            self.chunks.put(chunk)
            if not chunk:
                return

    def read(self, timeout=5):
        deadline = time.monotonic() + timeout
        while len(self.buffer) < 5 or len(self.buffer) < 5 + struct.unpack_from("!I", self.buffer, 1)[0]:
            remaining = deadline - time.monotonic()
            try:
                chunk = self.chunks.get(timeout=max(0, remaining))
            except queue.Empty:
                raise TimeoutError(f"event timeout; pending {[kind for kind, _ in self.events]}") from None
            if not chunk:
                raise RuntimeError(self.process.stderr.read().decode())
            self.buffer.extend(chunk)
        length = struct.unpack_from("!I", self.buffer, 1)[0]
        event = (chr(self.buffer[0]), bytes(self.buffer[5:5 + length]))
        del self.buffer[:5 + length]
        self.events.append(event)
        self.history.append(event)

    def take(self, kind, predicate=lambda _: True, timeout=5):
        deadline = time.monotonic() + timeout
        while True:
            for i, (candidate, data) in enumerate(self.events):
                if candidate == kind and predicate(data):
                    self.events.pop(i)
                    return data
            self.read(max(0, deadline - time.monotonic()))

    def command(self, kind, data=b"", expected=0):
        self.process.stdin.write(kind.encode() + struct.pack("!I", len(data)) + data)
        self.process.stdin.flush()
        result = self.take("A", lambda data: struct.unpack_from("!I", data)[0] == ord(kind))
        status = struct.unpack_from("!i", result, 4)[0]
        assert status == expected, (kind, status, expected)

    def status(self, kind, token, expected=0):
        event = self.take(kind, lambda data: struct.unpack_from("!I", data)[0] == token)
        assert struct.unpack_from("!i", event, 4)[0] == expected, (kind, token, event)

    def drain(self, timeout=.1):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                self.read(end - time.monotonic())
            except TimeoutError:
                break

    def stop(self):
        self.process.stdin.write(b"T\0\0\0\0")
        self.process.stdin.flush()
        self.take("Z")
        result = self.process.wait(timeout=5)
        errors = self.process.stderr.read().decode()
        assert result == 0 and not errors, errors


class Peer:
    def __init__(self, harness, ipv6=False, sport=40000):
        self.h = harness
        self.source = "fd12::2" if ipv6 else "10.12.0.2"
        self.destination = "2606:4700:4700::1111" if ipv6 else "1.1.1.1"
        self.sport, self.dport = sport, 8443
        self.seq, self.ack = 1000 + sport, 0
        self.received = bytearray()
        self.fin = False

    def send(self, flags, payload=b"", expected=0):
        wire = packet(self.source, self.destination, self.sport, self.dport, self.seq, self.ack, flags, payload)
        self.h.command("P", wire, expected)
        if expected == 0:
            self.seq += len(payload) + bool(flags & 2) + bool(flags & 1)

    def matching(self, wire):
        source, destination, sport, dport, *_ = decode(wire)
        return (source, destination, sport, dport) == (self.destination, self.source, self.dport, self.sport)

    def connect(self, send_syn=True):
        if send_syn:
            self.send(2)
        segment = decode(self.h.take("P", self.matching))
        assert segment[6] & 0x12 == 0x12 and segment[5] == self.seq
        self.ack = segment[4] + 1
        self.send(0x10)
        opened = self.h.take("O")
        self.id, status = struct.unpack("!Ii", opened)
        assert status == 0
        return self

    def receive(self, length, fin=False):
        deadline = time.monotonic() + 10
        while len(self.received) < length or fin and not self.fin:
            segment = decode(self.h.take("P", self.matching, deadline - time.monotonic()))
            seq, flags, payload = segment[4], segment[6], segment[7]
            assert not flags & 4, "unexpected TCP RST"
            if not payload and not flags & 1:
                continue
            if seq == self.ack:
                self.received.extend(payload)
                self.ack += len(payload)
                if flags & 1:
                    self.ack += 1
                    self.fin = True
            else:
                assert seq < self.ack, "unexpected out-of-order output"
            if payload or flags & 1:
                self.send(0x10)
        return bytes(self.received)

    def read(self):
        self.h.command("R", struct.pack("!I", self.id))

    def write(self, payload, token, expected=0):
        self.h.command("W", struct.pack("!II", self.id, token) + payload, expected)

    def shutdown(self, token):
        self.h.command("F", struct.pack("!II", self.id, token))
        self.h.status("W", token)

    def close(self, expected=0):
        self.h.command("C", struct.pack("!I", self.id))
        self.h.status("C", self.id, expected)


def main(binary):
    h = Harness(binary)
    try:
        h.command("N")
        h.command("B", expected=-4)
        h.command("X", expected=-4)
        h.command("G", struct.pack("!I", 3))
        # Both IP families use genuine independent SYN/ACK, payload and FIN.
        for ipv6 in (False, True):
            peer = Peer(h, ipv6, 40000 + int(ipv6)).connect()
            payload = b"paused receive before enabling reads"
            peer.send(0x18, payload)
            h.drain()
            assert not any(kind == "D" and struct.unpack_from("!I", data)[0] == peer.id for kind, data in h.events)
            peer.read()
            actual = h.take("D", lambda data: struct.unpack_from("!I", data)[0] == peer.id)
            assert actual[4:] == payload
            response = bytes((i * 29 + 7) & 255 for i in range(7000))
            peer.write(response, 100 + int(ipv6))
            h.status("W", 100 + int(ipv6))
            if ipv6:
                peer.send(0x11)
                h.status("E", peer.id)
            peer.shutdown(200 + int(ipv6))
            assert peer.receive(len(response), fin=True) == response
            if not ipv6:
                peer.send(0x11)
                h.status("E", peer.id)
            peer.close()
        h.command("G", struct.pack("!I", 1))
        blocked = Peer(h, sport=40050)
        blocked.send(2)
        h.drain(.15)
        assert not any(kind == "P" and blocked.matching(data) for kind, data in h.events)
        h.command("G", struct.pack("!I", 0))
        blocked.connect(False).close()
        h.command("G", struct.pack("!I", 5))
        rejected = Peer(h, sport=40051)
        rejected.send(2)
        synack = decode(h.take("P", rejected.matching))
        rejected.ack = synack[4] + 1
        rejected.send(0x10)
        assert decode(h.take("P", rejected.matching))[6] & 4
        h.drain(.05)
        assert not any(kind == "O" for kind, _ in h.events)
        h.command("G", struct.pack("!I", 6))
        opened_then_closed = Peer(h, sport=40052).connect()
        h.status("C", opened_then_closed.id)
        h.command("G", struct.pack("!I", 0))
        # The relay may close its stream after both half-closes while the
        # TCP tail and FIN are still unacknowledged. Drop their first emission,
        # close the stream, then require retransmission through the retained
        # tuple and ACK it only after observing that retransmission.
        tail = Peer(h, sport=40060).connect()
        tail.read()
        response = b"graceful retransmission tail" * 40
        tail.write(response, 700)
        h.status("W", 700)
        tail.shutdown(701)
        h.drain(.05)
        initial = [decode(data) for kind, data in h.events if kind == "P" and tail.matching(data)]
        assert any(item[7] for item in initial) and any(item[6] & 1 for item in initial)
        h.events = [(kind, data) for kind, data in h.events if kind != "P" or not tail.matching(data)]
        client_fin_seq = tail.seq
        tail.send(0x11)
        h.status("E", tail.id)
        tail.close()
        retransmitted = h.take("P", lambda wire: tail.matching(wire) and bool(decode(wire)[7] or decode(wire)[6] & 1), timeout=8)
        assert not decode(retransmitted)[6] & 4
        h.events.insert(0, ("P", retransmitted))
        assert tail.receive(len(response), fin=True) == response
        # A duplicate FIN in TIME_WAIT still resolves to the original tuple;
        # a new SYN cannot reuse that internal port while its tombstone lives.
        duplicate_fin = packet(tail.source, tail.destination, tail.sport, tail.dport, client_fin_seq, tail.ack, 0x11)
        h.command("P", duplicate_fin)
        ack = decode(h.take("P", lambda wire: tail.matching(wire) and decode(wire)[5] == tail.seq))
        assert ack[6] & 0x10 and not ack[6] & 4
        Peer(h, sport=40060).send(2, expected=-11)
        # No ACK means the lwIP send window remains occupied. The next full
        # request stays pending, the third is rejected and owns no callback.
        peer = Peer(h, sport=40100).connect()
        peer.write(b"a" * 32768, 300)
        h.status("W", 300)
        peer.write(b"b" * 32768, 301)
        peer.write(b"c", 302, -11)
        peer.close()
        h.status("W", 301, -9)
        h.drain()
        assert not any(kind == "W" and struct.unpack_from("!I", data)[0] == 302 for kind, data in h.history)
        # An allocation rejection does not consume a tuple or send data.
        h.command("M", struct.pack("!i", 0))
        failed = Peer(h, sport=40200)
        failed.send(2, expected=-2)
        h.command("M", struct.pack("!i", -1))
        failed.connect()
        h.command("M", struct.pack("!i", 1))
        failed.write(b"no allocation", 400, -2)
        h.command("M", struct.pack("!i", -1))
        failed.close()
        h.command("M", struct.pack("!i", 1))
        pending_allocation = Peer(h, sport=40201)
        pending_allocation.send(2, expected=-2)
        h.command("M", struct.pack("!i", -1))
        h.drain(.05)
        pending_allocation.connect().close()
        # Stack close is a child-channel barrier; admission opens again only
        # after it finishes. Recreate on the same owner and stop with a child.
        pending = Peer(h, sport=40300).connect()
        h.command("S")
        h.status("C", pending.id, -9)
        h.status("S", 0)
        h.command("M", struct.pack("!i", 0))
        h.command("N", expected=-2)
        h.command("M", struct.pack("!i", 1))
        h.command("N", expected=-2)
        h.command("M", struct.pack("!i", -1))
        h.drain(.05)
        h.command("N", struct.pack("!I", 250))
        idle = Peer(h, sport=40301).connect()
        h.status("C", idle.id, -6)
        h.command("S")
        h.status("S", 0)
        h.command("N")
        reentrant = Peer(h, sport=40302).connect()
        h.command("G", struct.pack("!I", 2))
        reentrant.write(b"close in emit", 500)
        h.status("W", 500)
        h.status("C", reentrant.id, -9)
        h.status("S", 0)
        h.command("G", struct.pack("!I", 0))
        h.command("N")
        read_close = Peer(h, sport=40303).connect()
        read_close.read()
        h.command("G", struct.pack("!I", 4))
        read_close.send(0x18, b"close stack from data callback")
        assert h.take("D", lambda data: struct.unpack_from("!I", data)[0] == read_close.id)[4:] == b"close stack from data callback"
        h.status("C", read_close.id, -9)
        h.status("S", 0)
        h.command("G", struct.pack("!I", 0))
        h.command("N")
        for port in range(41000, 41008):
            Peer(h, sport=port).send(2)
        Peer(h, sport=41008).send(2, expected=-11)
        h.command("S")
        h.status("S", 0)
        h.command("N")
        h.command("X", expected=-4)
        final = Peer(h, True, 40400).connect()
        h.stop()
        live = set()
        closed_ids = set()
        for kind, data in h.history:
            if kind == "O":
                identifier = struct.unpack_from("!I", data)[0]
                assert identifier not in live and identifier not in closed_ids
                live.add(identifier)
            elif kind == "C":
                identifier = struct.unpack_from("!I", data)[0]
                assert identifier in live
                live.remove(identifier)
                closed_ids.add(identifier)
            elif kind == "S":
                assert not live, "stack closed before its child streams"
        assert not live
        closes = [struct.unpack("!Ii", data) for kind, data in h.history if kind == "C"]
        assert closes.count((final.id, -9)) == 1
        for token in (100, 101, 200, 201, 300, 301, 500, 700, 701):
            assert sum(kind == "W" and struct.unpack_from("!I", data)[0] == token for kind, data in h.history) == 1
        print("lwIP IPv4/IPv6 TCP handshake, paused reads, payload, both half-close orders, backpressure/output congestion, allocation failure, idle expiry, reentrant emit/close, cancellation, singleton/owner and recreation passed")
    finally:
        if h.process.poll() is None:
            h.process.kill()
            h.process.wait(timeout=5)


if __name__ == "__main__":
    main(sys.argv[1])
