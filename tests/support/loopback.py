"""Loopback fixtures that reserve each UDP port in both address families."""
import errno
import random
import socket


def unavailable_port(error):
    # Winsock also returns WSAEACCES for exclusive/excluded ports when a
    # candidate allocated for one transport is bound by another.
    return error.errno == errno.EADDRINUSE or getattr(error, "winerror", None) == 10013


def udp_pair(family, port=0):
    """Return (echo socket, other-family reservation), both bound to loopback.

    On Darwin, a dual-stack ephemeral bind can overlap a specific IPv4 bind.
    A peer then receives no response, and an echo can send to itself. Reserving
    the same port in both families prevents this fixture-induced collision.
    The reservation is never read; callers must close both sockets.
    """
    if family not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError("expected IPv4 or IPv6")
    other = socket.AF_INET6 if family == socket.AF_INET else socket.AF_INET
    hosts = {socket.AF_INET: "127.0.0.1", socket.AF_INET6: "::1"}
    for _ in range(32):
        primary, guard = socket.socket(family, socket.SOCK_DGRAM), socket.socket(other, socket.SOCK_DGRAM)
        try:
            for sock in (primary, guard):
                if sock.family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            primary.bind((hosts[family], port))
            guard.bind((hosts[other], primary.getsockname()[1]))
            primary.settimeout(0.1)
            return primary, guard
        except OSError as error:
            primary.close(); guard.close()
            if port or not unavailable_port(error):
                raise
    raise OSError(errno.EADDRINUSE, "could not reserve a loopback UDP port in both families")


def tcp_udp_pair(family):
    """Reserve one loopback port for TCP, UDP and the other UDP family."""
    hosts = {socket.AF_INET: "127.0.0.1", socket.AF_INET6: "::1"}
    for attempt in range(32):
        tcp = socket.socket(family, socket.SOCK_STREAM)
        try:
            if family == socket.AF_INET6:
                tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            # Winsock may allocate consecutive ephemeral UDP ports inside an
            # entire excluded TCP range. Start with a TCP-eligible port, and
            # spread retries across the dynamic range if UDP cannot use it.
            candidate = 0 if attempt == 0 else random.randrange(49152, 65536)
            tcp.bind((hosts[family], candidate))
            udp, guard = udp_pair(family, tcp.getsockname()[1])
            return tcp, udp, guard
        except OSError as error:
            tcp.close()
            if not unavailable_port(error):
                raise
    raise OSError(errno.EADDRINUSE, "could not reserve matching loopback TCP/UDP ports")
