"""Loopback fixtures that reserve each UDP port in both address families."""
import errno
import socket


def udp_pair(family):
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
            primary.bind((hosts[family], 0))
            guard.bind((hosts[other], primary.getsockname()[1]))
            primary.settimeout(0.1)
            return primary, guard
        except OSError as error:
            primary.close(); guard.close()
            if error.errno != errno.EADDRINUSE:
                raise
    raise OSError(errno.EADDRINUSE, "could not reserve a loopback UDP port in both families")
