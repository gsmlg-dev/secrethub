#!/usr/bin/env python3
"""Loopback-only authoritative DNS fixture backed by Pebble's TXT storage.

challtestsrv intentionally serves a recursive-style response without AA. This
test server owns only the two declared fixture zones; it never grants authority
to names outside those zones and never contacts a public DNS service.
"""

import argparse
import select
import socket
import struct
import time

FIXTURE_ZONES = ("example.com", "example.test")
AA = 0x0400
QR = 0x8000


def question(packet):
    """Read one ordinary IN question, rejecting compressed or malformed names."""
    if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("one question required")
    offset = 12
    labels = []
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            raise ValueError("invalid question name")
        labels.append(packet[offset : offset + size].decode("ascii").lower())
        offset += size
    else:
        raise ValueError("unterminated question name")
    if offset + 4 > len(packet):
        raise ValueError("missing question type")
    name = ".".join(labels)
    if len(name) > 253:
        raise ValueError("question name too long")
    kind, dns_class = struct.unpack_from("!HH", packet, offset)
    if dns_class != 1:
        raise ValueError("IN questions only")
    return name, kind, dns_class


def authoritative_response(query, response):
    expected = question(query)
    if len(response) < 12 or response[:2] != query[:2] or question(response) != expected:
        raise ValueError("upstream response mismatch")
    flags = struct.unpack_from("!H", response, 2)[0]
    if not flags & QR:
        raise ValueError("upstream response required")
    name = expected[0]
    owned = any(name == zone or name.endswith("." + zone) for zone in FIXTURE_ZONES)
    flags = (flags & ~AA) | (AA if owned else 0)
    return response[:2] + struct.pack("!H", flags) + response[4:]


def receive_exact(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS TCP read deadline")
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ValueError("incomplete DNS TCP frame")
        data.extend(chunk)
    return bytes(data)


def forward(query, upstream_port, tcp=False):
    question(query)
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as upstream:
        upstream.settimeout(2)
        upstream.connect(("127.0.0.1", upstream_port))
        if tcp:
            upstream.sendall(struct.pack("!H", len(query)) + query)
            deadline = time.monotonic() + 2
            size = struct.unpack("!H", receive_exact(upstream, 2, deadline))[0]
            response = receive_exact(upstream, size, deadline)
        else:
            upstream.send(query)
            response = upstream.recv(65_535)
    return authoritative_response(query, response)


def failure(query):
    # Fail closed without fabricating authoritative answers.
    return query[:2] + struct.pack("!HHHHH", QR | 2, 0, 0, 0, 0)


def serve(listen_port, upstream_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        udp.bind(("127.0.0.1", listen_port))
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", listen_port))
        tcp.listen(16)
        print(f"Authoritative fixture zones: {', '.join(FIXTURE_ZONES)}", flush=True)
        while True:
            for listener in select.select([udp, tcp], [], [])[0]:
                if listener is udp:
                    query, peer = udp.recvfrom(65_535)
                    try:
                        udp.sendto(forward(query, upstream_port), peer)
                    except (OSError, ValueError, UnicodeError):
                        if len(query) >= 12:
                            udp.sendto(failure(query), peer)
                else:
                    connection, _ = tcp.accept()
                    with connection:
                        query = b""
                        try:
                            deadline = time.monotonic() + 2
                            size = struct.unpack("!H", receive_exact(connection, 2, deadline))[0]
                            query = receive_exact(connection, size, deadline)
                            response = forward(query, upstream_port, tcp=True)
                        except (OSError, ValueError, UnicodeError):
                            if len(query) < 12:
                                continue
                            response = failure(query)
                        connection.settimeout(2)
                        try:
                            connection.sendall(struct.pack("!H", len(response)) + response)
                        except OSError:
                            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, default=28054)
    parser.add_argument("--upstream-port", type=int, default=28053)
    args = parser.parse_args()
    serve(args.listen_port, args.upstream_port)
