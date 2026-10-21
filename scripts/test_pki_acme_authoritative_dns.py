import struct
import pathlib
import select
import socket
import subprocess
import sys
import threading
import unittest

from pki_acme_authoritative_dns import AA, QR, authoritative_response, question


def query(name):
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 42, 0x0100, 1, 0, 0, 0) + encoded + b"\0\0\x10\0\x01"


def reply(packet, flags=QR | 0x0080):
    return packet[:2] + struct.pack("!H", flags) + packet[4:]


class AuthoritativeFixtureTest(unittest.TestCase):
    def test_loopback_tcp_and_udp_resolve_the_same_authoritative_txt(self):
        packet = query("_acme-challenge.example.com")
        value = b"fixture-challenge-value"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(value) + 1)
        response = reply(packet)[:6] + b"\0\1" + packet[8:] + answer + bytes([len(value)]) + value

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_upstream:
            tcp_upstream.bind(("127.0.0.1", 0))
            upstream_port = tcp_upstream.getsockname()[1]
            tcp_upstream.listen(1)
            tcp_upstream.settimeout(3)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_upstream:
                udp_upstream.bind(("127.0.0.1", upstream_port))
                udp_upstream.settimeout(3)

                def respond_tcp():
                    connection, _ = tcp_upstream.accept()
                    with connection:
                        connection.settimeout(2)
                        received = bytearray()
                        while len(received) < len(packet) + 2:
                            chunk = connection.recv(len(packet) + 2 - len(received))
                            if not chunk:
                                return
                            received.extend(chunk)
                        if received == struct.pack("!H", len(packet)) + packet:
                            framed = struct.pack("!H", len(response)) + response
                            connection.sendall(framed[:1])
                            connection.sendall(framed[1:])

                def respond_udp():
                    received, peer = udp_upstream.recvfrom(65535)
                    if received == packet:
                        udp_upstream.sendto(response, peer)

                threads = [threading.Thread(target=target, daemon=True) for target in [respond_tcp, respond_udp]]
                for thread in threads:
                    thread.start()
                    self.addCleanup(thread.join, 4)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    listen_port = reservation.getsockname()[1]
                process = subprocess.Popen(
                    [sys.executable, "-B", str(pathlib.Path(__file__).with_name("pki_acme_authoritative_dns.py")),
                     "--listen-port", str(listen_port), "--upstream-port", str(upstream_port)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.addCleanup(process.communicate, timeout=3)
                self.addCleanup(process.terminate)
                self.assertTrue(select.select([process.stdout], [], [], 3)[0], "fixture did not start")
                self.assertIn(b"Authoritative fixture zones:", process.stdout.readline())

                expected = authoritative_response(packet, response)
                try:
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=2) as client:
                        framed = struct.pack("!H", len(packet)) + packet
                        client.sendall(framed[:1])
                        client.sendall(framed[1:])
                        received = bytearray()
                        while len(received) < len(expected) + 2:
                            chunk = client.recv(len(expected) + 2 - len(received))
                            self.assertTrue(chunk, "TCP response ended early")
                            received.extend(chunk)
                        self.assertEqual(received, struct.pack("!H", len(expected)) + expected)
                except OSError as error:
                    self.fail(f"TCP DNS fixture resolution failed: {error}")

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(packet, ("127.0.0.1", listen_port))
                    self.assertEqual(client.recvfrom(65535)[0], expected)

    def test_only_explicit_fixture_zone_boundaries_gain_authority(self):
        for name in ["example.com", "_acme-challenge.example.com", "_acme-challenge.native-acme.EXAMPLE.test"]:
            packet = query(name)
            response = authoritative_response(packet, reply(packet))
            self.assertTrue(struct.unpack_from("!H", response, 2)[0] & AA)
        for name in ["example.org", "badexample.com", "example.com.invalid", "example.test.invalid"]:
            packet = query(name)
            response = authoritative_response(packet, reply(packet, QR | AA))
            self.assertFalse(struct.unpack_from("!H", response, 2)[0] & AA)

    def test_response_rcode_and_answer_bytes_are_preserved(self):
        packet = query("_acme-challenge.example.com")
        response = reply(packet, QR | 3) + b"fixture-TXT-wire-bytes"
        actual = authoritative_response(packet, response)
        self.assertEqual(actual[4:], response[4:])
        self.assertEqual(struct.unpack_from("!H", actual, 2)[0] & 0xF, 3)

    def test_mismatched_or_malformed_messages_cannot_gain_authority(self):
        packet = query("example.com")
        for response in [b"", reply(query("example.test")), b"\0\1" + reply(packet)[2:], packet]:
            with self.assertRaises(ValueError):
                authoritative_response(packet, response)
        with self.assertRaises(ValueError):
            question(packet[:4] + b"\0\2" + packet[6:])
        with self.assertRaises(ValueError):
            question(packet[:12] + b"\xc0\x0c\0\x10\0\x01")


if __name__ == "__main__":
    unittest.main()
