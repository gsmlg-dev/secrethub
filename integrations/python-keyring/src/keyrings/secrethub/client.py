"""Minimal stdlib-only client for the SecretHub Agent local socket protocol.

One AF_UNIX stream connection is opened per request. Requests and responses
are single newline-terminated JSON documents. Secret values are never placed
in exception messages.
"""

import json
import os
import socket
import uuid

DEFAULT_SOCKET_PATH = "/var/run/secrethub/agent.sock"
SOCKET_ENV = "SECRET_HUB_AGENT_SOCKET_PATH"
DEFAULT_TIMEOUT = 10.0
MAX_FRAME = 65536


class AgentUnavailable(Exception):
    """The Agent socket could not be reached or did not answer in time."""


class AgentError(Exception):
    """The Agent answered with an error code."""

    def __init__(self, code):
        self.code = str(code)
        super().__init__(self.code)


class ProtocolError(AgentError):
    """The Agent response violated the local protocol."""

    def __init__(self):
        super().__init__("PROTOCOL_ERROR")


def resolve_socket_path(socket_path=None):
    if socket_path:
        return socket_path
    return os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET_PATH


class AgentClient:
    def __init__(self, socket_path=None, timeout=DEFAULT_TIMEOUT):
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, action, params):
        request_id = str(uuid.uuid4())
        frame = (
            json.dumps(
                {"request_id": request_id, "action": action, "params": params},
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")

        raw = self._exchange(resolve_socket_path(self.socket_path), frame)

        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ProtocolError() from None

        if not isinstance(response, dict) or response.get("request_id") != request_id:
            raise ProtocolError()

        status = response.get("status")
        if status == "ok":
            data = response.get("data")
            if not isinstance(data, dict):
                raise ProtocolError()
            return data
        if status == "error":
            error = response.get("error")
            code = error.get("code") if isinstance(error, dict) else None
            if not isinstance(code, str) or not code:
                raise ProtocolError()
            raise AgentError(code)
        raise ProtocolError()

    def _exchange(self, path, frame):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            raise AgentUnavailable("SecretHub Agent socket unavailable") from None
        try:
            sock.settimeout(self.timeout)
            sock.connect(path)
            sock.sendall(frame)
            return self._read_line(sock)
        except (OSError, socket.timeout):
            # Covers FileNotFoundError, ConnectionRefusedError, PermissionError,
            # timeouts and resets. The path is not secret; values never reach here.
            raise AgentUnavailable(
                "SecretHub Agent unavailable at " + str(path)
            ) from None
        finally:
            sock.close()

    @staticmethod
    def _read_line(sock):
        buf = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                raise ProtocolError()
            newline = chunk.find(b"\n")
            if newline >= 0:
                buf += chunk[:newline]
                if len(buf) > MAX_FRAME:
                    raise AgentError("RESPONSE_TOO_LARGE")
                return bytes(buf)
            buf += chunk
            if len(buf) > MAX_FRAME:
                raise AgentError("RESPONSE_TOO_LARGE")
