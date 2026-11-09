import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import keyring
import keyring.backend
import pytest
from keyring.errors import KeyringError, PasswordDeleteError, PasswordSetError

from keyrings.secrethub import SecretHubKeyring

SRC = str(Path(__file__).resolve().parents[1] / "src")


class FakeAgent:
    """Threaded AF_UNIX server speaking the Agent newline-JSON protocol."""

    def __init__(self, path):
        self.path = path
        self.entries = {}  # (service, account) -> {"username", "value"}
        self.requests = []
        self.forced_error = None
        self.mismatch_request_id = False
        self.delete_status = None
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(path)
        self._sock.listen(16)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self._sock.close()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                request = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
                self.requests.append(request)
                response = self._handle(request)
                response["request_id"] = (
                    "not-the-request-id"
                    if self.mismatch_request_id
                    else request["request_id"]
                )
                conn.sendall(
                    (json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8")
                )

    def _handle(self, request):
        if self.forced_error:
            return error(self.forced_error)
        params = request["params"]
        assert params["namespace"] == "generic"
        service = params["service"]
        action = request["action"]

        if action == "credential_get":
            if "account" in params:
                entry = self.entries.get((service, params["account"]))
                if entry is None:
                    return error("NOT_FOUND")
            else:
                matches = [v for (s, _), v in self.entries.items() if s == service]
                if not matches:
                    return error("NOT_FOUND")
                if len(matches) > 1:
                    return error("AMBIGUOUS")
                entry = matches[0]
            return ok({"entry_id": "e1", "namespace": "generic",
                       "source_kind": "owned", **entry})

        if action == "credential_put":
            key = (service, params["account"])
            status = "updated" if key in self.entries else "created"
            self.entries[key] = {"username": params["account"], "value": params["value"]}
            return ok({"status": status, "entry_id": "e1"})

        if action == "credential_delete":
            if self.delete_status:
                return ok({"status": self.delete_status})
            removed = self.entries.pop((service, params["account"]), None)
            return ok({"status": "deleted" if removed else "absent"})

        return error("INVALID_REQUEST")


def ok(data):
    return {"status": "ok", "data": data}


def error(code):
    return {"status": "error", "error": {"code": code}}


@pytest.fixture
def sock_dir():
    # AF_UNIX paths are length-limited; keep them short.
    with tempfile.TemporaryDirectory(prefix="shk") as d:
        yield d


@pytest.fixture
def agent(sock_dir):
    fake = FakeAgent(os.path.join(sock_dir, "agent.sock"))
    yield fake
    fake.close()


@pytest.fixture
def selected(agent):
    previous = keyring.get_keyring()
    keyring.set_keyring(SecretHubKeyring(socket_path=agent.path))
    yield agent
    keyring.set_keyring(previous)


def test_round_trip_through_keyring_api(selected):
    keyring.set_password("my-app", "alice", "s3cret")
    assert keyring.get_password("my-app", "alice") == "s3cret"

    put = selected.requests[0]
    assert put["action"] == "credential_put"
    assert put["params"] == {"namespace": "generic", "service": "my-app",
                             "account": "alice", "value": "s3cret"}
    assert selected.requests[1]["params"] == {"namespace": "generic",
                                              "service": "my-app", "account": "alice"}

    keyring.delete_password("my-app", "alice")
    assert keyring.get_password("my-app", "alice") is None


def test_service_and_username_passed_exactly(selected):
    keyring.set_password(" Svc/Name ", " Bob ", "v")
    assert (" Svc/Name ", " Bob ") in selected.entries
    assert keyring.get_password("svc/name", "bob") is None


def test_not_found_returns_none(selected):
    assert keyring.get_password("missing", "nobody") is None


def test_empty_string_value_round_trips(selected):
    keyring.set_password("svc", "user", "")
    assert keyring.get_password("svc", "user") == ""
    assert keyring.get_password("svc", "other") is None


def test_unicode_values(selected):
    value = "пароль-密码-🔑"
    keyring.set_password("сервис", "ユーザー", value)
    assert keyring.get_password("сервис", "ユーザー") == value
    cred = keyring.get_credential("сервис", "ユーザー")
    assert (cred.username, cred.password) == ("ユーザー", value)


def test_get_credential_with_and_without_username(selected):
    assert keyring.get_credential("svc", "alice") is None
    assert keyring.get_credential("svc", None) is None  # NOT_FOUND

    keyring.set_password("svc", "alice", "pw-a")
    cred = keyring.get_credential("svc", "alice")
    assert (cred.username, cred.password) == ("alice", "pw-a")

    cred = keyring.get_credential("svc", None)
    assert (cred.username, cred.password) == ("alice", "pw-a")
    assert "account" not in selected.requests[-1]["params"]

    keyring.set_password("svc", "bob", "pw-b")
    assert keyring.get_credential("svc", None) is None  # AMBIGUOUS


def test_ambiguous_with_explicit_account_is_an_error(selected):
    selected.forced_error = "AMBIGUOUS"
    with pytest.raises(KeyringError, match="^AMBIGUOUS$"):
        keyring.get_password("svc", "alice")


@pytest.mark.parametrize("code", ["FORBIDDEN", "UNAUTHORIZED", "VAULT_SEALED",
                                  "INCOMPATIBLE_VERSION", "BUSY"])
def test_denials_raise_keyring_error(selected, code):
    selected.forced_error = code
    with pytest.raises(KeyringError, match="^" + code + "$"):
        keyring.get_password("svc", "alice")
    with pytest.raises(KeyringError):
        keyring.get_credential("svc", None)


def test_set_errors_raise_password_set_error(selected):
    for code in ("READ_ONLY", "FORBIDDEN", "UNCONFIRMED"):
        selected.forced_error = code
        with pytest.raises(PasswordSetError, match="^" + code + "$") as exc_info:
            keyring.set_password("svc", "alice", "do-not-leak")
        assert "do-not-leak" not in str(exc_info.value)
        assert "do-not-leak" not in repr(exc_info.value)


def test_delete_absent_raises(selected):
    with pytest.raises(PasswordDeleteError, match="not found"):
        keyring.delete_password("svc", "ghost")


def test_delete_disabled_reference_succeeds(selected):
    selected.delete_status = "disabled"
    assert keyring.delete_password("svc", "ref") is None


def test_delete_error_code(selected):
    selected.forced_error = "AMBIGUOUS"
    with pytest.raises(PasswordDeleteError, match="^AMBIGUOUS$"):
        keyring.delete_password("svc", "alice")


def test_request_id_mismatch_is_an_error(selected):
    selected.entries[("svc", "alice")] = {"username": "alice", "value": "pw"}
    selected.mismatch_request_id = True
    with pytest.raises(KeyringError) as exc_info:
        keyring.get_password("svc", "alice")
    assert "pw" not in str(exc_info.value)
    with pytest.raises(PasswordSetError):
        keyring.set_password("svc", "alice", "pw2")


def test_unavailable_socket_raises(sock_dir):
    backend = SecretHubKeyring(socket_path=os.path.join(sock_dir, "absent.sock"))
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    try:
        with pytest.raises(KeyringError):
            keyring.get_password("svc", "alice")
        with pytest.raises(KeyringError):
            keyring.get_credential("svc", None)
        with pytest.raises(PasswordSetError):
            keyring.set_password("svc", "alice", "pw")
        with pytest.raises(PasswordDeleteError):
            keyring.delete_password("svc", "alice")
    finally:
        keyring.set_keyring(previous)


def test_socket_path_from_environment(agent, monkeypatch):
    monkeypatch.setenv("SECRET_HUB_AGENT_SOCKET_PATH", agent.path)
    previous = keyring.get_keyring()
    keyring.set_keyring(SecretHubKeyring())
    try:
        keyring.set_password("env-svc", "u", "pw")
        assert keyring.get_password("env-svc", "u") == "pw"
    finally:
        keyring.set_keyring(previous)


def test_explicit_socket_path_overrides_environment(agent, sock_dir, monkeypatch):
    monkeypatch.setenv("SECRET_HUB_AGENT_SOCKET_PATH",
                       os.path.join(sock_dir, "wrong.sock"))
    backend = SecretHubKeyring(socket_path=agent.path)
    backend.set_password("svc", "u", "pw")
    assert backend.get_password("svc", "u") == "pw"


def test_not_auto_discovered():
    names = {type(k).__module__ + "." + type(k).__name__
             for k in keyring.backend.get_all_keyring()}
    assert not any("secrethub" in n for n in names)
    assert SecretHubKeyring not in set(keyring.backend.KeyringBackend.get_viable_backends())


def test_selected_via_environment_variable(agent):
    script = (
        "import keyring, keyrings.secrethub as s;"
        "k = keyring.get_keyring();"
        "assert isinstance(k, s.SecretHubKeyring), k;"
        "keyring.set_password('proc', 'u', 'pw');"
        "print(keyring.get_password('proc', 'u'))"
    )
    env = dict(os.environ,
               PYTHON_KEYRING_BACKEND="keyrings.secrethub.SecretHubKeyring",
               SECRET_HUB_AGENT_SOCKET_PATH=agent.path,
               PYTHONPATH=SRC + os.pathsep + os.environ.get("PYTHONPATH", ""),
               PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-c", script], env=env,
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "pw"
