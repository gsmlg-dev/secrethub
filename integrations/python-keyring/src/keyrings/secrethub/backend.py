"""keyring backend that stores generic credentials in SecretHub via the local Agent."""

from keyring.backend import KeyringBackend
from keyring.credentials import SimpleCredential
from keyring.errors import KeyringError, PasswordDeleteError, PasswordSetError

from .client import DEFAULT_TIMEOUT, AgentClient, AgentError, AgentUnavailable

NAMESPACE = "generic"
_LOOKUP_MISSES = ("NOT_FOUND", "AMBIGUOUS")


class SecretHubError(KeyringError):
    """The SecretHub Agent refused or failed a lookup. Message is the error code."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class AgentUnavailableError(KeyringError):
    """The SecretHub Agent socket could not be reached."""


class SecretHubKeyring(KeyringBackend):
    """SecretHub host keyring (generic namespace).

    Never auto-selected: no entry point is registered and the class reports
    itself as non-viable for discovery. Select it explicitly with
    ``PYTHON_KEYRING_BACKEND=keyrings.secrethub.SecretHubKeyring``.
    """

    priority = 1
    # Excluded from keyring.backend.get_all_keyring() even when imported;
    # explicit selection (load_keyring / set_keyring) does not consult this.
    viable = False

    def __init__(self, socket_path=None, timeout=DEFAULT_TIMEOUT):
        self.socket_path = socket_path
        self.timeout = timeout
        super().__init__()

    def _request(self, action, params):
        client = AgentClient(socket_path=self.socket_path, timeout=self.timeout)
        return client.request(action, params)

    def _get(self, service, username):
        params = {"namespace": NAMESPACE, "service": service}
        if username is not None:
            params["account"] = username
        try:
            return self._request("credential_get", params)
        except AgentUnavailable as exc:
            raise AgentUnavailableError(str(exc)) from None
        except AgentError as exc:
            if exc.code == "NOT_FOUND" or (
                username is None and exc.code in _LOOKUP_MISSES
            ):
                return None
            raise SecretHubError(exc.code) from None

    def get_password(self, service, username):
        data = self._get(service, username)
        return None if data is None else data["value"]

    def get_credential(self, service, username):
        data = self._get(service, username)
        if data is None:
            return None
        return SimpleCredential(data.get("username", username), data["value"])

    def set_password(self, service, username, password):
        params = {
            "namespace": NAMESPACE,
            "service": service,
            "account": username,
            "value": password,
        }
        try:
            self._request("credential_put", params)
        except AgentUnavailable:
            raise PasswordSetError("AGENT_UNAVAILABLE") from None
        except AgentError as exc:
            raise PasswordSetError(exc.code) from None

    def delete_password(self, service, username):
        params = {"namespace": NAMESPACE, "service": service, "account": username}
        try:
            data = self._request("credential_delete", params)
        except AgentUnavailable:
            raise PasswordDeleteError("AGENT_UNAVAILABLE") from None
        except AgentError as exc:
            raise PasswordDeleteError(exc.code) from None
        status = data.get("status")
        if status == "absent":
            raise PasswordDeleteError("not found")
        if status not in ("deleted", "disabled"):
            raise PasswordDeleteError("UNEXPECTED_STATUS")
