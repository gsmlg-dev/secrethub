# keyrings.secrethub

A [`keyring`](https://pypi.org/project/keyring/) backend that stores and reads
credentials through the local SecretHub Agent, using the host keyring
`generic` namespace. See `docs/subsystem/host-keyring.md` for the protocol.

No desktop session, D-Bus, Secret Service or KWallet is needed: the backend
talks only to the Agent's Unix domain socket, so it works in headless
services, containers and cron jobs.

## Install

Install into the application's own environment (virtualenv, container image,
system Python used by the service):

```bash
pip install ./integrations/python-keyring
```

The only dependency is `keyring>=24`; the Agent client uses the standard
library only.

## Select the backend explicitly

The package registers **no** `keyring.backends` entry point and is never
auto-selected, even when imported. Choose it in one of these ways:

* Environment variable:

  ```bash
  export PYTHON_KEYRING_BACKEND=keyrings.secrethub.SecretHubKeyring
  ```

* `keyringrc.cfg` (see `python -c "import keyring.util.platform_ as p; print(p.config_root())"`):

  ```ini
  [backend]
  default-keyring=keyrings.secrethub.SecretHubKeyring
  ```

* In code:

  ```python
  import keyring
  from keyrings.secrethub import SecretHubKeyring

  keyring.set_keyring(SecretHubKeyring())
  ```

## Socket selection

The Agent socket is chosen in this order:

1. `SecretHubKeyring(socket_path=...)` (or the `socket_path` attribute),
2. `SECRET_HUB_AGENT_SOCKET_PATH`,
3. `/var/run/secrethub/agent.sock`.

The per-request timeout defaults to 10 seconds (`timeout=` / `timeout`
attribute). The socket is owner-only; run the application as a user the Agent
grants access to.

## Mapping

`service` and `username` are passed to the Agent exactly as given (no
normalization); `username` becomes the entry `account`. An empty string is a
stored value, distinct from `None`.

| keyring call | Agent action | Result |
| --- | --- | --- |
| `get_password(service, username)` | `credential_get` | value, or `None` on `NOT_FOUND` |
| `set_password(service, username, password)` | `credential_put` | `None` |
| `delete_password(service, username)` | `credential_delete` | `None` for `deleted`/`disabled`; `PasswordDeleteError("not found")` for `absent` |
| `get_credential(service, username)` | `credential_get` | `SimpleCredential` or `None` |
| `get_credential(service, None)` | `credential_get` without `account` | unique match, or `None` on `NOT_FOUND`/`AMBIGUOUS` |

## Errors

Error messages contain only the Agent error code, never secret values.

| Condition | Raised |
| --- | --- |
| `NOT_FOUND` on lookup | returns `None` |
| `AMBIGUOUS` on `get_credential(service, None)` | returns `None` |
| any other lookup error (`FORBIDDEN`, `UNAUTHORIZED`, `VAULT_SEALED`, `UNAVAILABLE`, `INCOMPATIBLE_VERSION`, ...) | `keyrings.secrethub.SecretHubError` (a `keyring.errors.KeyringError`) |
| Agent socket missing, refused, not permitted or timed out on lookup | `keyrings.secrethub.AgentUnavailableError` (a `KeyringError`) |
| any store failure, including `READ_ONLY` and `UNCONFIRMED` | `keyring.errors.PasswordSetError(code)` |
| any erase failure | `keyring.errors.PasswordDeleteError(code)` |
| Agent unavailable on store/erase | `PasswordSetError` / `PasswordDeleteError` with `AGENT_UNAVAILABLE` |
| malformed response or `request_id` mismatch | `PROTOCOL_ERROR` in the matching exception |

An unavailable or denying Agent is never reported as a miss. `UNCONFIRMED`
means the outcome of a write or delete is unknown; do not retry automatically.

## Tests

```bash
cd integrations/python-keyring
PYTHONPATH=src python3 -m pytest -q
```

The tests run a fake Agent on a temporary Unix socket and exercise the backend
through the public `keyring` API.
