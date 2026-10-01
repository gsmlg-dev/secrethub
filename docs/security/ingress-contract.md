# SecretHub ingress contract

WP2 adapts SecretHub to the existing Caddy mTLS authentication boundary. Caddy
configuration and administrator certificates remain operator-owned. SecretHub
has no administrator login, account, certificate allowlist or authentication
session on this path.

## Listeners and trust

`SecretHub.Web.Endpoint` is the private management backend. Bind it to loopback;
only the existing authenticated Caddy ingress may forward to it. For a proxy in
a separate network namespace, use a dedicated private network with enforced
access controls and explicitly configure the proxy peer IPs. Never publish the
management port or allow arbitrary tenants/processes on that private boundary.
The application compares the adapter's peer IP to `trusted_proxy_ips`; it ignores
forwarded identity headers and request Host values for this decision. This peer
check restricts transport access; it does not authenticate a second human.

A process already inside this trusted local/private boundary can access
management. Securing that boundary is a deployment prerequisite, and the
production candidate gate must demonstrate that outside clients cannot reach
it directly. Source tests alone cannot prove the live Caddy or firewall setup.

`SecretHub.Web.MachineEndpoint` exposes a separate, explicit machine route set.
It has no management routes, browser pages, session, or LiveView socket. It is
disabled by default and must be enabled explicitly in the runtime contract.
Keep it private by default; expose its machine-only port through the existing
infrastructure only where needed for enrollment and authenticated API clients.

`SecretHub.Web.AgentEndpoint` remains the dedicated TLS listener for trusted
Agent runtime. Its socket requires the verified peer certificate, and Core
continues to check identity, certificate state, revocation and policies. It does
not serve management HTTP routes or LiveView. AppRole and pending enrollment
tokens never replace the certificate identity for trusted runtime.

## Route classification

| Surface | Management backend | Machine backend | Authorization |
| --- | --- | --- | --- |
| `/admin/*`, `/vault/*`, `/live/*` | Yes | No | Existing Caddy mTLS and trusted private peer; browser CSRF and exact Origin |
| `/v1/sys/init`, `/unseal`, `/seal`, `/csrf-token` | Yes | No | Protected management path; no dependence on Vault being unsealed |
| AppRole role CRUD and SecretID rotation | Yes | No | Protected management path |
| PKI CA creation, CSR signing, revocation | Yes | No | Protected management path |
| Client Auth identities, issuance and management reads | Yes | No | Protected management path |
| Application lifecycle writes | Yes | No | Protected management path |
| AppRole login/renew and RoleID lookup | Yes | Yes | Existing credentials, token checks and rate limits |
| CLI access request creation/polling | Yes | Yes | Existing request/token workflow and rate limits; approval is management-only |
| Agent enrollment create/status/CSR/connect-info/finalize | Yes | Yes | Existing pending enrollment proof/token checks and rate limits |
| Application certificate bootstrap/renew | Yes | Yes | Existing bootstrap/current-key proof and rate limits |
| Secret CRUD, application and certificate reads | Yes | Yes | Vault token and existing secret policies |
| Dynamic credentials and leases | Yes | Yes | Existing token authorization; launch profile availability separately constrained |
| Client Auth public bundle/authority status | Yes | Yes | Public trust material only |
| Health, seal status | Yes | Yes | Health/status only; no state mutation |
| `/agent/socket` trusted runtime | Separate Agent listener | No | Agent mTLS certificate identity |

## Browser and secret handling

Management HTTP requests and both LiveView transports are checked before Phoenix
socket dispatch. An Origin, when supplied, must exactly match the configured
management URL (scheme, hostname and port). The request's Host and forwarded
headers cannot choose the allowed Origin. Browser management mutations retain
Plug CSRF verification, including JSON APIs.

Non-browser clients first fetch `GET /v1/sys/csrf-token` through the protected
management ingress, retain the returned cookie, and send the token as
`X-CSRF-Token` with mutations. This cookie is CSRF/session state only, never an
administrator credential. Production cookies are encrypted, HttpOnly, Secure
and SameSite=Lax. Management and machine responses use `Cache-Control: no-store`
so secret-bearing bodies and initialization shares cannot enter caches.

Initialization and manual unseal remain available while sealed through the
management ingress. Restart-sealed and manual-seal behavior are owned by WP1.

## Required evidence

Focused source regressions cover peer rejection, forged headers and old session
state, every management route category, transport Origins, missing CSRF tokens,
protected initialization/unseal, and unauthorized machine calls. The isolated
production candidate harness must additionally check actual Caddy mTLS success
and rejection, external direct-backend failure, connected LiveView operations,
and the enabled Machine/Agent listeners. No live Caddy configuration or
production certificate is changed by these implementation tests.

## Source verification (2026-10-01)

Worktree `.trees/codex/prelaunch-wp1`, baseline
`f214b0242e432719fbb0a9b39d4982b9d34514c9`. Tests ran with isolated
PostgreSQL 16, database `secrethub_test_web`, and a separate Mix build directory.
The initial ingress regression run had 14 tests / 11 failures; the storage
availability regressions had 3 tests / 3 failures before their changes.

The final scoped suite passed **97 tests, 0 failures**, including the generated
management route inventory, actual endpoint transport requests, connected
Vault LiveView, protected CSRF-cookie initialization/unseal, machine enrollment,
application certificate bootstrap/renewal and certificate verifier regressions.
After adding valid-token policy denial and unchanged-secret assertions on the
machine listener, the AppRole security file separately passed **13 tests,
0 failures**. Scoped formatting, compilation with `--warnings-as-errors`, and
`git diff --check` passed. Negative certificate and rate-limit cases emit their
existing expected warning/error logs.

This is source integration evidence. Existing live Caddy, external backend
reachability, production cookies and exact production artifacts still require
the candidate acceptance harness; no live deployment acceptance is claimed.


## Launch health and feature contract

The single-operator profile enables static secrets and Client Auth PKI. Dynamic
issuance, lease APIs, engine configuration, lease dashboards and automatic
rotation are unavailable with `feature_unavailable`. Machine routes still
validate the Vault token before reporting availability. Connected management
mounts enforce the same gate. Direct dynamic issuance/renewal and lease mutations
are guarded, rotation jobs discard disabled work, Core omits LeaseManager and
Agent omits LeaseRenewer. The Agent retains static delivery, runtime bootstrap
and PKI trust-bundle workers. Existing dynamic leases require operator review
before enabling this profile; these changes do not revoke real credentials.

| Probe | Meaning | Expected sealed/empty behavior |
| --- | --- | --- |
| `/v1/sys/health/live` | Application process responds; independent of DB/Vault | 200 |
| Protected `/v1/sys/health/management` | DB and usable Vault state machine; not shutting down | 200; initialization/unseal remain reachable |
| `/v1/sys/health/ready` | DB, initialized nonlegacy Vault, verified 32-byte unsealed key, required CRL worker; not shutting down | 503 |

Database and state-machine checks use bounded 500 ms calls and return stable,
redacted reasons. Management readiness rejects loading/unavailable state. A
required CRL worker must exist, be enabled, have reconciled successfully, have a
recent heartbeat and retain a scheduled next check. Missing CRL/reconciliation
failure makes readiness false. A healthy worker can wait for an authority that
has not been initialized; static-secret readiness does not claim that PKI can
already issue certificates. PKI APIs enforce their own authority prerequisites.

WP3 focused verification on the same isolated web database passed: **16 Core
health/profile tests**, **15 web workflow/share-limit tests**, the selected
**Agent launch-supervision test** and selected **runtime lease-gate test**, each
with zero failures. Share input now enforces the existing 251-share boundary.
Compilation with `--warnings-as-errors`, scoped formatting checks and
`git diff --check` passed.

A broader regression run encountered an unqualified environment test:
`engines/dynamic/postgresql_test.exs:82` selects `DEVENV_STATE/postgres` or a
separate TCP database named `secrethub_test`; it does not follow the isolated
`PGHOST`/partition contract. Its credential-generation check failed with
`FATAL 28P01 (invalid_password)` against that other service. No local service or
credentials were modified. Dynamic lifecycle acceptance is excluded from the
launch profile. Exact-artifact probes and real consumer acceptance remain
separate launch gates.

Final WP3 regression evidence after the health/configuration fixture changes:
**34 Core tests, 0 failures** (health, profile and existing lease behavior) and
**115 web tests, 0 failures** (workflow gates, ingress, machine policy denials,
PKI, certificate verification and full runtime channel). The CRL fault test
injects database unavailability immediately after a successful refresh-check
transaction; restoring the original fallback reproduces a healthy response
(**1 selected test, 1 failure**), and the bounded retry implementation passes.
A malformed feature list fails closed. Runtime-channel fixtures now wait a
bounded interval for durable Vault loading before actual initialization/unseal.
