# HTTP client migration status

Assessment date: 2026-11-08.

Req callers now use `http_fetch 1.0.0-rc.8`: CLI JSON responses, Agent enrollment
and HTTP operations, bounded PKI downloads, and Swoosh's API client. Their focused
tests cover response handling, explicit trust, redirects and body limits.
TLS 1.2 / TLS 1.3 interoperability and the real Core-Agent mTLS flows are
qualified with the published RC.8 cohort.

The Agent now uses `http_web_socket 1.0.0-rc.8` through
`Phoenix.SocketClient.Transports.Websocket` from `phoenix_socket_client 0.9.0`.
The direct `websocket_client` dependency and the custom
`MTLSWebSocketTransport` have been removed. In-memory client identity, explicit
CA trust, hostname verification and the TLS 1.2 / TLS 1.3 policy are forwarded
through the public adapter's `:ssl` option.

The RC.8 upgrade resolves the previously reproduced transport failure tracked
in [gsmlg-dev/http_fetch#157](https://github.com/gsmlg-dev/http_fetch/issues/157).
The original TLS 1.2-first / TLS 1.3 policy and certificate verification are
unchanged; no custom transport or dependency patch is used.

## Historical RC.5 / RC.6 behavior

The published `ex_ssl 1.0.0-rc.5` package belongs to the `http_fetch` repository
and implements TLS for both Fetch and WebSocket. An isolated OTP TLS server and
identical valid CA, SNI, hostname and client-identity options gave these results:

| Client versions | OTP SSL | ExSSL RC.5 |
| --- | --- | --- |
| TLS 1.2, TLS 1.3 | PASS | `illegal_parameter` |
| TLS 1.3, TLS 1.2 | PASS | PASS |
| TLS 1.2 only | PASS | `handshake_failure` |
| TLS 1.3 only | PASS | PASS |

All four version lists are accepted public inputs. When the server only supports
TLS 1.2, both dual-version orders fail in ExSSL and pass in OTP SSL. Removing
client authentication also reproduces the defect, so ordinary HTTPS requests
to TLS 1.2 peers are affected. When TLS succeeds, the WebSocket Open event and
Phoenix adapter's connection notification work correctly.

The same matrix was rerun against published `ex_ssl 1.0.0-rc.6`, including
TLS 1.2-only servers and ordinary HTTPS, with the same failures. All 91 ExSSL
library files are unchanged from RC.5. The RC.6 upgrade does not fix TLS
negotiation.

Before RC.8, the replacement failed the real Core-Agent flow tests S9 and S11
before runtime acceptance. That failure is historical; both selected flows now
pass with their original runtime-acceptance timeouts.

## RC.8 qualification

All eight installed packages in the shared-version HTTP cohort are locked to
`1.0.0-rc.8`. Development and test builds were checked against those versions.
The original OTP reference-server probes produced matching results for both
OTP SSL and the installed ExSSL package:

| Server and client identity | Positive handshakes | Expected protocol rejections |
| --- | --- | --- |
| TLS 1.2 / TLS 1.3 server, in-memory RSA mTLS | 8 | 0 |
| TLS 1.2 / TLS 1.3 server, ordinary TLS | 8 | 0 |
| TLS 1.2-only server, in-memory RSA mTLS | 6 | 2 |
| TLS 1.2-only server, ordinary TLS | 6 | 2 |

Both mixed client-version orders and TLS 1.2-only succeed. A TLS 1.3-only
client correctly fails against a TLS 1.2-only server. Client and server results
were checked separately for all 32 cases. An initial concurrent probe had two
handshake timeouts; the unchanged probe passed when rerun after compilation
with its original five-second timeout.

The real Core-Agent flow tests S9 and S11 pass: the Agent joins runtime over
mTLS and reads an authorized secret, and the CLI reads through the local Agent
backed by that runtime. The 15-second acceptance assertions are unchanged.
HTTP regression coverage also checks explicit CA trust, rejection of an
untrusted CA and rejection of a wrong hostname against both TLS versions.
ExSSL reports TLS 1.2 certificate-validation failures as `bad_certificate`;
TLS 1.3 retains its specific `unknown_ca` and `certificate_unknown` alerts.

These results qualify the targeted HTTP/WebSocket transport paths. They do not
constitute a full-suite, complete release-build or deployment qualification.
