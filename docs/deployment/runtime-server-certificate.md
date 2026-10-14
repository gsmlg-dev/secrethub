# Issue or renew the Agent runtime server certificate

Use `POST /admin/api/pki/runtime-server-certificate` through the management
HTTPS origin protected by Caddy's mandatory operator mTLS. The Vault must be
unsealed and an existing active SecretHub signing CA must be available. This
operation works with `RELEASE_DISTRIBUTION=none`; it does not require release RPC.
It never creates, replaces, or exports the signing CA private key.

The JSON request contains `advertised_host`, the DNS name or IP address that
Agents use to connect to Core. Optional `subject_alt_names` is a list of DNS names
and IPv4/IPv6 addresses containing that exact advertised host. It defaults to
`[advertised_host]`. Names must be concrete hosts, without schemes, ports,
wildcards, paths, or whitespace. The certificate always has `serverAuth` EKU;
request fields cannot select client EKUs.

Each successful request generates a fresh RSA keypair and leaf certificate with
the existing issuer's 365-day lifetime. Renewal uses the same operation. The
response's `data` contains `certificate_pem`, `private_key_pem`,
`ca_certificate_pem` (the active signing CA), and `ca_fingerprint`. The response is
marked `Cache-Control: no-store`. The leaf key is returned once and is not stored
in the certificate database. The audit event records only the advertised host,
SANs, leaf serial, and CA fingerprint. If audit logging fails, material is not
returned.

## Protected operator request

Run from a trusted operator workstation. Set the management origin, operator
client certificate/key, and the CA used to verify that management HTTPS origin.
Use an encrypted operator filesystem for temporary output. Do not enable shell
tracing or curl verbose/trace output, or print the response into terminal logs.

```sh
umask 077
operator_dir="$(mktemp -d)"
management_url="https://secrethub-management.example.net"
operator_cert="/secure/operator-cert.pem"
operator_key="/secure/operator-key.pem"
management_ca="/secure/management-ca.pem"

curl --fail --silent --show-error \
  --cert "$operator_cert" --key "$operator_key" --cacert "$management_ca" \
  --cookie-jar "$operator_dir/cookies" \
  "$management_url/v1/sys/csrf-token" --output "$operator_dir/csrf.json"
csrf_token="$(jq -er '.csrf_token' "$operator_dir/csrf.json")"

cat > "$operator_dir/request.json" <<'JSON'
{
  "advertised_host": "runtime.example.net",
  "subject_alt_names": ["runtime.example.net", "192.0.2.10", "2001:db8::10"]
}
JSON

curl --fail --silent --show-error \
  --cert "$operator_cert" --key "$operator_key" --cacert "$management_ca" \
  --cookie "$operator_dir/cookies" \
  --header "X-CSRF-Token: $csrf_token" --header "Content-Type: application/json" \
  --data-binary "@$operator_dir/request.json" \
  "$management_url/admin/api/pki/runtime-server-certificate" \
  --output "$operator_dir/material.json"

jq -er '.data.certificate_pem' "$operator_dir/material.json" > "$operator_dir/runtime-cert.pem"
jq -er '.data.private_key_pem' "$operator_dir/material.json" > "$operator_dir/runtime-key.pem"
jq -er '.data.ca_certificate_pem' "$operator_dir/material.json" > "$operator_dir/signing-ca.pem"

openssl verify -partial_chain -CAfile "$operator_dir/signing-ca.pem" \
  -purpose sslserver -verify_hostname runtime.example.net "$operator_dir/runtime-cert.pem"
```

For an advertised IP address, use OpenSSL's `-verify_ip` instead of
`-verify_hostname`. Provision the leaf certificate/key through the existing
encrypted deployment mechanism (for example, SOPS), with the deployed private
key readable only by the Core service. Preserve the existing Agent enrollment
trust chain; the returned signing CA must match it. Plan renewal before the
earlier of the leaf or signing CA expiration. Issuance does not install material
or restart a running listener.

After securely provisioning the material, remove the temporary response, key,
CSRF token, and cookie files. Keep any required backup encrypted. For a `503`
response, resolve the reported unavailable CA/key/audit condition; never
regenerate an initialized CA as a recovery shortcut. Invalid names return `422`,
and missing or invalid CSRF tokens are rejected by the management pipeline.
