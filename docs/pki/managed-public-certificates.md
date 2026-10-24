# Managed public server certificates

SecretHub provides a Mozilla-derived public root catalogue and Let's Encrypt
ACME v2 DNS-01 certificates through Cloudflare and Route 53. Management remains
behind the existing Caddy mTLS proxy. Internal CA, Agent, application and client
identity trust are separate; public certificates do not authorize machines.

## Installation and configuration

Run the normal Core release migration command before starting the new binary.
The two new Core migrations install Oban schema version 14 and the dedicated
ACME tables, ownership constraints and retention guards. Back up PostgreSQL and
Vault recovery material first. No existing internal CA is imported or replaced.
ACME retention guards intentionally require a coordinated retention migration
before rolling the database backwards; restoring an old binary alone does not
remove them.

The supported Core profile includes `public_trust` and `acme`. Set
`SECRET_HUB_ACME_ENABLED=false` to stop new issuance and publication. Named
`SecretHub.Core.Oban` runs bounded `acme` and `acme_cleanup` queues and a minute
reconciler; Human's Oban instance remains separate. Creating/registering an
account contacts the CA; DNS changes begin when a managed issuance order runs.
DNS cleanup and pending revocations continue while issuance is disabled. Keep
their old credential references, Vault access and outbound connectivity available.

The Vault must be unsealed to create/use encrypted account keys, pending leaf
keys and credential secrets. Public trust inspection/export works while sealed,
without a database or network. Queue state survives restart; do not purge Oban
or ACME tables to recover a failed attempt.

## Public roots

Open `/admin/pki/trust-stores` or `/admin/api/pki/trust-stores` to inspect/export
`mozilla_webpki`. Its SHA-256 is computed from the actual packaged PEM bytes;
the catalogue includes source/package version, root count, fingerprints and
validity. This is a Mozilla-derived root collection, not full Firefox policy
enforcement. Core declares CAStore directly. The original PEM provenance header
is retained. Core's packaged `priv/pki/PUBLIC-TRUST-NOTICE.txt` records CAStore's
Apache-2.0 packaging notice and the Mozilla/NSS source-data MPL-2.0 notice; the
separate staging-root source/hash manifest is packaged beside it.

Update public roots by reviewing/updating the CAStore dependency and lockfile,
rebuilding and publishing a release. Review removed roots and affected server
chains before rollout; replace affected issuers/certificates as needed. A binary
rollback restores its older root policy, including roots removed by a newer
release. There is no runtime downloader or machine-wide SSL trust modification.

ACME/provider HTTPS always uses explicit public roots and peer/hostname
verification. Official Let's Encrypt staging issuance roots have a separate
pinned profile; they never enter production HTTPS or internal identity trust.

## Account and provider setup

Use `/admin/pki/acme` (or `/admin/api/pki/acme/*`). Choose production or staging
explicitly and supply contact addresses. The account modal loads the current
Terms of Service from that environment's official ACME directory and shows a
link to the actual agreement. Review it and explicitly check acceptance; opening
the modal, changing environments, or retrying a failed lookup clears acceptance.
The form cannot submit until the current agreement has loaded. Confirming an
update saves the exact displayed agreement and queues registration for enabled
accounts, making an existing waiting retry due immediately.
A changed terms URL fails closed until the operator accepts it again. API
callers continue to supply the agreement URL with explicit acceptance.
Account keys are distinct from leaf keys and are encrypted
with existing Vault primitives. Account-key rollover is outside this version.

The page shows existing accounts and managed certificates. Use **Add ACME
account**, **Add managed certificate**, or a row's edit action to open its form
in a modal. Failed validation keeps the entered values and displays the error
inside the modal. Cancel or Escape discards unsaved changes; a successful save
closes the modal and refreshes the list.

First store provider credentials in an existing encrypted static secret:

| Provider | Secret data | Required access |
| --- | --- | --- |
| Cloudflare | Scalar API token from the ordinary Secret **Value** form, or structured `api_token` / `token` | Zone Read and DNS Edit on each explicitly selected public zone |
| Route 53 | `access_key_id`, `secret_access_key`, optional `session_token` | `route53:GetHostedZone`, `route53:ListResourceRecordSets`, `route53:ChangeResourceRecordSets` on selected zones, plus `route53:GetChange` on change IDs and `route53:ListHostedZones` on `*` for zone discovery |

For Cloudflare, paste the API token directly into the ordinary Secret **Value**
field; no JSON or secret conversion is needed. Existing structured credential
secrets containing `api_token` or `token` remain supported. This scalar-token
compatibility applies only to Cloudflare; Route 53 requires its structured AWS
credential fields listed above.

For Route 53, constrain changes with IAM condition keys for TXT type, normalized
challenge names and CREATE/DELETE actions. The adapter preserves whole supported
RRsets using exact-preimage DELETE/CREATE batches. It rejects private zones and
unfamiliar routing-policy records. It does not use an unconditional UPSERT.
Cloudflare creates individual marked TXT records and records their exact IDs.

Alternatively select Route 53's explicit `aws_environment` mode, using
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional `AWS_SESSION_TOKEN` in
Core's environment. This version does not discover instance-role/container/SSO
credentials. Do not put credentials in provider JSON, job arguments or metadata.

Open `/admin/pki/acme/dns-providers` to see configured providers. Add or edit a
provider in its modal form. Select the credential **secret path** using autocomplete
from existing encrypted static secrets; SecretHub retains its UUID reference
internally. The secret values remain on Core and are never sent to the form.
Selecting credentials loads available public zones from the provider API. Choose
the allowed zones from that list; zone IDs and names are filled automatically.
Cloudflare lists active zones, and Route 53 excludes private hosted zones. Discovery
only reads provider metadata and does not create DNS records. Credential or DNS
service changes require reloading and selecting the matching zones.

The management API continues to accept `credential_secret_id` UUIDs and also
accepts `credential_secret_path`. An explicit path resolves to that stored secret;
an unknown path fails instead of falling back to a previously submitted UUID.
API callers configure explicit `zone_id`/canonical `zone_name` entries.
The certificate modal at `/admin/pki/acme` needs only **ACME account**, **Name**,
**Leaf key**, **DNS names** and **Zone**. Name is a display name, so values such as
`gsmlg.net` or names containing spaces and Unicode are supported. New names must
be unique and at most 255 Unicode codepoints. Selecting a Zone determines the
provider and matching DNS suffix automatically; every DNS name must belong to
that Zone. Saving a definition does not request issuance.

The management API retains advanced bindings for certificates spanning multiple
zones or using CNAME delegation. Editing a certificate in the modal preserves its
existing bindings unless a different Zone is explicitly selected. For a
certificate spanning multiple zones, leave **Keep current zones** selected to
preserve those bindings. A binding's optional
`suffix` selects the longest label-boundary match. Equal matches are rejected. Names are normalized
for IDNA, case and trailing dots. Wildcard and apex can share one TXT owner;
different SANs may use different providers. Inbound HTTP/TLS and public A/AAAA
records are unnecessary for DNS-01.

For CNAME delegation, configure `delegated_owner` and the provider/zone that owns
that target, with `suffix` identifying the original name. CNAME traversal is
bounded and loops/unconfigured targets fail. The authoritative target must be
publicly resolvable. Provider API success/Route 53 INSYNC alone is insufficient:
Core observes authoritative TXT answers before acknowledging the challenge.

To rotate credentials, update the encrypted credential secret in place while
preserving its ID and permissions. Destructive provider reference/zone edits are
blocked until active orders and cleanup obligations resolve. Disabling a
provider is supported and retains its old binding for cleanup.

## Issuance, renewal and delivery

Create a managed definition using the five-field modal. SecretHub generates its
stable internal slug automatically and displays the Name in lists and details.
Renaming a certificate preserves its internal slug and output secret path. Legacy
definitions display their existing slug until named. The API accepts a `name`
with an automatically generated slug, and still accepts explicit `slug` values
for existing integrations; slugs use lowercase letters and digits separated by
hyphens. The account and slug remain immutable after creation. Issue with a
unique stable request ID.
Replaying the same request reuses its order; changing its desired revision under
that ID is rejected. Progress and redacted errors are durable and visible. One
leaf key/CSR is retained across retries. A lost order-create response without a
known remote URL becomes a visible uncertain failure; a new request is an
explicit replacement, not a promise of exactly-once remote issuance.

On success, `pki.acme.<slug>` is a single encrypted static secret containing
`certificate`, `chain`, `fullchain`, `private_key`, `combined_pem`, version ID,
fingerprint, identifiers, environment and validity. Certificate/key validation,
material/history ownership, pointer switch and audit append are atomic. Generic
secret writes, rollback/deletion/rotation and pruning of pinned history cannot
replace managed material. Policies are preserved; grant existing applications
ordinary read access to this dotted secret path.

An explicit version export resolves that exact current or historical secret
version, then checks its embedded ID and fingerprint. Lists/details omit private
keys; protected private exports use `Cache-Control: no-store`. Staging output is
marked staging and remains untrusted by production clients.

`/admin/pki/certificates` lists published ACME versions alongside internal CA
certificates, with their DNS names, environment, current/historical marker,
validity and status. Unissued definitions are absent; expired, quarantined and
revoked versions remain visible. Use an ACME row's management link to open
`/admin/pki/acme` for its lifecycle actions.

For Agent delivery, read the structured secret through the existing authorized
runtime path and render `combined_pem` to **one sink file** with restrictive
permissions. Existing sink behavior is the delivery boundary. This release does
not implement atomic deployment of separate key/certificate files or automatic
application reload. Operators must arrange and verify application adoption.

Renewal uses RFC 9773 ARI when available, persists the chosen randomized window
and refresh time, and sends replacement information. Without usable ARI it uses
actual certificate lifetime: about two-thirds elapsed, or half for lifetimes
shorter than ten days. Failures have bounded backoff and visible errors; the
serving valid version remains available. Reconciliation recovers due work after
job exhaustion, restart or Vault unavailability. Monitor expiry and failed orders
as well as queue health; an expired certificate is blocked from new delivery.

## Cleanup, revocation and recovery

Cleanup is independent of issuance success. Exact intents/receipts survive
success, failure, cancellation and restart. Retry cleanup from management after
repairing credentials, permissions or DNS conflicts. Cloudflare deletes only its
owned, unchanged record; borrowed matches are preserved. Route 53 subtracts owned
values while preserving unrelated values/TTL. Internal locks serialize Core's
writers; they cannot fence external DNS writers. Lost Route 53 mutation responses
can leave ownership ambiguous. Such records remain visible unresolved obligations
and require operator investigation; do not force-delete a whole TXT owner.

Requesting revocation immediately quarantines the selected version locally.
Remote state is pending/failed until the CA confirms success or alreadyRevoked.
Quarantine applies to current and historical private exports/delivery, including
cache revalidation, and survives remote ambiguity. Revoking an older generation
does not disable a newer healthy version. Already distributed bytes cannot be
recalled; operators must remove/reload remote material themselves.

Back up the full database, encrypted credential secrets, output/history, account
keys and Vault recovery material together. After restore, unseal Vault, restore
the same credential references and inspect outstanding remote orders/receipts
before resuming. Reconciliation revisits known URLs and cleanup; never restore
only certificate metadata without its exact encrypted material version.

## Qualification

See [execution evidence](secrethub-pki-acme-execution.md). Deterministic provider
fixtures and local Pebble are distinct from real Let's Encrypt staging through
an authorized zone. Neither provider's live staging gate is claimed without that
explicit evidence. No production certificate is requested for qualification.
