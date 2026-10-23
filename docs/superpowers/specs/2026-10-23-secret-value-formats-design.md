# Explicit Secret Value Formats

Date: 2026-10-23
Status: Implemented and source-qualified on 2026-10-23 after user approval. Live schema rollout remains an operator step.
Repository baseline: `main` at `a01a1c72ede2` (`v1.0.0-rc.24`).

## User intent

A stored Secret has two selectable value formats:

- **Text**: an exact string. A token, PEM document, or JSON document entered as
  text remains text; its contents never select a format automatically.
- **Structured data**: an application-defined object. Users freely add, rename,
  replace, and remove fields. There is no fixed AWS or DNS-provider schema.

Here, editable/dynamic fields do not mean dynamically generated credentials.
Existing static/dynamic generation, engine selection, rotation, and leases remain
separate concepts.

For example, an AWS application can use `access_key_id`, `secret_access_key`,
optional `region`, and optional `session_token`. Another application can use
completely different fields. Cloudflare can use a Text Secret containing its API
token directly.

## Approaches considered

1. **Explicit format metadata and a generic field editor — recommended.** Record
   format separately from the encrypted application payload, carry it through
   versioning and Agent reads, and let each consumer validate its required
   fields. This resolves ambiguity without reserving application field names.
2. **Infer format from JSON syntax or a `value` field.** This requires less
   metadata but changes JSON text into objects and can discard legitimate
   structured fields. It cannot represent the user's distinction reliably.
3. **Provider-specific Secret schemas.** Fixed Cloudflare/AWS forms could validate
   credentials early, but constrain reuse by other applications. Provider
   requirements belong at the consumer boundary instead.

## Scope

Implement the value-format contract across Shared schemas, Core storage and
versions, the existing Secret management form, HTTP metadata, trusted static
reads, Agent cache, and UDS delivery. Keep DNS credential validation consistent
with those formats. Add focused regression tests and operator/API documentation.

Keep the already implemented DNS-provider modal, list, Secret-path completion,
zone discovery, and Trust Store table changes intact. Work on `main` and preserve
unrelated files.

This design does not add application schema registries, presets, a JSON editor,
typed/nested field authoring, new authentication, or changes to generated dynamic
credentials. It does not authorize running migrations against an existing
service, changing Vault state, restarting services, or publishing a release.

## Data model and encrypted representation

Add nullable `value_format` to `secrets` and `secret_versions`. The only non-null
values are `text` and `structured`; enforce this with schema validation and a
database check constraint. Do not reuse `secret_type`, `engine_type`, or a key in
user-defined metadata. Dynamic-engine definitions without a stored value do not
need a value format.

Retain the current encrypted JSON-map representation:

| Selected format | Decrypted storage payload |
| --- | --- |
| Text | `{"value": "the exact supplied string"}` |
| Structured data | The supplied application object |

The discriminator is outside that object. Field names such as `value`, `data`,
`format`, and `value_format` are all valid application keys and have no special
meaning inside a Structured Secret.

Text preserves Unicode, whitespace, newlines, and the empty string without
trimming, JSON parsing, or pretty-printing. Structured values remain JSON objects
in storage/API contracts, including existing arrays, numbers, booleans, nulls,
and nested objects. The first UI editor creates string-valued fields; it never
silently converts an existing non-string value to a string. An empty structured
object is valid when explicitly submitted in the new format contract.

## Create and edit behavior

For stored static values, the existing Secret modal offers Text and Structured
data. Text uses the existing textarea. Structured data uses repeatable rows with
an editable field name, a secret value input, and add/remove controls. No AWS
field is mandatory in this generic form.

In the row editor, newly added or renamed field names must not be empty or
whitespace-only. Final names must be unique and are case-sensitive; preserve
accepted names exactly. Existing keys, including empty or whitespace-only keys
from older writers, can remain unchanged during classification and edits. Do
not impose a new key-naming restriction on the existing JSON-object API. Never
create atoms from user-provided field names. Values can be empty strings.

Saved values remain hidden when editing:

- Text editing starts in **Keep current value** mode. **Replace value** enables
  the textarea; an explicit replacement may be empty or whitespace-only.
- Opening the Structured field editor decrypts on the server only to obtain
  field names and value kinds. Return only those descriptors to the LiveView;
  never assign saved values to the socket or render them into the DOM.
- Existing rows default to **Keep value**. Renaming keeps the original value;
  **Replace value** supplies a new string; removal explicitly deletes the field.
  An untouched blank input never overwrites an existing value.
- Existing non-string fields show their kind and a hidden-value placeholder.
  They can be kept, renamed, removed, or explicitly replaced with a string.
  Their original JSON value is preserved while kept or renamed.
- Newly entered values are never repopulated from stored ciphertext after a
  save. Validation errors retain only values entered in the current form.

Core, rather than the browser, applies field operations to the saved object.
Submit the expected Secret version with field operations. Under the existing
write lock, verify that version, decrypt the current object, construct the final
object from original keys plus explicit operations, then validate and encrypt
once. This supports renames without making one rename accidentally overwrite
another. Reject stale submissions and duplicate final names without partial
writes. Do not accept replacement of the whole saved object from placeholder
inputs.

Changing between explicit Text and Structured formats requires a complete new
payload in the selected format. Do not automatically parse JSON, choose one
field, or stringify an object. Metadata-only edits preserve both format and
ciphertext. Managed certificate outputs retain their existing write protection.

The list/detail view shows the known value format without displaying values.

## Existing data and older writers

Old ciphertext does not reliably reveal the original entry mode: the object
`{"value": "x"}` can be either text storage or an intentional one-field object.
Do not guess or backfill by decrypting existing data.

The additive migration leaves existing rows and historical versions with null
`value_format`. Null is an internal compatibility state, never a third format
offered by the creation form. The UI can display **Format not specified** and
offer the two explicit choices.

Until explicitly classified, existing records keep their current read behavior.
To classify an unmanaged Secret without replacing its value:

- Choosing Text is valid only when its stored object contains exactly one
  `value` key with a string value. This is validation of the user's choice,
  rather than automatic classification.
- Choosing Structured preserves the entire stored object, including a lone
  `value` field and all existing JSON types.
- Save classification as an ordinary new version, preserving the previous
  ciphertext and its null format in history. Reuse ciphertext when no payload
  changed. Explicitly choosing Structured can change UDS delivery from legacy
  unwrapping to the complete object; explain that consequence in the form.

New UI writes always specify a format. The known internal text-input path may
also specify Text. Managed certificate publication explicitly writes Structured.

Older HTTP/direct map writers that omit format retain the compatibility
contract: new records remain unclassified, and updates preserve the current
classification. If a record already has an explicit format, a replacement must
validate against it. Metadata-only writes never classify a record implicitly.
Document explicit format selection for new integrations while retaining older
callers. Existing legacy nonempty-map validation remains unchanged for requests
that do not opt into the new contract.

## Versions, protected material, and revision invalidation

Every archived version captures its own `value_format`. Historical reads return
the format belonging to the selected ciphertext. Rollback restores both into a
new current version; comparison reports format changes without revealing data.

Do not update historical rows during migration or classification. Retained ACME
versions reject all updates; preserve that guarantee. Extend the existing
managed-secret database guard to cover `value_format` so an ordinary update
cannot reinterpret managed output. New managed publication writes Structured
for both initial publication and replacement; old pinned rows remain untouched.

Persist format changes through normal versioned Secret updates, which already
advance path revisions. Format must never change only in application metadata
or outside the revision mechanism, otherwise an Agent could retain the wrong
interpretation of cached data.

## API and Agent delivery

Keep Core's decrypted payload map contract and the HTTP response's existing
`data` object. Add `value_format` as response metadata alongside that object,
never inside application data. A new HTTP write can explicitly choose a format:
Text requires `data` to be exactly its string-valued storage wrapper; Structured
accepts a JSON object. Existing request shapes continue through the compatibility
rules above.

Propagate format as follows:

1. Trusted static-read authorization emits `value_format` alongside its existing
   `value`, `version`, and `revision` envelope fields. The channel/connection
   forwarding keeps that envelope intact.
2. Agent cache entries retain format separately from application data, including
   fresh responses, revision-validated hits, and `not_modified` reconstruction.
   Existing cache entries or older Core responses lacking format use the legacy
   interpretation.
3. UDS interprets only explicit Text as a storage wrapper to unwrap. Explicit
   Structured returns the complete application object, even when it has a
   `value` key or keys named after protocol metadata. Missing format preserves
   the old behavior until the Secret is classified.
4. The CLI already unwraps the UDS response envelope once. Preserve that behavior
   and verify complete structured objects survive it; a new CLI wire contract is
   unnecessary. HTTP CLI reads continue returning the existing `data` object.

For example, explicit Structured `{"value":"x","region":"y"}` reaches the
UDS application and CLI as that complete object. Explicit Text reaches UDS as a
string. HTTP continues returning the documented map representation for both.

Do not change the application map supplied by `Cache.get` to templates. Format
metadata stays in the cache entry and does not become a template variable or an
environment key. Dynamic credential cache entries, generation, and rendered
sink output keep their existing contracts.

## DNS consumers

The generic Secret editor does not enforce provider schemas. Provider operations
validate credentials on the server after decrypting the selected Secret:

- Cloudflare Text is the API token itself. Preserve the current `api_token`,
  `token`, and compatible `value` aliases for existing structured/legacy
  credentials.
- Route53 requires string fields `access_key_id` and `secret_access_key` and
  accepts optional `session_token`. An optional `region` can be stored for other
  AWS applications; global Route53 signing keeps its existing region behavior.
- JSON entered in Text is not parsed into AWS credentials. Return an actionable
  validation message directing the operator to Structured data and the required
  field names. Do not echo any values in errors.

Secret-path autocomplete, server-only credential use, read-only zone discovery,
and selected-zone validation continue to work with these formats.

## Security and failure behavior

Keep encrypted payloads encrypted at rest. Field descriptors require the same
management boundary as existing Secret writes and no new authentication layer.
Decrypted existing values stay inside bounded Core operations and never enter
socket assigns, errors, logs, audit events, or test output.

Validation failures identify field positions or safe operation names, not saved
values. Audit only existing bounded operation metadata such as Secret identity,
version, selected format, and operation result. Do not log arbitrary field names,
payloads, or secret-derived hashes. A sealed Vault or decryption failure returns
a safe failure and performs no write. Keep expected-version checks, revision
checks, authorization, and managed-output protection intact.

## Acceptance and verification

Use focused regressions and a disposable test database. No live migration is
part of qualification.

- Exact text round trips: token, JSON-looking text, Unicode, newlines,
  whitespace-only, and explicit empty replacement; omitted replacement preserves
  both value and format.
- Arbitrary structured fields can be added, renamed, replaced, and removed;
  test names `value`, `data`, `format`, and `value_format`, duplicate final names,
  explicit empty values, stale edits, preservation of non-string JSON, and
  retention of existing empty/whitespace-only keys without requiring renames.
- Edit forms expose descriptors but never existing values, including validation
  failures, and metadata-only edits preserve ciphertext.
- Legacy data is not rewritten or inferred. Explicit classification validates
  the selected shape, versions the change, and invalidates cached revisions.
- Version archive/read/rollback retain the matching format, and protected ACME
  history remains unchanged. Verify new managed publications are Structured.
- Verify HTTP compatibility and Core-to-Agent-to-UDS-to-CLI delivery, including
  `not_modified` cache hits, missing-format compatibility, and objects containing
  `value` plus sibling fields. Template inputs and dynamic credential results
  retain their existing shapes.
- Verify Cloudflare Text and structured credentials, Route53 required fields,
  optional AWS fields, and failure without echoing credentials.
- Run scoped formatting, compilation, lint, and relevant tests. Report unrelated
  baseline failures separately and do not broaden repair scope.

After user approval, write the implementation plan and execute this bounded
change on `main`, preserving the existing dirty DNS/UI implementation. Delivery
evidence must distinguish tested source changes from live migration or service
acceptance.
