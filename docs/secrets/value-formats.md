# Secret value formats

Stored static Secrets have two selectable value formats, independent of the
static/dynamic credential engine and rotation settings.

| Format | Use it for | Entry behavior |
| --- | --- | --- |
| Text | API tokens, passwords, PEM files, JSON documents | Preserve the exact string, including whitespace and newlines. JSON-looking text is never parsed. |
| Structured data | Configuration with several application-defined fields | Freely add, rename, replace, and remove fields. Each application chooses its own names. |

## Editing values

The Secret management modal offers Text or Structured data for stored values.
Structured field rows accept string values, including empty strings. Newly added
or renamed fields need nonblank, unique names. Names are case-sensitive.

Saved values are hidden when editing. Text defaults to **Keep current value**;
choose **Replace value** to enter a replacement, including an empty string.
Structured fields also default to keeping their saved values. Renaming a field
preserves its value. Replacement and removal are explicit operations.

Existing structured arrays, objects, numbers, booleans, and nulls show their kind
without their saved value. Keeping or renaming these fields preserves the
original JSON value. The row editor can explicitly replace one with a string or
remove it. Existing unusual field names can remain unchanged. The HTTP API
continues accepting JSON objects with nested or non-string values.

Concurrent edits are checked against the version loaded by the editor. If the
Secret changed, reopen the form before applying field changes. Changing between
explicit Text and Structured formats requires a replacement value; no automatic
JSON parsing, field extraction, or stringification occurs.

## Application examples

A Cloudflare Secret can use Text with the API token entered directly. The DNS
provider selects the Secret path and discovers available zones using that token
on the server. Existing structured credential aliases `api_token`, `token`, and
`value` remain supported.

An AWS application can use Structured data with these freely editable fields:

| Field | Meaning |
| --- | --- |
| `access_key_id` | AWS access key ID |
| `secret_access_key` | AWS secret access key |
| `region` | Optional application region |
| `session_token` | Optional session token for temporary credentials |

These names are an example, not a fixed Secret schema. Route53 validates
`access_key_id` and `secret_access_key` when using the Secret. It accepts
`session_token` and retains its global signing region; a stored `region` remains
available to other AWS applications. Pasting an AWS JSON document as Text does
not create these fields.

Other applications can define entirely different names, including `value`,
`data`, `format`, and `value_format`. These application fields do not replace
protocol or format metadata.

## HTTP contract

Explicit format is a top-level request property, outside the `data` object.
These examples use dummy values.

Text request body for `POST /v1/secret/data/prod/cloud/cloudflare`:

```json
{
  "value_format": "text",
  "data": {"value": "example-cloudflare-token"}
}
```

Structured request body for `POST /v1/secret/data/prod/cloud/aws`:

```json
{
  "value_format": "structured",
  "data": {
    "access_key_id": "example-access-key-id",
    "secret_access_key": "example-secret-access-key",
    "region": "ap-southeast-1"
  }
}
```

An explicit Structured request may contain an empty object. Text requires exactly
one `value` field whose value is a string, including an empty string. The HTTP
read response retains its existing `data` object and includes `value_format` in
`metadata`. Historical reads use the selected version's format.

UDS applications receive Text as a string and Structured as the complete object.
The CLI's Agent client unwraps the response envelope once and preserves the
complete structured object. Agent cache entries retain format separately, so
revision-validated cached reads produce the same application value as fresh
reads. Template variables retain the existing application data map.

## Existing Secrets and compatibility

Older Secrets and historical versions have no recorded value format. They show
**Format not specified** until explicitly classified or replaced. This is an
internal compatibility state, not another format for creating Secrets. The
migration does not decrypt, classify, or rewrite existing values.

Choose Text without replacement only if the saved payload is the existing
single string-valued `value` wrapper. Choosing Structured preserves the complete
saved object. Both choices create a new version, and rollback restores the
matching historical format as well as the value.

Legacy UDS delivery historically extracted a `value` field whenever one existed.
Explicitly classifying a legacy Secret as Structured changes that delivery to
the complete object, including any sibling fields. Confirm that its applications
expect an object before making that choice.

Older map writers that omit `value_format` remain compatible: new records remain
unclassified, and writes to existing records preserve their current format.
Replacements must match an already selected format. Omitted format does not
implicitly change metadata-only edits, and empty legacy request bodies remain
invalid. New integrations should select a format explicitly.

Managed certificate output is Structured and remains protected from ordinary
Secret editing. Its retained historical versions are never backfilled.

## Schema rollout

The additive Core migration introduces nullable format columns for Secrets and
their versions, validates explicit formats, and extends managed-output protection.
Apply it through the existing deployment migration procedure before running code
that reads the new columns. Back up and operate the target database according to
its normal operator procedure. Source tests use disposable databases; passing
those tests does not mean a running database has been migrated.
