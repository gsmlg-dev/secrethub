# Explicit Secret Value Formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Support exact Text and freely editable Structured Secrets, preserving legacy values, history, and application delivery.

**Architecture:** Keep encrypted JSON maps and add nullable `value_format` metadata. Apply structured field operations under the existing Core write lock. Propagate format outside application data through HTTP and Agent cache to UDS.

**Tech Stack:** Elixir/Phoenix LiveView, Ecto/PostgreSQL, existing DuskMoon components and Agent cache.

---

Approved specification: `docs/superpowers/specs/2026-10-23-secret-value-formats-design.md`.
Work directly on `main`. Preserve all pre-existing dirty DNS/UI files and unrelated untracked files. No live migrations, Vault operations, restarts, push, or release.

## Shared integration contract

```elixir
# Persisted metadata; nil preserves the pre-format compatibility contract.
field :value_format, :string # nil | "text" | "structured"

# New Text: exact wrapper. New Structured: arbitrary JSON object.
Secrets.create_secret(%{"name" => "Text example", "secret_path" => "example.text",
  "value_format" => "text", "value" => "  token\n"})
Secrets.create_secret(%{"name" => "Structured example", "secret_path" => "example.structured",
  "value_format" => "structured", "secret_data" => %{"value" => "x", "region" => "y"}})

# Server-only descriptor read; no saved values in the result.
{:ok, %{version: version, fields: [%{key: key, kind: kind}]}} =
  Secrets.field_descriptors(secret_id)

# Existing rows use original_key; new rows omit it. Removal is explicit.
Secrets.update_secret(secret_id, %{
  "value_format" => "structured",
  "field_operations" => [
    %{"original_key" => "old", "name" => "renamed", "operation" => "keep"},
    %{"name" => "new", "operation" => "replace", "value" => ""},
    %{"original_key" => "removed", "operation" => "remove"}
  ]
}, expected_version: version)
```

Unmentioned existing fields remain unchanged. Validate duplicate final keys and duplicate source operations. `keep` requires an existing original key; `replace` requires a string, including an empty string. Newly added/renamed names must be nonblank. Existing unusual keys and non-string values can be retained. Check `expected_version` before decrypting/applying field operations; reject missing or stale versions safely.

Text edit omits `value` to keep ciphertext and submits it, including `""`, only for an explicit replacement. Classifying a legacy value without replacement validates the selected format and preserves ciphertext. Switching an already explicit format requires a replacement.

## Task 1: Core storage, history, and protected publication

**Owner:** Core implementer.

**Files:**
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/secret.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/secret_version.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/secrets.ex`
- Create: a focused pure value-format helper under `apps/secrethub_core/lib/secrethub_core/secrets/` if needed to keep normalization and field operations bounded.
- Create: additive migration in `apps/secrethub_core/priv/repo/migrations/`.
- Test: `apps/secrethub_core/test/secrethub_core/secret_value_formats_test.exs`.

- [x] Add focused behavior regressions for exact text, JSON-looking text, nil compatibility, structured reserved names, keep/rename/replace/remove, stale version, duplicate names, hidden descriptors, and per-version rollback.
- [x] Run the new tests before implementation and record the expected failure.
- [x] Add nullable format columns and CHECK constraints without updating existing rows. Extend the managed-secret guard to reject ordinary format mutations; preserve all pinned-version UPDATE protection.
- [x] Implement the shared contract above using existing lock/version/archive paths. Preserve format on metadata-only/legacy updates. Explicit text must validate the exact singleton string wrapper; structured must remain a JSON map. Managed publication writes `"structured"`.
- [x] Snapshot, read, compare, and restore the selected version's format; preserve existing `read_exact_material/2` callers and add a metadata-bearing variant if needed.
- [x] Run focused Core tests with a test database only:

```sh
devenv --no-tui shell -- env MIX_ENV=test TEST_DB_POOL_SIZE=2 mix test apps/secrethub_core/test/secrethub_core/secret_value_formats_test.exs apps/secrethub_core/test/secrethub_core/secrets_test.exs
```

Expected: all in-scope tests pass; no live database migration. Parent manages commits after integration verification.

## Task 2: Generic Secret form and list metadata

**Owner:** UI implementer, independent of Task 1 except the shared contract.

**Files:**
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/secret_form_component.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/secret_management_live.ex`
- Test: `apps/secrethub_web/test/secrethub_web_web/live/secret_management_live_test.exs`
- Create a focused LiveComponent test file if necessary.

- [x] Add failing tests for selectable Text/Structured creation, arbitrary repeatable rows, hidden saved values, explicit empty replacement, field operations, stale edit feedback, legacy classification, and visible format badges.
- [x] Implement repeatable rows using existing component APIs; no dependency vendoring or token overrides. Keep component state limited to descriptors and user-entered replacement values.
- [x] Submit `field_operations` plus the descriptor version through `Secrets.update_secret/3`; omit payload for metadata-only edits. Use explicit Keep/Replace controls for text and each existing field. Explain legacy classification's delivery effect in the form.
- [x] Display non-string saved kinds without conversion; allow explicit remove/replace. Show unknown legacy format as an unset classification, never a third creation format. Keep static/dynamic generation controls independent.
- [x] Run the focused LiveView/component tests after Task 1 is available:

```sh
devenv --no-tui shell -- env MIX_ENV=test TEST_DB_POOL_SIZE=2 mix test apps/secrethub_web/test/secrethub_web_web/live/secret_management_live_test.exs
```

Expected: all scoped tests pass and DOM never contains saved values. Parent manages commits.

## Task 3: HTTP and Core-to-Agent delivery

**Owner:** Parent.

**Files:**
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/secret_api_controller.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/runtime_authorization.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/cache.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Test: matching focused HTTP, runtime authorization, Agent cache/UDS, and `apps/secrethub_cli/test/secrethub_cli/agent_client_test.exs` regressions.

- [x] Write/observe failing UDS regression with structured `%{"value" => "x", "region" => "y"}` and both fresh and `not_modified` reads.
- [x] Add format outside the trusted `value` payload and cache application data:

```elixir
%{value: data, value_format: secret.value_format, version: secret.version, revision: revision}
Cache.put(key, data, version: version, revision: revision, value_format: format)
```

- [x] UDS returns the complete map for `"structured"`, unwraps a Text singleton wrapper for `"text"`, and preserves old behavior only for absent/nil format. Preserve `Cache.get` data and dynamic/template contracts.
- [x] HTTP accepts optional top-level `value_format`, allows explicit Structured `{}`, passes it to Core, and adds it to current/historical response metadata. Keep the existing `data` map. Avoid logging or returning raw changesets with user replacement values.
- [x] Verify CLI preserves arbitrary objects after its existing single envelope unwrap; change CLI implementation only if a regression demonstrates necessity.
- [x] Run focused runtime/UDS/CLI/HTTP tests, then scoped compile/format/lint checks. No unrelated auth/socket tests.

## Task 4: Integration, documentation, and delivery

**Owner:** Parent after Tasks 1–3, with independent spec/quality reviews.

**Files:** approved spec and this checklist; new `docs/secrets/value-formats.md`; narrow DNS credential error/help callsites only if needed.

- [x] Verify Cloudflare Text and existing structured aliases; verify Route53 reports the required Structured fields without echoing values and ignores stored optional `region` for global signing.
- [x] Document two formats, editable arbitrary fields, hidden-value behavior, legacy classification, HTTP examples, and compatible Agent/CLI delivery; include only dummy credentials.
- [x] Review implementation against every acceptance item in the approved specification, then perform code-quality review and repair scoped findings.
- [x] Run scoped format/compile/lint checks and all affected focused tests. Report unrelated baseline findings without repairing them. Record concrete counts and test-log paths.
- [x] Inspect only the scoped diff, preserve earlier dirty DNS/UI changes and unrelated files, and commit the value-format implementation conventionally. Update this checklist and spec with actual verification evidence.

Completion means reviewed implementation plus passing focused verification. Source qualification does not imply a live migration, service restart, or release.

## Verification evidence — 2026-10-23

Implemented and reviewed on `main`, preserving the earlier DNS-provider and
Trust Store work. Existing service databases and Vault state were not changed.
The new migration was exercised only in disposable test databases.

| Focused test group | Result | Local evidence |
| --- | --- | --- |
| Core value formats, pure field operations, existing Secrets context | 44 passed | `/tmp/secrethub-value-formats-tests-final.log` |
| Core runtime authorization, DNS adapters, managed certificates | 72 passed | `/tmp/secrethub-value-formats-integration.log` |
| Agent UDS delivery after final refactoring | 26 passed | `/tmp/secrethub-value-formats-tests-final.log` |
| Agent cache security | 3 passed | `/tmp/secrethub-value-formats-cache-cli-final.log` |
| CLI Agent client | 3 passed | `/tmp/secrethub-value-formats-cache-cli-final.log` |
| HTTP formats, Secret form component, Secret management LiveView | 23 passed | `/tmp/secrethub-value-formats-tests-final.log` |
| ACME management and provider UI compatibility | 19 passed | `/tmp/secrethub-value-formats-integration.log` |

These are 190 distinct scoped tests across the recorded runs. The initial
integration run exposed three incorrect new Web test assertions: the existing
not-found error is a string; a generic nested marker matched a CSS class; and
the creation assertion needed to wait for the parent LiveView save message.
The final 23-test Web run passes with corrected assertions, retaining exact
payload and non-disclosure checks. Final regression commands exited successfully.

Test-first evidence: the initial Core integration suite failed 7/7 before the
format contract existed; the pure helper failed 6/6 before implementation.
The UDS regression run failed 2/26 for structured-field loss and unknown-format
handling, and the initial HTTP format run failed 4/4. A later form regression
failed 1/12 before requiring an explicit format for legacy replacement. Core
RED results were captured in tool output; delivery/HTTP/form RED logs are under
`/tmp/secrethub-value-format-{delivery,http}-red.log` and
`/tmp/secrethub-value-format-form-check.log`.

Final scoped formatting, whitespace checks, and compilation with
`--warnings-as-errors` passed. Logs:
`/tmp/secrethub-value-formats-format-check-final.log` and
`/tmp/secrethub-value-formats-compile-final.log`.

Strict Credo checked 12 scoped source files. All new findings were repaired.
It still exits with six existing findings: three refactoring opportunities in
`Secrets.update_unmanaged_secret_locked/3` and
`RuntimeAuthorization.authorize_static_read/4`, plus three alias suggestions.
Running Credo against the original `HEAD` versions of those two files produced
the same six findings. They were left unchanged, as required by the scope.
Evidence: `/tmp/secrethub-value-formats-credo-final.log` and
`/tmp/secrethub-value-formats-credo-baseline.log`.

Independent specification and code-quality reviews approved the implementation.
The final function splits and corrected Web assertions also received read-only
review. The three DNS credential help/error strings remain with the earlier
dirty ACME UI work; that file is excluded from the value-format commit.
Apply the additive migration through the normal operator procedure before
running this code against an existing service database. No live UI acceptance,
restart, push, or release was performed for this change.
