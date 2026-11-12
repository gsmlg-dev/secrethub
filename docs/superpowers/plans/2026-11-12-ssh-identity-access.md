# SSH Identity and Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SSH source identities become first-class objects, independent of Agents. Each identity is either held by an Agent with a device-local private key, or added by an operator as an external public key. Identities rotate through generations, both on a Styx schedule and on demand. The `/admin/ssh-access` UI becomes three tabs: devices, identities, and access.

**Architecture:**

- **Core.** A new pure module, `SecretHub.Core.SSH.Identities`, owns identity lifecycle transitions over in-memory maps. `SecretHub.Core.SSH` keeps its role: locking, revision checks, auditing, persistence, and runtime views.
- **Rules.** Rules now select a source identity or identity group and a destination endpoint or host group.
- **Agent keys.** Agents store ed25519 keys under `<state_dir>/ssh-identities/<uid>/` and sign locally. Core only authorizes each signature and never releases private material.
- **Rotation.** Rotation uses pull-based reconciliation. The existing heartbeat-driven `inventory` reply carries requested generations. The Agent then reports each new public key with a new `identity_report` runtime operation.

**Tech Stack:** Elixir umbrella, Ecto/PostgreSQL, Phoenix LiveView with `phoenix_duskmoon` `dm_*` components, Phoenix channels, and the Styx job runner.

**Spec:** `docs/superpowers/specs/2026-11-12-ssh-identity-access-design.md`

**Conventions for every task**

- Run tests with `test-all <path>`. Inside devenv, `MIX_ENV` is `dev`, so do not run bare `mix test`.
- Each task ends with `mix format` and a commit. Commit messages follow `type(scope): subject`; omit any Claude attribution trailers.
- Do not create branches or worktrees. Work on the current `main` checkout.
- Compatibility does not matter: production holds 0 rows in `ssh_identities`, and no Agent uses the SSH sockets yet. Old protocol fields are removed, not kept alongside the new ones.

---

## File structure

| File | Responsibility |
|---|---|
| `apps/secrethub_core/priv/repo/migrations/20261112000000_rebuild_ssh_identities.exs` (new) | Drop and recreate `ssh_identities`, create `ssh_identity_keys`, clear legacy rules |
| `apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity.ex` (rewrite) | Identity schema with no private key field |
| `apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity_key.ex` (new) | Per-generation public key schema |
| `apps/secrethub_core/lib/secrethub_core/ssh/identities.ex` (new) | Pure lifecycle: report, approve, revoke, external add/replace, rotation, schedule |
| `apps/secrethub_core/lib/secrethub_core/ssh/evaluator.ex` (rewrite) | Pure policy over identity sources and endpoint/host-group destinations |
| `apps/secrethub_core/lib/secrethub_core/ssh.ex` (modify) | Management ops, runtime views, `rotate_due/1`, persistence |
| `apps/secrethub_core/lib/secrethub_core/workers/ssh_identity_rotation_worker.ex` (new) | Hourly Styx cron entry |
| `config/config.exs` (modify) | `ssh` queue and crontab entry |
| `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex` (modify) | Accept `ssh:identity_report` |
| `apps/secrethub_agent/lib/secrethub_agent/ssh/key_store.ex` (new) | Device-local key files |
| `apps/secrethub_agent/lib/secrethub_agent/ssh/reconciler.ex` (new) | First-use enrollment and generation reconciliation |
| `apps/secrethub_agent/lib/secrethub_agent/ssh/server.ex` (modify) | Local signing after `authorize_sign` allow |
| `apps/secrethub_agent/lib/secrethub_agent/ssh/lookup.ex` (modify) | Reply keys `allowed`, `identity_generations` |
| `apps/secrethub_agent/lib/secrethub_agent/connection.ex` (modify) | Run the reconciler after each inventory report |
| `apps/secrethub_web/lib/secret_hub/web/live/ssh_access_live.ex` (rewrite) | State, events, staging, and confirm for three tabs |
| `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/preview.ex` (new) | Human-readable change and edge sentences |
| `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/devices.ex` (new) | Devices tab function components |
| `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/identities.ex` (new) | Identities tab function components |
| `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/access.ex` (new) | Access matrix and group drawer components |
| `docs/deployment/ssh-access-management.md` (modify) | Operator documentation for the new model |

---

### Task 1: Schemas and migration

**Files:**
- Create: `apps/secrethub_core/priv/repo/migrations/20261112000000_rebuild_ssh_identities.exs`
- Rewrite: `apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity.ex`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity_key.ex`
- Test: `apps/secrethub_core/test/secrethub_core/ssh/schema_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
defmodule SecretHub.Core.SSH.SchemaTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture}
  alias SecretHub.Shared.Schemas.Agent
  alias SecretHub.Shared.Schemas.SSH.{Identity, IdentityKey}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
  end

  test "identities hold public keys only and enforce origin shape" do
    Repo.insert!(%Agent{agent_id: "laptop", name: "laptop", status: :trusted_connected})
    refute :private_key_encrypted in Identity.__schema__(:fields)

    agent = %Identity{
      id: Ecto.UUID.generate(),
      name: "gao@laptop",
      origin: "agent",
      agent_id: "laptop",
      local_username: "gao",
      local_uid: 1000,
      status: "pending"
    }

    assert {:ok, stored} = Repo.insert(agent)

    assert {:ok, _} =
             Repo.insert(%IdentityKey{
               id: Ecto.UUID.generate(),
               identity_id: stored.id,
               generation: 1,
               public_key: "ssh-ed25519 AAAA",
               fingerprint: "SHA256:one"
             })

    assert [%IdentityKey{generation: 1}] =
             Repo.preload(Repo.get!(Identity, stored.id), :keys).keys

    invalid = %Identity{
      id: Ecto.UUID.generate(),
      name: "broken",
      origin: "external",
      agent_id: "laptop",
      status: "active"
    }

    assert_raise Ecto.ConstraintError, fn -> Repo.insert(invalid) end
  end

  test "legacy rules are cleared by the migration" do
    assert %{rules: []} = Repo.get!(SecretHub.Shared.Schemas.SSH.Inventory, 1)
  end
end
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/schema_test.exs`
Expected: compile error, `SecretHub.Shared.Schemas.SSH.IdentityKey is not available`.

- [ ] **Step 3: Write the migration**

```elixir
defmodule SecretHub.Core.Repo.Migrations.RebuildSSHIdentities do
  use Ecto.Migration

  # Production holds 0 identity rows. Rules referenced Agents as sources, so the
  # migration clears them; groups gain kinds when loaded.
  def up do
    drop(table(:ssh_identities))

    create table(:ssh_identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:origin, :string, null: false)

      add(
        :agent_id,
        references(:agents, column: :agent_id, type: :string, on_delete: :delete_all)
      )

      add(:local_username, :string)
      add(:local_uid, :bigint)
      add(:status, :string, null: false)
      add(:rotation_days, :integer)
      add(:next_rotation_at, :utc_datetime)
      add(:requested_generation, :bigint, null: false, default: 1)
      add(:rotation_overdue, :boolean, null: false, default: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:ssh_identities, [:name]))
    create(unique_index(:ssh_identities, [:agent_id, :local_uid]))

    create(
      constraint(:ssh_identities, :ssh_identity_origin,
        check: """
        (origin = 'agent' AND agent_id IS NOT NULL AND local_username IS NOT NULL
          AND local_uid BETWEEN 0 AND 4294967295)
        OR (origin = 'external' AND agent_id IS NULL AND local_username IS NULL
          AND local_uid IS NULL)
        """
      )
    )

    create(
      constraint(:ssh_identities, :ssh_identity_status,
        check: "status IN ('pending', 'active', 'retired')"
      )
    )

    create(
      constraint(:ssh_identities, :ssh_identity_rotation_days,
        check: "rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650"
      )
    )

    create table(:ssh_identity_keys, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:identity_id, references(:ssh_identities, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:generation, :bigint, null: false)
      add(:public_key, :text, null: false)
      add(:fingerprint, :string, null: false)
      add(:not_after, :utc_datetime)
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(unique_index(:ssh_identity_keys, [:fingerprint]))
    create(unique_index(:ssh_identity_keys, [:identity_id, :generation]))
    execute("UPDATE ssh_inventory SET rules = '{}'")
  end

  def down do
    drop(table(:ssh_identity_keys))
    drop(table(:ssh_identities))

    create table(:ssh_identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :agent_id,
        references(:agents, column: :agent_id, type: :string, on_delete: :delete_all),
        null: false
      )

      add(:username, :string, null: false)
      add(:uid, :bigint, null: false)
      add(:public_key, :text, null: false)
      add(:fingerprint, :string, null: false)
      add(:private_key_encrypted, :binary, null: false)
      add(:key_revision, :bigint, null: false, default: 1)
      add(:active, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:ssh_identities, [:agent_id, :username]))
    create(unique_index(:ssh_identities, [:agent_id, :uid]))
    create(unique_index(:ssh_identities, [:fingerprint]))
  end
end
```

- [ ] **Step 4: Write the schemas**

`apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity.ex`:

```elixir
defmodule SecretHub.Shared.Schemas.SSH.Identity do
  @moduledoc """
  SSH source identity. Stores public keys only: Agent identities keep their
  private key on the device; external identities are held by their owner.
  """
  use Ecto.Schema
  alias SecretHub.Shared.Schemas.SSH.IdentityKey

  @primary_key {:id, :binary_id, autogenerate: false}
  schema "ssh_identities" do
    field(:name, :string)
    field(:origin, :string)
    field(:agent_id, :string)
    field(:local_username, :string)
    field(:local_uid, :integer)
    field(:status, :string, default: "pending")
    field(:rotation_days, :integer, default: 90)
    field(:next_rotation_at, :utc_datetime)
    field(:requested_generation, :integer, default: 1)
    field(:rotation_overdue, :boolean, default: false)
    has_many(:keys, IdentityKey, foreign_key: :identity_id, preload_order: [asc: :generation])
    timestamps(type: :utc_datetime)
  end
end
```

`apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity_key.ex`:

```elixir
defmodule SecretHub.Shared.Schemas.SSH.IdentityKey do
  @moduledoc "One public key generation of an SSH identity. A non-nil not_after marks it superseded."
  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: false}
  schema "ssh_identity_keys" do
    belongs_to(:identity, SecretHub.Shared.Schemas.SSH.Identity, type: :binary_id)
    field(:generation, :integer)
    field(:public_key, :string)
    field(:fingerprint, :string)
    field(:not_after, :utc_datetime)
    timestamps(type: :utc_datetime, updated_at: false)
  end
end
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/schema_test.exs`
Expected: 2 tests, 0 failures. Other SSH tests now fail to compile or fail at runtime. Tasks 2–5 fix them, so do not run the full suite yet.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_core/priv/repo/migrations/20261112000000_rebuild_ssh_identities.exs \
  apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity.ex \
  apps/secrethub_shared/lib/secrethub_shared/schemas/ssh/identity_key.ex \
  apps/secrethub_core/test/secrethub_core/ssh/schema_test.exs
git commit -m "feat(core): store SSH identities as public key generations"
```

---

### Task 2: Pure identity lifecycle

**Files:**
- Create: `apps/secrethub_core/lib/secrethub_core/ssh/identities.ex`
- Test: `apps/secrethub_core/test/secrethub_core/ssh/identities_test.exs`

An identity in memory is a plain map:

```elixir
%{
  id: uuid,
  name: string,
  origin: "agent" | "external",
  agent_id: string | nil,
  local_username: string | nil,
  local_uid: integer | nil,
  status: "pending" | "active" | "retired",
  rotation_days: integer | nil,
  next_rotation_at: DateTime | nil,
  requested_generation: integer,
  rotation_overdue: boolean,
  keys: [
    %{
      id: uuid,
      generation: integer,
      public_key: string,
      fingerprint: string,
      not_after: DateTime | nil,
      inserted_at: DateTime
    }
  ]
}
```

- [ ] **Step 1: Write the failing tests**

```elixir
defmodule SecretHub.Core.SSH.IdentitiesTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.SSH.Identities
  alias SecretHub.Shared.SSH.Key

  @now ~U[2026-11-12 00:00:00Z]

  defp public do
    {:ok, key} = Key.generate("ed25519")
    key.public.public_line
  end

  defp report(overrides \\ %{}) do
    Map.merge(
      %{
        agent_id: "laptop",
        agent_name: "laptop",
        uid: 1000,
        username: "gao",
        generation: 1,
        public_key: public()
      },
      overrides
    )
  end

  test "first report creates a pending identity that approval activates" do
    assert {:ok, [identity], {:reported, _}} = Identities.report([], report(), @now)
    assert %{name: "gao@laptop", status: "pending", origin: "agent", requested_generation: 1} =
             identity

    refute Identities.usable?(identity, @now)
    assert {:ok, [active]} = Identities.approve([identity], identity.id, @now)
    assert active.status == "active"
    assert active.next_rotation_at == DateTime.add(@now, 90 * 86_400)
    assert Identities.usable?(active, @now)
  end

  test "re-reporting the same key is idempotent and other generations are rejected" do
    first = report()
    {:ok, ids, _} = Identities.report([], first, @now)
    assert {:ok, ^ids, :unchanged} = Identities.report(ids, first, @now)

    assert {:error, :unexpected_generation} =
             Identities.report(ids, report(%{generation: 2}), @now)

    assert {:error, :unexpected_generation} = Identities.report([], report(%{generation: 2}), @now)
    assert {:error, :account_changed} = Identities.report(ids, %{first | username: "eve"}, @now)
  end

  test "requested rotation accepts exactly the next generation with a grace period" do
    {:ok, [identity], _} = Identities.report([], report(), @now)
    {:ok, ids} = Identities.approve([identity], identity.id, @now)
    {:ok, [requested]} = Identities.request_rotation(ids, identity.id, @now)
    assert requested.requested_generation == 2

    later = DateTime.add(@now, 60)

    assert {:ok, [rotated], {:rotated, _}} =
             Identities.report([requested], report(%{generation: 2}), later)

    assert [%{generation: 1, not_after: grace}, %{generation: 2, not_after: nil}] = rotated.keys
    assert grace == DateTime.add(later, 3 * 86_400)
    assert length(Identities.valid_keys(rotated, later)) == 2
    assert [%{generation: 2}] = Identities.valid_keys(rotated, DateTime.add(grace, 1))
  end

  test "duplicate fingerprints are rejected across identities" do
    key = public()
    {:ok, ids, _} = Identities.report([], report(%{public_key: key}), @now)

    assert {:error, :duplicate_key} =
             Identities.report(ids, report(%{uid: 1001, username: "ops", public_key: key}), @now)

    assert {:error, :duplicate_key} = Identities.add_external(ids, "ci", key, 90, @now)
  end

  test "external identities are active, replaceable and only flagged when due" do
    assert {:ok, [ext]} = Identities.add_external([], "gh-deploy", public(), 30, @now)
    assert %{origin: "external", status: "active", rotation_overdue: false} = ext
    assert {:error, :invalid_name} = Identities.add_external([ext], "gh-deploy", public(), 30, @now)

    due = DateTime.add(@now, 31 * 86_400)
    assert {[flagged], [{:rotation_overdue, id}]} = Identities.schedule([ext], due)
    assert id == ext.id and flagged.rotation_overdue and flagged.status == "active"
    assert {[^flagged], []} = Identities.schedule([flagged], due)

    assert {:ok, [replaced]} = Identities.replace_external([flagged], ext.id, public(), due)
    refute replaced.rotation_overdue
    assert [%{generation: 1, not_after: %DateTime{}}, %{generation: 2}] = replaced.keys
  end

  test "schedule requests Agent rotation and prunes long-expired keys" do
    {:ok, [identity], _} = Identities.report([], report(), @now)
    {:ok, [active]} = Identities.approve([identity], identity.id, @now)
    due = DateTime.add(@now, 91 * 86_400)
    assert {[requested], [{:rotation_requested, _, 2}]} = Identities.schedule([active], due)

    {:ok, [rotated], _} = Identities.report([requested], report(%{generation: 2}), due)
    much_later = DateTime.add(due, 40 * 86_400)
    {[pruned], events} = Identities.schedule([rotated], much_later)
    assert [%{generation: 2}] = pruned.keys
    assert {:keys_pruned, rotated.id, 1} in events
  end

  test "revocation invalidates every key immediately and blocks reports" do
    {:ok, [identity], _} = Identities.report([], report(), @now)
    {:ok, ids} = Identities.approve([identity], identity.id, @now)
    {:ok, [revoked]} = Identities.revoke(ids, identity.id, @now)
    assert revoked.status == "retired"
    assert Identities.valid_keys(revoked, @now) == []
    assert {:error, :retired} = Identities.report([revoked], report(%{generation: 2}), @now)
  end

  test "rotation days accept nil or 1..3650" do
    {:ok, [ext]} = Identities.add_external([], "ci", public(), 90, @now)
    assert {:ok, [%{rotation_days: nil, next_rotation_at: nil}]} =
             Identities.set_rotation([ext], ext.id, nil, @now)

    assert {:error, :invalid_rotation} = Identities.set_rotation([ext], ext.id, 0, @now)
  end
end
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/identities_test.exs`
Expected: compile error, `SecretHub.Core.SSH.Identities is not available`.

- [ ] **Step 3: Implement the module**

```elixir
defmodule SecretHub.Core.SSH.Identities do
  @moduledoc """
  Pure SSH identity lifecycle over in-memory maps. Core never sees private keys:
  Agents report public keys per generation; operators add external public keys.
  """
  alias SecretHub.Shared.SSH.Key

  @grace_seconds 3 * 86_400
  @retain_expired_seconds 30 * 86_400
  @default_rotation_days 90

  def default_rotation_days, do: @default_rotation_days

  def valid_keys(identity, now), do: Enum.filter(identity.keys, &key_valid?(&1, now))

  def usable?(identity, now),
    do: identity.status == "active" and valid_keys(identity, now) != []

  def current_generation(identity),
    do: identity.keys |> Enum.map(& &1.generation) |> Enum.max(fn -> 0 end)

  def find_agent_identity(identities, agent_id, uid),
    do: Enum.find(identities, &(&1.origin == "agent" and &1.agent_id == agent_id and &1.local_uid == uid))

  def report(identities, report, now) do
    with {:ok, public} <- Key.decode_public(report.public_key) do
      existing = find_agent_identity(identities, report.agent_id, report.uid)

      cond do
        existing && existing.local_username != report.username ->
          {:error, :account_changed}

        existing && same_key?(existing, report.generation, public) ->
          {:ok, identities, :unchanged}

        fingerprint_taken?(identities, public.fingerprint) ->
          {:error, :duplicate_key}

        is_nil(existing) and report.generation == 1 ->
          identity = %{
            id: Ecto.UUID.generate(),
            name: report.username <> "@" <> report.agent_name,
            origin: "agent",
            agent_id: report.agent_id,
            local_username: report.username,
            local_uid: report.uid,
            status: "pending",
            rotation_days: @default_rotation_days,
            next_rotation_at: nil,
            requested_generation: 1,
            rotation_overdue: false,
            keys: [new_key(public, 1, now)]
          }

          {:ok, put(identities, identity), {:reported, identity.id}}

        is_nil(existing) ->
          {:error, :unexpected_generation}

        existing.status == "retired" ->
          {:error, :retired}

        report.generation == existing.requested_generation and
            report.generation == current_generation(existing) + 1 ->
          rotated = supersede(existing, new_key(public, report.generation, now), now)
          {:ok, put(identities, rotated), {:rotated, rotated.id}}

        true ->
          {:error, :unexpected_generation}
      end
    else
      _ -> {:error, :invalid_public_key}
    end
  end

  def approve(identities, id, now) do
    update(identities, id, fn
      %{status: "pending"} = identity ->
        {:ok, %{identity | status: "active", next_rotation_at: next_rotation(identity.rotation_days, now)}}

      _ ->
        {:error, :invalid_change}
    end)
  end

  def revoke(identities, id, now) do
    update(identities, id, fn
      %{status: "retired"} ->
        {:error, :invalid_change}

      identity ->
        keys = Enum.map(identity.keys, &expire_by(&1, now))
        {:ok, %{identity | status: "retired", keys: keys, next_rotation_at: nil}}
    end)
  end

  def add_external(identities, name, public_key, rotation_days, now) do
    with true <- valid_name?(name) and not Enum.any?(identities, &(&1.name == name)) || {:error, :invalid_name},
         true <- valid_rotation?(rotation_days) || {:error, :invalid_rotation},
         {:ok, public} <- decode(public_key),
         false <- fingerprint_taken?(identities, public.fingerprint) && {:error, :duplicate_key} do
      identity = %{
        id: Ecto.UUID.generate(),
        name: name,
        origin: "external",
        agent_id: nil,
        local_username: nil,
        local_uid: nil,
        status: "active",
        rotation_days: rotation_days,
        next_rotation_at: next_rotation(rotation_days, now),
        requested_generation: 1,
        rotation_overdue: false,
        keys: [new_key(public, 1, now)]
      }

      {:ok, put(identities, identity)}
    end
  end

  def replace_external(identities, id, public_key, now) do
    with {:ok, public} <- decode(public_key),
         false <- fingerprint_taken?(identities, public.fingerprint) && {:error, :duplicate_key} do
      update(identities, id, fn
        %{origin: "external", status: "active"} = identity ->
          generation = current_generation(identity) + 1
          rotated = supersede(identity, new_key(public, generation, now), now)
          {:ok, %{rotated | requested_generation: generation, rotation_overdue: false}}

        _ ->
          {:error, :invalid_change}
      end)
    end
  end

  def set_rotation(identities, id, days, now) do
    if valid_rotation?(days) do
      update(identities, id, fn identity ->
        next = if identity.status == "active", do: next_rotation(days, now), else: nil
        {:ok, %{identity | rotation_days: days, next_rotation_at: next}}
      end)
    else
      {:error, :invalid_rotation}
    end
  end

  def request_rotation(identities, id, now) do
    update(identities, id, fn
      %{origin: "agent", status: "active"} = identity ->
        {:ok, request(identity, now)}

      _ ->
        {:error, :invalid_change}
    end)
  end

  @doc "Due rotations and pruning. Returns {identities, events}; events are empty when nothing changed."
  def schedule(identities, now) do
    {updated, events} =
      Enum.map_reduce(identities, [], fn identity, events ->
        {identity, events} = due(identity, now, events)
        prune(identity, now, events)
      end)

    {updated, Enum.reverse(events)}
  end

  defp due(%{status: "active", next_rotation_at: %DateTime{} = at} = identity, now, events) do
    cond do
      DateTime.compare(at, now) == :gt ->
        {identity, events}

      identity.origin == "agent" ->
        requested = request(identity, now)
        {requested, [{:rotation_requested, identity.id, requested.requested_generation} | events]}

      identity.rotation_overdue ->
        {identity, events}

      true ->
        {%{identity | rotation_overdue: true}, [{:rotation_overdue, identity.id} | events]}
    end
  end

  defp due(identity, _, events), do: {identity, events}

  defp prune(identity, now, events) do
    cutoff = DateTime.add(now, -@retain_expired_seconds)

    {expired, kept} =
      Enum.split_with(identity.keys, &(&1.not_after && DateTime.compare(&1.not_after, cutoff) == :lt))

    if expired == [],
      do: {identity, events},
      else: {%{identity | keys: kept}, [{:keys_pruned, identity.id, length(expired)} | events]}
  end

  defp request(identity, now) do
    pending = identity.requested_generation > current_generation(identity)

    %{
      identity
      | requested_generation:
          if(pending, do: identity.requested_generation, else: current_generation(identity) + 1),
        next_rotation_at: next_rotation(identity.rotation_days, now)
    }
  end

  defp supersede(identity, key, now) do
    grace = now |> DateTime.add(@grace_seconds) |> DateTime.truncate(:second)

    keys =
      Enum.map(identity.keys, fn
        %{not_after: nil} = old -> %{old | not_after: grace}
        old -> old
      end)

    %{identity | keys: keys ++ [key], next_rotation_at: next_rotation(identity.rotation_days, now)}
  end

  defp same_key?(identity, generation, public),
    do: Enum.any?(identity.keys, &(&1.generation == generation and &1.fingerprint == public.fingerprint))

  defp fingerprint_taken?(identities, fingerprint),
    do: Enum.any?(identities, fn identity -> Enum.any?(identity.keys, &(&1.fingerprint == fingerprint)) end)

  defp new_key(public, generation, now),
    do: %{
      id: Ecto.UUID.generate(),
      generation: generation,
      public_key: public.public_line,
      fingerprint: public.fingerprint,
      not_after: nil,
      inserted_at: now
    }

  defp expire_by(%{not_after: nil} = key, now), do: %{key | not_after: now}

  defp expire_by(key, now),
    do: if(DateTime.compare(key.not_after, now) == :gt, do: %{key | not_after: now}, else: key)

  defp key_valid?(%{not_after: nil}, _), do: true
  defp key_valid?(%{not_after: at}, now), do: DateTime.compare(at, now) == :gt

  defp next_rotation(nil, _), do: nil
  defp next_rotation(days, now), do: now |> DateTime.add(days * 86_400) |> DateTime.truncate(:second)

  defp valid_rotation?(nil), do: true
  defp valid_rotation?(days), do: is_integer(days) and days in 1..3650

  defp valid_name?(name),
    do: is_binary(name) and Regex.match?(~r/\A[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,99}\z/, name)

  defp decode(public_key) do
    case Key.decode_public(public_key) do
      {:ok, public} -> {:ok, public}
      _ -> {:error, :invalid_public_key}
    end
  end

  defp update(identities, id, fun) do
    case Enum.find(identities, &(&1.id == id)) do
      nil ->
        {:error, :invalid_change}

      identity ->
        with {:ok, updated} <- fun.(identity), do: {:ok, put(identities, updated)}
    end
  end

  defp put(identities, identity),
    do: identities |> Enum.reject(&(&1.id == identity.id)) |> Kernel.++([identity]) |> Enum.sort_by(& &1.id)
end
```

`||` binds more loosely than `and`. `true <- cond || {:error, x}` yields `{:error, x}` when the condition is false, and the `with` passes it through. `false <- taken && {:error, x}` yields `false` (a match, so execution continues) when the fingerprint is free, and `{:error, x}` when it is taken. Do not swap `&&` for `||` here, or a taken fingerprint would return `true` instead of an error.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/identities_test.exs`
Expected: 8 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_core/lib/secrethub_core/ssh/identities.ex apps/secrethub_core/test/secrethub_core/ssh/identities_test.exs
git commit -m "feat(core): add pure SSH identity lifecycle with generation rotation"
```

---

### Task 3: Evaluator over identities

**Files:**
- Rewrite: `apps/secrethub_core/lib/secrethub_core/ssh/evaluator.ex`
- Rewrite: `apps/secrethub_core/test/secrethub_core/ssh/evaluator_test.exs`

- [ ] **Step 1: Replace the test file**

```elixir
defmodule SecretHub.Core.SSH.EvaluatorTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.SSH.Evaluator

  @now ~U[2026-11-12 00:00:00Z]

  defp key(generation, not_after \\ nil),
    do: %{id: "k#{generation}", generation: generation, public_key: "ssh-ed25519 K#{generation}", fingerprint: "F#{generation}", not_after: not_after}

  defp inventory(rules) do
    %{
      groups: [
        %{id: "laptops", name: "Laptops", kind: "identity", identity_ids: ["gao"]},
        %{id: "servers", name: "Servers", kind: "host", agent_ids: ["vultr-01", "vultr-02"]}
      ],
      rules: rules,
      identities: [
        %{id: "gao", status: "active", keys: [key(1)]},
        %{id: "ci", status: "active", keys: [key(1, DateTime.add(@now, -1))]},
        %{id: "phone", status: "pending", keys: [key(1)]}
      ],
      endpoints:
        for agent <- ["vultr-01", "vultr-02"],
            do: %{agent_id: agent, aliases: [agent], port: 22, approved: true, host_keys: ["h"]}
    }
  end

  defp rule(overrides),
    do:
      Map.merge(
        %{
          id: "allow",
          effect: "allow",
          enabled: true,
          source_kind: "identity_group",
          source_id: "laptops",
          destination_kind: "host_group",
          destination_id: "servers",
          destination_user: "gao"
        },
        overrides
      )

  test "default deny, groups expand, exact destination user" do
    assert %{allowed: false} = Evaluator.decision(inventory([]), "gao", "vultr-01", "gao")
    inv = inventory([rule(%{})])
    assert %{allowed: true, allow_rules: ["allow"]} = Evaluator.decision(inv, "gao", "vultr-02", "gao")
    refute Evaluator.decision(inv, "gao", "vultr-02", "root").allowed
    refute Evaluator.decision(inv, "ci", "vultr-02", "gao").allowed
  end

  test "deny wins and direct selectors work" do
    inv =
      inventory([
        rule(%{}),
        rule(%{id: "deny", effect: "deny", source_kind: "identity", source_id: "gao",
          destination_kind: "endpoint", destination_id: "vultr-02"})
      ])

    assert %{allowed: false, deny_rules: ["deny"]} = Evaluator.decision(inv, "gao", "vultr-02", "gao")
    assert Evaluator.decision(inv, "gao", "vultr-01", "gao").allowed
  end

  test "edges include only usable identities and approved endpoints" do
    inv =
      inventory([
        rule(%{}),
        rule(%{id: "ci", source_kind: "identity", source_id: "ci", destination_user: "deploy"}),
        rule(%{id: "phone", source_kind: "identity", source_id: "phone"})
      ])

    assert [
             %{identity_id: "gao", destination_agent_id: "vultr-01", destination_user: "gao"},
             %{identity_id: "gao", destination_agent_id: "vultr-02", destination_user: "gao"}
           ] = Evaluator.edges(inv, @now)
  end

  test "diff reports gained and lost edges" do
    before = inventory([])
    after_inv = inventory([rule(%{})])
    assert %{gained: [_, _], lost: []} = Evaluator.diff(before, after_inv, @now)
    assert %{gained: [], lost: [_, _]} = Evaluator.diff(after_inv, before, @now)
  end
end
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/evaluator_test.exs`
Expected: failures, because `decision/4` and `edges/2` are undefined.

- [ ] **Step 3: Replace the evaluator**

```elixir
defmodule SecretHub.Core.SSH.Evaluator do
  @moduledoc "Pure directed SSH policy: identity sources to endpoint destinations. Deny overrides allow."
  alias SecretHub.Core.SSH.Identities

  def decision(inventory, identity_id, destination, destination_user) do
    matches =
      Enum.filter(inventory.rules, fn rule ->
        rule.enabled and rule.destination_user == destination_user and
          source?(inventory, rule, identity_id) and destination?(inventory, rule, destination)
      end)

    allow = for rule <- matches, rule.effect == "allow", do: rule.id
    deny = for rule <- matches, rule.effect == "deny", do: rule.id
    %{allowed: allow != [] and deny == [], allow_rules: Enum.sort(allow), deny_rules: Enum.sort(deny)}
  end

  def edges(inventory, now \\ DateTime.utc_now()) do
    users = inventory.rules |> Enum.map(& &1.destination_user) |> Enum.uniq()

    for identity <- inventory.identities,
        Identities.usable?(identity, now),
        endpoint <- inventory.endpoints,
        endpoint.approved and endpoint.host_keys != [],
        user <- users,
        decision(inventory, identity.id, endpoint.agent_id, user).allowed do
      %{identity_id: identity.id, destination_agent_id: endpoint.agent_id, destination_user: user}
    end
    |> Enum.uniq()
    |> Enum.sort()
  end

  def diff(before, after_inventory, now \\ DateTime.utc_now()) do
    before_edges = MapSet.new(edges(before, now))
    after_edges = MapSet.new(edges(after_inventory, now))

    %{
      gained: MapSet.difference(after_edges, before_edges) |> Enum.sort(),
      lost: MapSet.difference(before_edges, after_edges) |> Enum.sort()
    }
  end

  def group_members(inventory, kind, id) do
    case Enum.find(inventory.groups, &(&1.id == id and &1.kind == kind)) do
      %{kind: "host", agent_ids: ids} -> ids
      %{kind: "identity", identity_ids: ids} -> ids
      _ -> []
    end
  end

  defp source?(_, %{source_kind: "identity", source_id: id}, identity_id), do: id == identity_id

  defp source?(inventory, %{source_kind: "identity_group", source_id: id}, identity_id),
    do: identity_id in group_members(inventory, "identity", id)

  defp source?(_, _, _), do: false

  defp destination?(_, %{destination_kind: "endpoint", destination_id: id}, agent), do: id == agent

  defp destination?(inventory, %{destination_kind: "host_group", destination_id: id}, agent),
    do: agent in group_members(inventory, "host", id)

  defp destination?(_, _, _), do: false
end
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/evaluator_test.exs`
Expected: 4 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_core/lib/secrethub_core/ssh/evaluator.ex apps/secrethub_core/test/secrethub_core/ssh/evaluator_test.exs
git commit -m "feat(core): evaluate SSH policy from identities to endpoints"
```

---

### Task 4: Management operations and persistence in `SecretHub.Core.SSH`

**Files:**
- Modify: `apps/secrethub_core/lib/secrethub_core/ssh.ex`
- Rewrite: `apps/secrethub_core/test/secrethub_core/ssh/store_test.exs` (management tests only; Task 5 adds the runtime tests)

The module keeps its structure: a revision-locked singleton, `preview/2` and `apply_changes/2`, and a fail-closed seal gate. The third argument of `change/3` is now `now` instead of the master key. The master key is still fetched in `preview/2`, `apply_changes/2`, and `runtime_operation/3`, and `ensure_master_key!/1` still runs before persisting, so sealed Core fails closed.

- [ ] **Step 1: Write the failing management tests**

Replace `store_test.exs`. Keep the existing `setup_all`/`setup` blocks and the `agent/2`, `principal/1`, and `await_state/2` helpers exactly as they are; the rest of this step uses them. Replace the old test bodies with:

```elixir
  test "atomic batches, stale revision, typed groups and no private fields", ctx do
    assert %{revision: 0, identities: [], groups: []} = SSH.snapshot()

    changes = [
      %{"op" => "group_upsert", "id" => "servers", "name" => "Servers", "kind" => "host"},
      %{"op" => "group_members", "group_id" => "servers", "member_ids" => ["target"]},
      %{"op" => "endpoint_upsert", "agent_id" => "target", "aliases" => ["target.example"],
        "port" => 22, "host_keys" => [ctx.host], "approved" => true},
      %{"op" => "identity_external_add", "name" => "gh-deploy", "public_key" => ctx.user_key,
        "rotation_days" => 30}
    ]

    assert {:ok, %{revision: 0, gained: [], lost: []}} = SSH.preview(changes, 0)
    assert SSH.snapshot().revision == 0
    assert {:ok, %{revision: 1, identities: [identity]}} = SSH.apply_changes(changes, 0)
    assert %{name: "gh-deploy", origin: "external", status: "active", keys: [%{generation: 1}]} = identity
    refute inspect(SSH.snapshot()) =~ "PRIVATE KEY"
    assert {:error, :stale_revision} = SSH.apply_changes([], 0)

    rule = %{"op" => "rule_upsert", "id" => "deploy", "effect" => "allow",
      "source_kind" => "identity", "source_id" => identity.id,
      "destination_kind" => "host_group", "destination_id" => "servers", "destination_user" => "deploy"}

    assert {:ok, %{gained: [%{identity_id: id, destination_agent_id: "target", destination_user: "deploy"}]}} =
             SSH.preview([rule], 1)

    assert id == identity.id
    assert {:error, :invalid_change} = SSH.apply_changes([rule, %{"op" => "bogus"}], 1)
    assert {:error, :group_in_use} =
             SSH.apply_changes([rule, %{"op" => "group_delete", "id" => "servers"}], 1)
  end

  test "identity operations: rotation settings, rotate, revoke and external replace", ctx do
    {:ok, %{identities: [ext]}} =
      SSH.apply_changes([%{"op" => "identity_external_add", "name" => "ci",
        "public_key" => ctx.user_key, "rotation_days" => 90}], 0)

    {:ok, other} = Key.generate("ed25519")

    assert {:ok, %{identities: [%{keys: [_, %{generation: 2}], rotation_overdue: false}]}} =
             SSH.apply_changes([%{"op" => "identity_external_replace", "id" => ext.id,
               "public_key" => other.public.public_line}], 1)

    assert {:ok, %{identities: [%{rotation_days: nil}]}} =
             SSH.apply_changes([%{"op" => "identity_rotation", "id" => ext.id, "rotation_days" => nil}], 2)

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{"op" => "identity_rotate", "id" => ext.id}], 3)

    assert {:ok, %{identities: [%{status: "retired"}]}} =
             SSH.apply_changes([%{"op" => "identity_revoke", "id" => ext.id}], 3)

    assert {:error, :duplicate_key} =
             SSH.apply_changes([%{"op" => "identity_external_add", "name" => "dup",
               "public_key" => ctx.user_key, "rotation_days" => 90}], 4)
  end

  test "endpoint collisions, invalid aliases and pending host keys fail closed", ctx do
    base = %{"op" => "endpoint_upsert", "agent_id" => "target", "aliases" => ["shared.example"],
      "port" => 22, "host_keys" => [ctx.host], "approved" => true}

    {:ok, _} = SSH.apply_changes([base], 0)

    assert {:error, :endpoint_conflict} =
             SSH.apply_changes([%{base | "agent_id" => "source"}], 1)

    assert {:error, :invalid_change} =
             SSH.apply_changes([%{base | "aliases" => ["bad host"]}], 1)
  end
```

Also extend the existing `setup` so that it returns `user_key`:

```elixir
    {:ok, user} = Key.generate("ed25519")
    %{source: source, target: target, host: host.public.public_line, user_key: user.public.public_line}
```

Remove every old test that depended on `identity_upsert`, `private_key`, or `source_user`. Task 5 restores the runtime coverage with the new model.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/store_test.exs`
Expected: failures with `:invalid_change` for `identity_external_add` and the `group_members` `member_ids` shape.

- [ ] **Step 3: Change the module header, loading, and persistence**

In `apps/secrethub_core/lib/secrethub_core/ssh.ex`:

1. Replace the aliases and attributes at the top of the module:

```elixir
  import Ecto.Query
  alias SecretHub.Core.{Agents, Audit, Repo}
  alias SecretHub.Core.SSH.{Evaluator, Identities}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Shared.Schemas.SSH.{Identity, IdentityKey, Inventory}
  alias SecretHub.Shared.SSH.Key

  @identity_fields [
    :id,
    :name,
    :origin,
    :agent_id,
    :local_username,
    :local_uid,
    :status,
    :rotation_days,
    :next_rotation_at,
    :requested_generation,
    :rotation_overdue
  ]
  @key_fields [:id, :generation, :public_key, :fingerprint, :not_after, :inserted_at]
  @inventory_fields [:groups, :endpoints, :rules, :reports]
  @mutating_ops ["inventory", "identity_report"]
  @record_keys ~w(id name kind agent_ids identity_ids agent_id aliases port host_keys approved enabled effect source_kind source_id destination_kind destination_id destination_user candidate_host_keys)
```

The `Encryption` alias is removed.

2. Replace `load_inventory/1`:

```elixir
  defp load_inventory(row) do
    %{
      revision: row.revision,
      groups: Enum.map(records(row.groups), &normalize_group/1),
      endpoints: records(row.endpoints),
      rules: records(row.rules),
      reports: row.reports,
      identities:
        Repo.all(from(i in Identity, order_by: i.id, preload: :keys))
        |> Enum.map(fn identity ->
          identity
          |> Map.take(@identity_fields)
          |> Map.put(:keys, Enum.map(identity.keys, &Map.take(&1, @key_fields)))
        end)
    }
  end

  # Groups stored before identity groups existed are host groups.
  defp normalize_group(group) do
    case Map.get(group, :kind, "host") do
      "identity" -> group |> Map.put(:kind, "identity") |> Map.put_new(:identity_ids, [])
      _ -> group |> Map.put(:kind, "host") |> Map.put_new(:agent_ids, [])
    end
  end
```

3. Replace the identity half of `persist!/3`:

```elixir
  defp persist!(row, inventory, revision) do
    row
    |> Ecto.Changeset.change(Map.take(inventory, @inventory_fields) |> Map.put(:revision, revision))
    |> Repo.update!(log: false)

    persist_identities!(inventory.identities)
  end

  defp persist_identities!(identities) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    replace = (@identity_fields -- [:id]) ++ [:updated_at]
    ids = Enum.map(identities, & &1.id)
    # identity_delete removes pending/retired identities; their keys cascade.
    Repo.delete_all(from(i in Identity, where: i.id not in ^ids), log: false)

    for identity <- identities do
      row =
        identity
        |> Map.take(@identity_fields)
        |> Map.merge(%{inserted_at: now, updated_at: now})

      Repo.insert_all(Identity, [row], on_conflict: {:replace, replace}, conflict_target: :id, log: false)
      key_ids = Enum.map(identity.keys, & &1.id)

      Repo.delete_all(
        from(k in IdentityKey, where: k.identity_id == ^identity.id and k.id not in ^key_ids),
        log: false
      )

      keys =
        for key <- identity.keys,
            do:
              key
              |> Map.take(@key_fields)
              |> Map.update!(:inserted_at, &DateTime.truncate(&1, :second))
              |> Map.put(:identity_id, identity.id)

      Repo.insert_all(IdentityKey, keys, on_conflict: {:replace, [:not_after]}, conflict_target: :id, log: false)
    end

    :ok
  end
```

Every `now` passed into `Identities` is truncated to the second by its caller (`preview/2`, `apply_changes/2`, `runtime_operation/3`, `rotate_due/1`), which `:utc_datetime` columns require. The explicit `DateTime.truncate` on `inserted_at` is a backstop.

4. Replace `public_snapshot/1`. Change only the identities and edges entries; the agents part stays the same:

```elixir
    inventory
    |> Map.delete(:reports)
    |> Map.put(:identities, inventory.identities)
    |> Map.put(:agents, agents)
    |> Map.put(:edges, Evaluator.edges(inventory))
```

`inventory.identities` already holds public fields only.

- [ ] **Step 4: Replace the management `change/3` clauses**

Pass `now` instead of `master_key`. In `preview/2` and `apply_changes/2`, call `change_batch!(before, changes, DateTime.utc_now() |> DateTime.truncate(:second))`. In `preview/2`, also pass the post-change identity names to the UI:

```elixir
        diff = Evaluator.diff(before, after_inventory)

        Map.merge(diff, %{
          revision: row.revision,
          changes: scrub_changes(changes),
          identity_names: Map.new(after_inventory.identities, &{&1.id, &1.name})
        })
```

In `apply_changes/2`, replace the audit `identities:` mapping with:

```elixir
            identities:
              Enum.map(inventory.identities, fn identity ->
                identity
                |> Map.take([:id, :name, :origin, :agent_id, :status, :requested_generation])
                |> Map.put(:fingerprints, Enum.map(identity.keys, & &1.fingerprint))
              end)
```

Replace the `group_upsert`, `group_members`, and `group_delete` clauses and every identity clause (`identity_upsert`, `identity_revoke`), and replace the rule clause:

```elixir
  defp change(inventory, %{"op" => "group_upsert", "name" => name} = attrs, _)
       when is_binary(name) and byte_size(name) in 1..100 do
    id = attrs["id"] || Ecto.UUID.generate()
    existing = Enum.find(inventory.groups, &(&1.id == id))
    kind = if existing, do: existing.kind, else: attrs["kind"]

    if valid_id?(id) and kind in ["host", "identity"] and not String.contains?(name, <<0>>) do
      group = existing || normalize_group(%{id: id, kind: kind})
      {:ok, put_record(inventory, :groups, Map.put(group, :name, name))}
    else
      {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "group_members", "group_id" => id, "member_ids" => ids}, _)
       when is_list(ids) and length(ids) <= 10_000 do
    ids = ids |> Enum.uniq() |> Enum.sort()

    case Enum.find(inventory.groups, &(&1.id == id)) do
      %{kind: "host"} = group ->
        if Enum.all?(ids, &agent_exists?/1),
          do: {:ok, put_record(inventory, :groups, %{group | agent_ids: ids})},
          else: {:error, :invalid_change}

      %{kind: "identity"} = group ->
        known = MapSet.new(inventory.identities, & &1.id)

        if Enum.all?(ids, &MapSet.member?(known, &1)),
          do: {:ok, put_record(inventory, :groups, %{group | identity_ids: ids})},
          else: {:error, :invalid_change}

      _ ->
        {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "group_delete", "id" => id}, _) do
    used =
      Enum.any?(
        inventory.rules,
        &((&1.source_kind == "identity_group" and &1.source_id == id) or
            (&1.destination_kind == "host_group" and &1.destination_id == id))
      )

    if used,
      do: {:error, :group_in_use},
      else: {:ok, %{inventory | groups: Enum.reject(inventory.groups, &(&1.id == id))}}
  end

  defp change(inventory, %{"op" => "identity_approve", "id" => id}, now),
    do: identities(inventory, Identities.approve(inventory.identities, id, now))

  defp change(inventory, %{"op" => "identity_delete", "id" => id}, _now) do
    used =
      Enum.any?(inventory.rules, &(&1.source_kind == "identity" and &1.source_id == id)) or
        Enum.any?(inventory.groups, &(&1.kind == "identity" and id in &1.identity_ids))

    if used,
      do: {:error, :identity_in_use},
      else: identities(inventory, Identities.delete(inventory.identities, id))
  end

  defp change(inventory, %{"op" => "identity_revoke", "id" => id}, now),
    do: identities(inventory, Identities.revoke(inventory.identities, id, now))

  defp change(inventory, %{"op" => "identity_rotate", "id" => id}, now),
    do: identities(inventory, Identities.request_rotation(inventory.identities, id, now))

  defp change(inventory, %{"op" => "identity_rotation", "id" => id} = attrs, now)
       when is_map_key(attrs, "rotation_days"),
       do: identities(inventory, Identities.set_rotation(inventory.identities, id, attrs["rotation_days"], now))

  defp change(inventory, %{"op" => "identity_external_add", "name" => name, "public_key" => key} = attrs, now),
    do:
      identities(
        inventory,
        Identities.add_external(inventory.identities, name, key, Map.get(attrs, "rotation_days", Identities.default_rotation_days()), now)
      )

  defp change(inventory, %{"op" => "identity_external_replace", "id" => id, "public_key" => key}, now),
    do: identities(inventory, Identities.replace_external(inventory.identities, id, key, now))

  defp change(inventory, %{"op" => "rule_upsert"} = attrs, _) do
    rule = %{
      id: attrs["id"] || Ecto.UUID.generate(),
      effect: attrs["effect"],
      enabled: Map.get(attrs, "enabled", true),
      source_kind: attrs["source_kind"],
      source_id: attrs["source_id"],
      destination_kind: attrs["destination_kind"],
      destination_id: attrs["destination_id"],
      destination_user: attrs["destination_user"]
    }

    if valid_id?(rule.id) and rule.effect in ["allow", "deny"] and is_boolean(rule.enabled) and
         valid_user?(rule.destination_user) and
         selector_exists?(inventory, rule.source_kind, rule.source_id) and
         selector_exists?(inventory, rule.destination_kind, rule.destination_id) do
      {:ok, put_record(inventory, :rules, rule)}
    else
      {:error, :invalid_change}
    end
  end
```

Add these helpers, and replace `selector_exists?/3`:

```elixir
  defp identities(inventory, {:ok, identities}), do: {:ok, %{inventory | identities: identities}}
  defp identities(_, {:error, reason}), do: {:error, reason}

  defp selector_exists?(inventory, "identity", id), do: Enum.any?(inventory.identities, &(&1.id == id))

  defp selector_exists?(inventory, "identity_group", id),
    do: Enum.any?(inventory.groups, &(&1.id == id and &1.kind == "identity"))

  defp selector_exists?(_, "endpoint", id), do: agent_exists?(id)

  defp selector_exists?(inventory, "host_group", id),
    do: Enum.any?(inventory.groups, &(&1.id == id and &1.kind == "host"))

  defp selector_exists?(_, _, _), do: false
```

`change_batch!/3` must roll back with the operation's specific reason, because the UI maps reasons such as `:duplicate_key` and `:invalid_name` to messages. The existing `{:error, reason} -> Repo.rollback(reason)` already does this.

Delete `provisioning_key/1`, `identity_encryption_key/2`, and the `identity_upsert` clause. Update `scrub_changes/1`:

```elixir
  defp scrub_changes(changes),
    do: Enum.map(changes, &Map.take(&1, @record_keys ++ ~w(op group_id member_ids public_key rotation_days)))
```

- [ ] **Step 5: Continue directly to Task 5**

`ssh.ex` will not compile yet, because the old `authorize_sign` view still calls the removed `Encryption` alias and `identity_encryption_key/2`. Tasks 4 and 5 are one change to `ssh.ex`. Do not run tests or commit here. Do Task 5, then run Task 4's tests and Task 5's tests together, and commit once at the end of Task 5.

---

### Task 5: Runtime views and `identity_report`

**Files:**
- Modify: `apps/secrethub_core/lib/secrethub_core/ssh.ex`
- Test: `apps/secrethub_core/test/secrethub_core/ssh/runtime_test.exs` (new)

- [ ] **Step 1: Write the failing runtime tests**

Create `runtime_test.exs` with the same `setup_all`/`setup` as `store_test.exs`. Copy the `agent/2`, `principal/1`, and `await_state/2` helpers verbatim, and set up two Agents (`source` with both capabilities, `target` with `ssh_lookup_v1`) plus a host key. Add these helpers and tests:

```elixir
  defp enroll(ctx, uid \\ 1000, username \\ "gao") do
    {:ok, key} = Key.generate("ed25519")

    assert {:ok, %{revision: _}} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => uid, "username" => username, "generation" => 1,
               "public_key" => key.public.public_line
             })

    identity = Enum.find(SSH.snapshot().identities, &(&1.local_uid == uid))
    {key, identity}
  end

  defp grant(ctx, identity) do
    rev = SSH.snapshot().revision

    {:ok, _} =
      SSH.apply_changes(
        [
          %{"op" => "identity_approve", "id" => identity.id},
          %{"op" => "endpoint_upsert", "agent_id" => "target", "aliases" => ["target.example"],
            "port" => 22, "host_keys" => [ctx.host], "approved" => true},
          %{"op" => "rule_upsert", "id" => "grant", "effect" => "allow", "source_kind" => "identity",
            "source_id" => identity.id, "destination_kind" => "endpoint", "destination_id" => "target",
            "destination_user" => "app"}
        ],
        rev
      )
  end

  test "report creates a pending identity; authorize_sign never returns key material", ctx do
    {key, identity} = enroll(ctx)
    assert %{status: "pending", name: "gao@source"} = identity
    payload = %{"uid" => 1000, "username" => "gao", "public_key" => key.public.public_line}
    assert {:error, :denied} = SSH.runtime_operation(principal(ctx.source), "authorize_sign", payload)

    grant(ctx, identity)
    assert {:ok, reply} = SSH.runtime_operation(principal(ctx.source), "authorize_sign", payload)
    assert reply.allowed == true and reply.public_key == key.public.public_line
    refute Map.has_key?(reply, :private_key)
    refute inspect(reply) =~ "PRIVATE KEY"

    assert {:ok, %{identities: [%{public_key: _, generation: 1}]}} =
             SSH.runtime_operation(principal(ctx.source), "identities", %{"uid" => 1000, "username" => "gao"})

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{payload | "username" => "eve"})
  end

  test "authorized_keys no longer requires the source Agent to be online", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
    Repo.update!(Ecto.Changeset.change(ctx.source, runtime_capabilities: []))

    assert {:ok, %{lines: ["no-agent-forwarding " <> line]}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "app", "key" => key.public.public_line
             })

    assert line == key.public.public_line

    assert {:ok, %{lines: []}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "root", "key" => key.public.public_line
             })
  end

  test "external identities appear in authorized_keys", ctx do
    {:ok, ext} = Key.generate("ed25519")

    {:ok, %{identities: [identity]}} =
      SSH.apply_changes([%{"op" => "identity_external_add", "name" => "gh-deploy",
        "public_key" => ext.public.public_line, "rotation_days" => 30}], 0)

    rev = SSH.snapshot().revision

    {:ok, _} =
      SSH.apply_changes([
        %{"op" => "endpoint_upsert", "agent_id" => "target", "aliases" => ["target.example"],
          "port" => 22, "host_keys" => [ctx.host], "approved" => true},
        %{"op" => "rule_upsert", "id" => "deploy", "effect" => "allow", "source_kind" => "identity",
          "source_id" => identity.id, "destination_kind" => "endpoint", "destination_id" => "target",
          "destination_user" => "deploy"}
      ], rev)

    assert {:ok, %{lines: [_]}} =
             SSH.runtime_operation(principal(ctx.target), "authorized_keys", %{
               "username" => "deploy", "key" => ext.public.public_line
             })
  end

  test "rotation: inventory carries requested generations and only the next one is accepted", ctx do
    {old, identity} = enroll(ctx)
    grant(ctx, identity)
    {:ok, _} = SSH.apply_changes([%{"op" => "identity_rotate", "id" => identity.id}], SSH.snapshot().revision)

    assert {:ok, %{identity_generations: [%{uid: 1000, requested_generation: 2, generations: [1]}]}} =
             SSH.runtime_operation(principal(ctx.source), "inventory", %{"host_keys" => [], "users" => []})

    {:ok, wrong} = Key.generate("ed25519")

    assert {:error, :denied} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 1000, "username" => "gao", "generation" => 3, "public_key" => wrong.public.public_line
             })

    {:ok, new} = Key.generate("ed25519")

    assert {:ok, _} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => 1000, "username" => "gao", "generation" => 2, "public_key" => new.public.public_line
             })

    for key <- [old, new] do
      assert {:ok, %{allowed: true}} =
               SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
                 "uid" => 1000, "username" => "gao", "public_key" => key.public.public_line
               })
    end
  end

  test "sealed vault fails closed for runtime operations", ctx do
    {key, identity} = enroll(ctx)
    grant(ctx, identity)
    :ok = SealState.seal()

    assert {:error, :sealed} =
             SSH.runtime_operation(principal(ctx.source), "authorize_sign", %{
               "uid" => 1000, "username" => "gao", "public_key" => key.public.public_line
             })
  end
```

Then port the remaining coverage from the old `store_test.exs` (still available in git as `HEAD~1`). The old "release key" assertions become `authorize_sign` `allowed` assertions, and identity setup uses `enroll/1` and `grant/2`:

| Old test | New assertion |
|---|---|
| certificate expiry/revocation, seal and audit failure prevent public release | After expiring or revoking the source certificate, `authorize_sign` returns `{:error, _}`. With `Audit` failing, `runtime_operation` returns `{:error, :audit_unavailable}` |
| audit-triggered revocation observed before release | Same flow, asserting that `authorize_sign` is denied, not that a key is returned |
| not-yet-valid and mismatched certificates | Unchanged except for identity setup |
| IPv6 aliases and nondefault ports | Unchanged, using `known_hosts` with an enrolled source identity |
| candidate inventory never creates approval; missing signing capability fails closed | Unchanged, plus a check that `identity_report` without `ssh_signing_v1` returns `{:error, :capability_unavailable}` |
| reported OS prerequisites are advisory | Unchanged |
| a numeric UID must be an integer | Applies to `identities`, `authorize_sign`, and `identity_report` |

`SealState.seal/0` is the seal function used in the existing seal test. Check the old test for the exact call and reuse it.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/runtime_test.exs`
Expected: failures, because `identity_report` is unsupported and `authorize_sign` returns the old shape.

- [ ] **Step 3: Implement the runtime views**

In `ssh.ex`:

1. In `runtime_operation/3`:
   - Use `lock_inventory(if(operation in @mutating_ops, do: "FOR UPDATE", else: "FOR SHARE"))`.
   - In the `final` recheck, use `if operation in @mutating_ops, do: result, else: runtime_view(load_inventory(lock_inventory("FOR SHARE")), agent_id, operation, payload, now)`.
   - Replace the trailing `if operation == "inventory", do: persist_candidates(...)` with `persist_runtime(operation, inventory, agent_id, final)`.
   - Bind `now = DateTime.utc_now() |> DateTime.truncate(:second)` at the top of the transaction and pass `now` as the fifth argument of `runtime_view`.
   - Replace the outer `case` with:

```elixir
      |> case do
        {:ok, {:ok, %{unchanged: true} = reply}} when operation in @mutating_ops ->
          {:ok, Map.delete(reply, :unchanged)}

        {:ok, {:ok, %{revision: revision} = reply}} when operation in @mutating_ops ->
          broadcast(revision)
          {:ok, reply}

        {:ok, result} ->
          result

        error ->
          error
      end
```

   Add this helper, and use it in `apply_changes/2` in place of the inline broadcast:

```elixir
  defp broadcast(revision) do
    if Process.whereis(SecretHub.Web.PubSub),
      do: Phoenix.PubSub.broadcast(SecretHub.Web.PubSub, "ssh:policy", {:ssh_policy_changed, revision})
  end
```

2. Replace the `identities`, `authorize_sign`, `authorized_keys`, `known_hosts`, and `inventory` clauses of `runtime_view/5`, and add `identity_report`:

```elixir
  defp runtime_view(inventory, agent_id, "identities", payload, now) do
    with true <- local_account?(payload) do
      keys =
        case agent_identity(inventory, agent_id, payload) do
          nil ->
            []

          identity ->
            if Identities.usable?(identity, now) and outgoing?(inventory, identity),
              do: for(key <- Identities.valid_keys(identity, now), do: %{public_key: key.public_key, generation: key.generation}),
              else: []
        end

      {:ok, %{identities: keys, revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "authorize_sign", payload, now) do
    with true <- local_account?(payload),
         {:ok, public} <- Key.decode_public(payload["public_key"]),
         %{} = identity <- agent_identity(inventory, agent_id, payload),
         true <- Identities.usable?(identity, now),
         %{} = key <- Enum.find(Identities.valid_keys(identity, now), &(&1.public_key == public.public_line)),
         true <- outgoing?(inventory, identity) do
      {:ok, %{allowed: true, public_key: key.public_key, generation: key.generation, revision: inventory.revision}}
    else
      _ -> {:error, :denied}
    end
  end

  defp runtime_view(inventory, agent_id, "authorized_keys", payload, now) do
    with true <- valid_user?(payload["username"]),
         {:ok, public} <- Key.decode_public(payload["key"]) do
      lines =
        for identity <- inventory.identities,
            Identities.usable?(identity, now),
            key <- Identities.valid_keys(identity, now),
            key.public_key == public.public_line,
            approved_endpoint?(inventory, agent_id),
            Evaluator.decision(inventory, identity.id, agent_id, payload["username"]).allowed,
            do: "no-agent-forwarding " <> key.public_key

      {:ok, %{lines: Enum.uniq(lines), revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "known_hosts", payload, now) do
    with true <- local_account?(payload),
         true <- payload["reason"] in ["ORDER", "HOSTNAME", "ADDRESS"],
         true <- is_integer(payload["port"]) and payload["port"] in 1..65_535,
         {:ok, host} <- lookup_alias(payload["host"], payload["port"]) do
      lines =
        for identity <- List.wrap(agent_identity(inventory, agent_id, payload)),
            Identities.usable?(identity, now),
            endpoint <- inventory.endpoints,
            endpoint.approved and endpoint.host_keys != [],
            endpoint.port == payload["port"] and host in endpoint.aliases,
            live_agent?(endpoint.agent_id, "ssh_lookup_v1"),
            outgoing_to?(inventory, identity, endpoint.agent_id),
            key <- endpoint.host_keys,
            do: known_host_name(host, endpoint.port) <> " " <> key

      {:ok, %{lines: Enum.uniq(lines), revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "inventory", payload, _now) do
    with {:ok, keys} <- public_keys(Map.get(payload, "host_keys", [])),
         {:ok, users} <- reported_users(Map.get(payload, "users", [])) do
      endpoint = Enum.find(inventory.endpoints, &(&1.agent_id == agent_id))
      report = Map.get(inventory.reports, agent_id)

      unchanged =
        endpoint != nil and report != nil and Map.get(endpoint, :candidate_host_keys, []) == keys and
          report["users"] == users

      {:ok,
       %{
         revision: inventory.revision + if(unchanged, do: 0, else: 1),
         candidate_host_keys: keys,
         users: users,
         unchanged: unchanged,
         identity_generations: identity_generations(inventory, agent_id)
       }}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "identity_report", payload, now) do
    with true <- local_account?(payload),
         true <- is_integer(payload["generation"]) and payload["generation"] >= 1,
         %Agent{} = agent <- Repo.get_by(Agent, agent_id: agent_id),
         {:ok, identities, event} <-
           Identities.report(
             inventory.identities,
             %{
               agent_id: agent_id,
               agent_name: agent.name || agent_id,
               uid: payload["uid"],
               username: payload["username"],
               generation: payload["generation"],
               public_key: payload["public_key"]
             },
             now
           ) do
      unchanged = event == :unchanged

      {:ok,
       %{
         revision: inventory.revision + if(unchanged, do: 0, else: 1),
         unchanged: unchanged,
         identities: identities
       }}
    else
      _ -> {:error, :denied}
    end
  end
```

3. Add or replace these helpers:

```elixir
  defp local_account?(payload),
    do: is_integer(payload["uid"]) and payload["uid"] in 0..4_294_967_295 and valid_user?(payload["username"])

  defp agent_identity(inventory, agent_id, payload) do
    case Identities.find_agent_identity(inventory.identities, agent_id, payload["uid"]) do
      %{local_username: username} = identity when username == payload["username"] -> identity
      _ -> nil
    end
  end

  defp identity_generations(inventory, agent_id) do
    now = DateTime.utc_now()

    for identity <- inventory.identities,
        identity.origin == "agent" and identity.agent_id == agent_id and identity.status != "retired",
        do: %{
          uid: identity.local_uid,
          requested_generation: identity.requested_generation,
          generations: Enum.map(Identities.valid_keys(identity, now), & &1.generation)
        }
  end

  defp outgoing?(inventory, identity),
    do:
      Enum.any?(
        inventory.endpoints,
        &(approved_endpoint?(inventory, &1.agent_id) and outgoing_to?(inventory, identity, &1.agent_id))
      )

  defp outgoing_to?(inventory, identity, destination),
    do:
      Enum.any?(inventory.rules, fn rule ->
        Evaluator.decision(inventory, identity.id, destination, rule.destination_user).allowed
      end)

  defp persist_runtime("inventory", inventory, agent_id, result),
    do: persist_candidates(inventory, agent_id, result)

  defp persist_runtime("identity_report", _inventory, _agent_id, {:ok, %{unchanged: true} = reply}),
    do: {:ok, Map.delete(reply, :identities)}

  defp persist_runtime("identity_report", inventory, _agent_id, {:ok, %{revision: revision, identities: identities}}) do
    persist!(Repo.get!(Inventory, 1), %{inventory | identities: identities}, revision)
    {:ok, %{revision: revision, accepted: true}}
  end

  defp persist_runtime(_, _, _, result), do: result
```

Change `persist_candidates/3` so that both success clauses pass `identity_generations` through:

```elixir
  defp persist_candidates(_, _, {:ok, %{unchanged: true} = reply}),
    do: {:ok, Map.take(reply, [:unchanged, :revision, :identity_generations])}

  defp persist_candidates(inventory, agent_id, {:ok, %{candidate_host_keys: keys, users: users, revision: revision} = reply}) do
    # unchanged body up to persist!, then:
    {:ok, %{revision: revision, identity_generations: reply.identity_generations}}
  end
```

Delete `source_identities/3`. Remove `live_agent?(identity.agent_id, "ssh_signing_v1")`; endpoints still use `live_agent?/2` through `approved_endpoint?/2`.

4. Add `identity_report` to `capability/2`:

```elixir
        operation when operation in ["identities", "authorize_sign", "identity_report"] -> ["ssh_signing_v1"]
```

5. Replace `decision_granted?/1` and `audit_metadata/5`:

```elixir
  defp decision_granted?({:ok, %{lines: lines}}), do: lines != []
  defp decision_granted?({:ok, %{identities: identities}}) when is_list(identities), do: identities != []
  defp decision_granted?({:ok, _}), do: true
  defp decision_granted?(_), do: false

  defp audit_metadata(inventory, agent_id, operation, payload, result) do
    identity =
      if is_integer(payload["uid"]),
        do: Identities.find_agent_identity(inventory.identities, agent_id, payload["uid"])

    presented =
      case Key.decode_public(payload["public_key"] || payload["key"]) do
        {:ok, public} -> public
        _ -> nil
      end

    identity =
      identity ||
        (presented &&
           Enum.find(inventory.identities, fn i -> Enum.any?(i.keys, &(&1.public_key == presented.public_line)) end))

    endpoint =
      Enum.find(inventory.endpoints, fn endpoint ->
        operation == "known_hosts" and endpoint.port == payload["port"] and
          match?({:ok, _}, lookup_alias(payload["host"], payload["port"])) and
          elem(lookup_alias(payload["host"], payload["port"]), 1) in endpoint.aliases
      end)

    %{}
    |> put_present(identity, &%{"source_identity_id" => &1.id, "source_identity_name" => &1.name, "source_origin" => &1.origin})
    |> put_present(presented, &%{"key_fingerprint" => &1.fingerprint})
    |> put_present(valid_user?(payload["username"]) && payload["username"], &%{"username" => &1})
    |> put_present(is_integer(payload["uid"]) && payload["uid"] in 0..4_294_967_295 && payload["uid"], &%{"uid" => &1})
    |> put_present(is_integer(payload["generation"]) && payload["generation"], &%{"generation" => &1})
    |> put_present(payload["reason"] in ["ORDER", "HOSTNAME", "ADDRESS"] && payload["reason"], &%{"reason" => &1})
    |> put_present(endpoint, &%{"destination_agent_id" => &1.agent_id, "destination_port" => &1.port})
    |> put_present(operation == "authorized_keys" and valid_user?(payload["username"]) && payload["username"],
      &%{"destination_agent_id" => agent_id, "destination_user" => &1})
    |> put_present(match?({:error, _}, result) && elem(result, 1), &%{"error" => to_string(&1)})
  end

  defp put_present(metadata, value, _) when value in [nil, false], do: metadata
  defp put_present(metadata, value, fun), do: Map.merge(metadata, fun.(value))
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_core/test/secrethub_core/ssh/`
Expected: every SSH Core test passes, including Task 4's `store_test.exs`.

- [ ] **Step 5: Commit Tasks 4 and 5 together**

```bash
git add apps/secrethub_core/lib/secrethub_core/ssh.ex apps/secrethub_core/test/secrethub_core/ssh/
git commit -m "feat(core): manage device-held SSH identities, typed groups and identity rules"
```

---

### Task 6: Scheduled rotation (Styx)

**Files:**
- Modify: `apps/secrethub_core/lib/secrethub_core/ssh.ex` (add `rotate_due/1`)
- Create: `apps/secrethub_core/lib/secrethub_core/workers/ssh_identity_rotation_worker.ex`
- Modify: `config/config.exs`
- Test: `apps/secrethub_core/test/secrethub_core/workers/ssh_identity_rotation_worker_test.exs`

- [ ] **Step 1: Write the failing test**

Use the same `setup_all`/`setup`/helpers as `runtime_test.exs`, including `enroll/2` and `grant/2`. Copy them; do not share them through a support module.

```elixir
  test "due Agent identities get rotation requests and external ones only a flag", ctx do
    {_, identity} = enroll(ctx)
    grant(ctx, identity)
    {:ok, ext} = Key.generate("ed25519")

    {:ok, _} =
      SSH.apply_changes([%{"op" => "identity_external_add", "name" => "ci",
        "public_key" => ext.public.public_line, "rotation_days" => 1}], SSH.snapshot().revision)

    later = DateTime.add(DateTime.utc_now(), 2 * 86_400)
    assert {:ok, events} = SSH.rotate_due(later)
    assert Enum.any?(events, &match?({:rotation_overdue, _}, &1))
    refute Enum.any?(events, &match?({:rotation_requested, _, _}, &1))

    agent_due = DateTime.add(DateTime.utc_now(), 91 * 86_400)
    assert {:ok, [{:rotation_requested, id, 2}]} = SSH.rotate_due(agent_due)
    assert id == identity.id
    assert {:ok, []} = SSH.rotate_due(agent_due)

    assert %{status: "active", rotation_overdue: true} =
             Enum.find(SSH.snapshot().identities, &(&1.name == "ci"))

    assert Repo.exists?(from(e in SecretHub.Shared.Schemas.AuditLog,
             where: e.event_type == "ssh.identity_rotation_requested"))
  end

  test "worker performs and returns :ok" do
    assert :ok = SecretHub.Core.Workers.SSHIdentityRotationWorker.perform(nil)
  end
```

Before using `SecretHub.Shared.Schemas.AuditLog`, confirm the audit schema module name with `grep -rn "defmodule .*AuditLog" apps/secrethub_shared/lib` and use the name it reports. Import `Ecto.Query` in the test module.

The first `rotate_due(later)` runs two days ahead, which is still before the Agent identity's 90-day `next_rotation_at`. That is why only the external identity gets flagged there.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `test-all apps/secrethub_core/test/secrethub_core/workers/ssh_identity_rotation_worker_test.exs`
Expected: `SSH.rotate_due/1 is undefined`.

- [ ] **Step 3: Implement `rotate_due/1` in `ssh.ex`**

```elixir
  @doc "Applies due rotations, overdue flags and key pruning. Returns {:ok, events}."
  def rotate_due(now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)

    with {:ok, master_key} <- master_key() do
      Repo.transaction(fn ->
        row = lock_inventory("FOR UPDATE")
        inventory = load_inventory(row)

        case Identities.schedule(inventory.identities, now) do
          {_, []} ->
            []

          {identities, events} ->
            revision = row.revision + 1

            for event <- events do
              {name, data} = rotation_audit(event)
              audit!(name, "system", "ssh_identity_rotation", revision, true, data)
            end

            ensure_master_key!(master_key)
            persist!(row, %{inventory | identities: identities}, revision)
            {revision, events}
        end
      end)
      |> case do
        {:ok, []} -> {:ok, []}
        {:ok, {revision, events}} ->
          broadcast(revision)
          {:ok, events}

        error ->
          error
      end
    end
  end

  defp rotation_audit({:rotation_requested, id, generation}),
    do: {"identity_rotation_requested", %{"identity_id" => id, "generation" => generation}}

  defp rotation_audit({:rotation_overdue, id}), do: {"identity_rotation_overdue", %{"identity_id" => id}}

  defp rotation_audit({:keys_pruned, id, count}),
    do: {"identity_keys_pruned", %{"identity_id" => id, "count" => count}}
```

- [ ] **Step 4: Implement the worker and register it**

```elixir
defmodule SecretHub.Core.Workers.SSHIdentityRotationWorker do
  @moduledoc "Hourly SSH identity rotation: requests Agent rotations, flags due external keys, prunes old keys."
  use Styx.Worker,
    queue: :ssh,
    max_attempts: 3,
    unique: [period: 3000, states: [:available, :scheduled, :executing, :retryable]]

  require Logger

  @impl true
  def perform(_) do
    case SecretHub.Core.SSH.rotate_due() do
      {:ok, _events} ->
        :ok

      {:error, :sealed} ->
        :ok

      {:error, reason} ->
        Logger.warning("SSH identity rotation failed", reason: inspect(reason))
        {:error, reason}
    end
  end
end
```

A sealed vault returns `:ok`, so Styx does not burn retries while sealed. The next hourly run picks up any due work.

In `config/config.exs`, change the `SecretHub.Core.Styx` block:

```elixir
  queues: [acme: 4, acme_cleanup: 2, ssh: 1],
  ...
    {Styx.Plugins.Cron,
     crontab: [
       {"* * * * *", SecretHub.Core.PKI.ACME.Reconciler},
       {"7 * * * *", SecretHub.Core.Workers.SSHIdentityRotationWorker}
     ]}
```

Check `config/test.exs` for the `SecretHub.Core.Styx` override. It must keep test queues and plugins inert; leave it unchanged if it already does.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_core/test/secrethub_core/workers/ssh_identity_rotation_worker_test.exs apps/secrethub_core/test/secrethub_core/ssh/`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_core/lib/secrethub_core/ssh.ex apps/secrethub_core/lib/secrethub_core/workers/ssh_identity_rotation_worker.ex config/config.exs apps/secrethub_core/test/secrethub_core/workers/ssh_identity_rotation_worker_test.exs
git commit -m "feat(core): schedule SSH identity rotation on Styx"
```

---

### Task 7: Runtime channel accepts `identity_report`

**Files:**
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex:274-326`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/ssh_runtime_channel_test.exs`

- [ ] **Step 1: Write the failing test**

Add this test to `ssh_runtime_channel_test.exs`. It uses the test's existing join helpers; reuse the socket setup from "SSH calls derive the Agent from the certificate":

```elixir
  test "identity_report requires signing and derives the Agent from the certificate", ctx do
    {:ok, _, socket} = join_with(ctx, ["ssh_signing_v1"])
    {:ok, key} = SecretHub.Shared.SSH.Key.generate("ed25519")

    payload = %{"uid" => 1000, "username" => "gao", "generation" => 1,
      "public_key" => key.public.public_line, "agent_id" => "forged"}

    assert {:reply, {:ok, %{accepted: true}}, _} =
             AgentRuntimeChannel.handle_in("ssh:identity_report", payload, socket)

    assert [%{agent_id: agent_id}] = SecretHub.Core.SSH.snapshot().identities
    assert agent_id == ctx.agent.agent_id

    {:ok, _, lookup_only} = join_with(ctx, ["ssh_lookup_v1"])

    assert {:reply, {:error, %{reason: "SSH_UNAVAILABLE"}}, _} =
             AgentRuntimeChannel.handle_in("ssh:identity_report", payload, lookup_only)
  end
```

If the file has no `join_with/2` helper, add one around the join call that the existing tests use, parameterized by the advertised capabilities. Use the same `AgentRuntimeChannel.join("agent:runtime", payload, socket)` shape that the file already has.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `test-all apps/secrethub_web/test/secrethub_web/channels/ssh_runtime_channel_test.exs`
Expected: `unknown_event` reply.

- [ ] **Step 3: Implement**

In `agent_runtime_channel.ex`, add `"identity_report"` to the guard list. In `supported`, add it to the signing branch:

```elixir
          op when op in ["identities", "authorize_sign", "identity_report"] -> "ssh_signing_v1" in negotiated
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_web/test/secrethub_web/channels/`
Expected: all pass. Update existing assertions that expect a `private_key` field in `authorize_sign` replies so they expect `allowed: true` instead.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex apps/secrethub_web/test/secrethub_web/channels/ssh_runtime_channel_test.exs
git commit -m "feat(web): route Agent SSH identity reports"
```

---

### Task 8: Agent device-local key store

**Files:**
- Create: `apps/secrethub_agent/lib/secrethub_agent/ssh/key_store.ex`
- Test: `apps/secrethub_agent/test/secrethub_agent/ssh/key_store_test.exs`

- [ ] **Step 1: Write the failing tests**

```elixir
defmodule SecretHub.Agent.SSH.KeyStoreTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.KeyStore
  @moduletag :tmp_dir

  test "creates owner-only key files per uid and generation", %{tmp_dir: root} do
    assert KeyStore.generations(1000, root) == []
    assert {:ok, %{generation: 1, public: public, private_pem: pem}} = KeyStore.create(1000, 1, root)
    assert pem =~ "PRIVATE KEY"
    assert {:error, :exists} = KeyStore.create(1000, 1, root)
    assert KeyStore.generations(1000, root) == [1]
    assert KeyStore.uids(root) == [1000]

    assert {:ok, %{mode: dir_mode}} = File.stat(Path.join(root, "1000"))
    assert Bitwise.band(dir_mode, 0o777) == 0o700
    assert {:ok, %{mode: file_mode}} = File.stat(Path.join([root, "1000", "1.key"]))
    assert Bitwise.band(file_mode, 0o777) == 0o600

    assert {:ok, %{generation: 1}} = KeyStore.find_by_blob(1000, public.blob, root)
    assert {:error, :not_found} = KeyStore.find_by_blob(1001, public.blob, root)
  end

  test "prune keeps only listed generations", %{tmp_dir: root} do
    for generation <- 1..3, do: {:ok, _} = KeyStore.create(1000, generation, root)
    :ok = KeyStore.prune(1000, [2, 3], root)
    assert KeyStore.generations(1000, root) == [2, 3]
  end

  test "ignores foreign files and invalid names", %{tmp_dir: root} do
    File.mkdir_p!(Path.join(root, "notauid"))
    File.mkdir_p!(Path.join(root, "1000"))
    File.write!(Path.join([root, "1000", "junk"]), "x")
    assert KeyStore.uids(root) == [1000]
    assert KeyStore.generations(1000, root) == []
  end
end
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_agent/test/secrethub_agent/ssh/key_store_test.exs`
Expected: `KeyStore` is undefined.

- [ ] **Step 3: Implement**

```elixir
defmodule SecretHub.Agent.SSH.KeyStore do
  @moduledoc """
  Device-local SSH identity keys under <state_dir>/ssh-identities/<uid>/<generation>.key.
  Owner-only files; private keys never leave this directory.
  """
  alias SecretHub.Shared.SSH.Key

  def root, do: Path.join(Application.fetch_env!(:secrethub_agent, :state_dir), "ssh-identities")

  def uids(root \\ root()) do
    case File.ls(root) do
      {:ok, names} ->
        names |> Enum.flat_map(&integer/1) |> Enum.filter(&File.dir?(Path.join(root, to_string(&1)))) |> Enum.sort()

      _ ->
        []
    end
  end

  def generations(uid, root \\ root()) do
    case File.ls(dir(uid, root)) do
      {:ok, names} ->
        names
        |> Enum.flat_map(fn name ->
          case String.split(name, ".") do
            [number, "key"] -> integer(number)
            _ -> []
          end
        end)
        |> Enum.sort()

      _ ->
        []
    end
  end

  def load(uid, generation, root \\ root()) do
    with {:ok, pem} <- File.read(path(uid, generation, root)),
         {:ok, imported} <- Key.import_private(pem) do
      {:ok, %{generation: generation, private_pem: imported.private_pem, public: imported.public}}
    else
      _ -> {:error, :not_found}
    end
  end

  def find_by_blob(uid, blob, root \\ root()) do
    uid
    |> generations(root)
    |> Enum.find_value({:error, :not_found}, fn generation ->
      case load(uid, generation, root) do
        {:ok, %{public: %{blob: ^blob}} = key} -> {:ok, key}
        _ -> nil
      end
    end)
  end

  def create(uid, generation, root \\ root())
      when is_integer(uid) and uid >= 0 and is_integer(generation) and generation >= 1 do
    directory = dir(uid, root)
    :ok = File.mkdir_p(directory)
    :ok = File.chmod(directory, 0o700)
    {:ok, key} = Key.generate("ed25519")
    target = path(uid, generation, root)

    case File.open(target, [:write, :exclusive, :binary]) do
      {:ok, file} ->
        :ok = File.chmod(target, 0o600)
        :ok = IO.binwrite(file, key.private_pem)
        :ok = File.close(file)
        {:ok, %{generation: generation, private_pem: key.private_pem, public: key.public}}

      {:error, :eexist} ->
        {:error, :exists}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def prune(uid, keep, root \\ root()) do
    for generation <- generations(uid, root), generation not in keep do
      File.rm(path(uid, generation, root))
    end

    :ok
  end

  defp dir(uid, root), do: Path.join(root, Integer.to_string(uid))
  defp path(uid, generation, root), do: Path.join(dir(uid, root), "#{generation}.key")

  defp integer(text) do
    case Integer.parse(text) do
      {number, ""} when number >= 0 -> [number]
      _ -> []
    end
  end
end
```

`chmod` runs before the private key is written, so the file is never readable by others. `<state_dir>` is already verified as mode 0700 by `identity_store.ex`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_agent/test/secrethub_agent/ssh/key_store_test.exs`
Expected: 3 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_agent/lib/secrethub_agent/ssh/key_store.ex apps/secrethub_agent/test/secrethub_agent/ssh/key_store_test.exs
git commit -m "feat(agent): keep SSH identity keys on the device"
```

---

### Task 9: Agent reconciler and inventory wiring

**Files:**
- Create: `apps/secrethub_agent/lib/secrethub_agent/ssh/reconciler.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/ssh/lookup.ex:84-88`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex:702-716`
- Test: `apps/secrethub_agent/test/secrethub_agent/ssh/reconciler_test.exs`

- [ ] **Step 1: Write the failing tests**

```elixir
defmodule SecretHub.Agent.SSH.ReconcilerTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.{KeyStore, Reconciler}
  @moduletag :tmp_dir

  setup %{tmp_dir: root} do
    parent = self()

    request = fn operation, payload ->
      send(parent, {operation, payload})
      {:ok, %{"accepted" => true}}
    end

    account = fn uid -> {:ok, %{uid: uid, username: "u#{uid}"}} end
    %{root: root, request: request, account: account}
  end

  test "first use creates generation 1 and reports only its public key", ctx do
    :ok = Reconciler.ensure_enrolled(%{uid: 1000, username: "gao"}, ctx.request, ctx.root)
    assert_receive {"identity_report", %{"uid" => 1000, "username" => "gao", "generation" => 1, "public_key" => line}}
    refute line =~ "PRIVATE"
    :ok = Reconciler.ensure_enrolled(%{uid: 1000, username: "gao"}, ctx.request, ctx.root)
    refute_receive {"identity_report", _}
  end

  test "requested generation creates and reports the next key; prune keeps valid ones", ctx do
    {:ok, _} = KeyStore.create(1000, 1, ctx.root)

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 2, "generations" => [1]}],
        ctx.request, ctx.root, ctx.account
      )

    assert_receive {"identity_report", %{"generation" => 2}}
    assert KeyStore.generations(1000, ctx.root) == [1, 2]

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 2, "generations" => [2]}],
        ctx.request, ctx.root, ctx.account
      )

    refute_receive {"identity_report", _}
    assert KeyStore.generations(1000, ctx.root) == [2]
  end

  test "unknown to Core re-reports generation 1; a lost report is retried", ctx do
    {:ok, _} = KeyStore.create(1000, 1, ctx.root)
    :ok = Reconciler.reconcile([], ctx.request, ctx.root, ctx.account)
    assert_receive {"identity_report", %{"generation" => 1}}

    {:ok, _} = KeyStore.create(1000, 2, ctx.root)

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 2, "generations" => [1]}],
        ctx.request, ctx.root, ctx.account
      )

    assert_receive {"identity_report", %{"generation" => 2}}
  end

  test "an empty valid list (retired identity) keeps local keys", ctx do
    {:ok, _} = KeyStore.create(1000, 1, ctx.root)

    :ok =
      Reconciler.reconcile(
        [%{"uid" => 1000, "requested_generation" => 1, "generations" => []}],
        ctx.request, ctx.root, ctx.account
      )

    assert KeyStore.generations(1000, ctx.root) == [1]
  end
end
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_agent/test/secrethub_agent/ssh/reconciler_test.exs`
Expected: `Reconciler` is undefined.

- [ ] **Step 3: Implement the reconciler**

```elixir
defmodule SecretHub.Agent.SSH.Reconciler do
  @moduledoc """
  First-use identity enrollment and pull-based rotation. Core requests a
  generation; the Agent generates it locally and reports only the public key.
  """
  alias SecretHub.Agent.SSH.{Identity, KeyStore}

  def ensure_enrolled(account, request, root \\ KeyStore.root()) do
    if KeyStore.generations(account.uid, root) == [] do
      with {:ok, key} <- KeyStore.create(account.uid, 1, root), do: report(account, key, request)
    end

    :ok
  end

  def reconcile(requests, request, root \\ KeyStore.root(), account \\ &Identity.account/1)
      when is_list(requests) do
    by_uid = Map.new(requests, &{&1["uid"], &1})

    for uid <- KeyStore.uids(root), {:ok, local} <- [account.(uid)] do
      reconcile_uid(local, Map.get(by_uid, uid), request, root)
    end

    :ok
  end

  def reconcile(_, _, _, _), do: :ok

  @doc "Connection entry point: reconciles after an inventory reply when signing is enabled."
  def after_inventory({:ok, reply}, connection) when is_map(reply) do
    if Application.get_env(:secrethub_agent, :ssh_signing_enabled) == true do
      request = fn operation, payload ->
        SecretHub.Agent.Connection.ssh_request(connection, operation, payload, 5000)
      end

      reconcile(SecretHub.Agent.SSH.Lookup.value(reply, "identity_generations") || [], request)
    end

    :ok
  end

  def after_inventory(_, _), do: :ok

  defp reconcile_uid(account, nil, request, root) do
    with {:ok, key} <- KeyStore.load(account.uid, 1, root), do: report(account, key, request)
  end

  defp reconcile_uid(account, %{"requested_generation" => requested, "generations" => valid}, request, root)
       when is_integer(requested) and is_list(valid) do
    latest = account.uid |> KeyStore.generations(root) |> Enum.max(fn -> 0 end)

    cond do
      requested > latest ->
        with {:ok, key} <- KeyStore.create(account.uid, requested, root), do: report(account, key, request)

      requested == latest and requested not in valid ->
        with {:ok, key} <- KeyStore.load(account.uid, requested, root), do: report(account, key, request)

      true ->
        :ok
    end

    if valid != [], do: KeyStore.prune(account.uid, Enum.uniq([requested | valid]), root)
  end

  defp reconcile_uid(_, _, _, _), do: :ok

  defp report(account, key, request) do
    request.("identity_report", %{
      "uid" => account.uid,
      "username" => account.username,
      "generation" => key.generation,
      "public_key" => key.public.public_line
    })
  end
end
```

- [ ] **Step 4: Wire into Lookup and Connection**

In `lookup.ex`, extend the atom-key fallback:

```elixir
  defp existing_key("lines"), do: :lines
  defp existing_key("identities"), do: :identities
  defp existing_key("public_key"), do: :public_key
  defp existing_key("allowed"), do: :allowed
  defp existing_key("identity_generations"), do: :identity_generations
```

Delete the `"private_key"` clause, because the Agent no longer reads private keys from Core replies.

In `connection.ex`, change the `:ssh_inventory` task body (around line 707):

```elixir
        Task.Supervisor.start_child(SecretHub.Agent.SSH.Tasks, fn ->
          connection
          |> SecretHub.Agent.SSH.Inventory.report()
          |> SecretHub.Agent.SSH.Reconciler.after_inventory(connection)
        end)
```

Core's reply arrives over the channel as JSON, so `identity_generations` entries have string keys (`"uid"`, `"requested_generation"`, `"generations"`), which is what `reconcile/4` matches on. `Inventory.report/1` returns `{:error, _}` when no inventory is available; `after_inventory/2` ignores that.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_agent/test/secrethub_agent/ssh/`
Expected: the reconciler tests pass. `server_test` may still fail; Task 10 fixes it.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_agent/lib/secrethub_agent/ssh/reconciler.ex apps/secrethub_agent/lib/secrethub_agent/ssh/lookup.ex apps/secrethub_agent/lib/secrethub_agent/connection.ex apps/secrethub_agent/test/secrethub_agent/ssh/reconciler_test.exs
git commit -m "feat(agent): reconcile SSH identity generations with Core"
```

---

### Task 10: Agent signs locally

**Files:**
- Modify: `apps/secrethub_agent/lib/secrethub_agent/ssh/server.ex:14-30,165-210`
- Modify: `apps/secrethub_agent/test/secrethub_agent/ssh/server_test.exs`

- [ ] **Step 1: Write the failing test**

In `server_test.exs`, pass `key_root: ctx.dir` to every signing `Server` child spec. Replace the first test with:

```elixir
  test "first use enrolls locally, lists Core-authorized keys and signs without key material", ctx do
    {:ok, identity} = Identity.current()
    parent = self()
    key_root = Path.join(ctx.dir, "keys")

    request = fn
      "identity_report", payload ->
        send(parent, {:report, payload})
        {:ok, %{"accepted" => true}}

      "identities", payload ->
        send(parent, {:identities, payload})
        {:ok, local} = SecretHub.Agent.SSH.KeyStore.load(identity.uid, 1, key_root)
        {:ok, %{"identities" => [%{"public_key" => local.public.public_line, "generation" => 1}]}}

      "authorize_sign", payload ->
        send(parent, {:authorize, payload})
        {:ok, %{"allowed" => true, "public_key" => payload["public_key"]}}
    end

    path = Path.join(ctx.dir, "sign.sock")

    start_supervised!(
      {Server, path: path, kind: :signing, task_supervisor: ctx.task_supervisor,
       request: request, key_root: key_root}
    )

    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: 4])
    :ok = :gen_tcp.send(socket, <<11>>)
    assert {:ok, <<12, 1::32, _::binary>>} = :gen_tcp.recv(socket, 0, 2000)
    assert_receive {:report, %{"uid" => uid, "generation" => 1, "public_key" => line}}
    assert uid == identity.uid
    refute line =~ "PRIVATE"
    assert_receive {:identities, %{"uid" => ^uid}}

    {:ok, local} = SecretHub.Agent.SSH.KeyStore.load(identity.uid, 1, key_root)
    blob = local.public.blob
    data = "challenge"
    sign = <<13, byte_size(blob)::32, blob::binary, byte_size(data)::32, data::binary, 0::32>>
    :ok = :gen_tcp.send(socket, sign)
    assert {:ok, <<14, _::binary>>} = :gen_tcp.recv(socket, 0, 2000)
    assert_receive {:authorize, %{"public_key" => _}}
    :gen_tcp.close(socket)
  end
```

Keep the existing assertions for the forged-identity and mutation rejections (the `<<17>>` request returns `<<5>>`) by adding them after the sign step. Adjust the other tests that start a signing server so their `request` callbacks accept `"identity_report"`.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `test-all apps/secrethub_agent/test/secrethub_agent/ssh/server_test.exs`
Expected: no `:report` message, and the identities answer has count 0.

- [ ] **Step 3: Implement**

In `server.ex`:

1. In `init/1`, keep `key_root: Keyword.get(opts, :key_root)` in the config map that is passed to `serve/3`. Read the existing `init/1` (lines 14–30) and add the field next to `:request`.

2. Replace `sign_operation/3`, and pass the config's key root:

```elixir
  defp signing(payload, uid, request, deadline, key_root) do
    with {:ok, identity} <- Identity.account(uid, remaining(deadline)),
         {:ok, operation} <- Protocol.decode(payload),
         {:ok, result} <- sign_operation(operation, identity, request, key_root) do
      result
    else
      _ -> Protocol.failure()
    end
  end

  defp sign_operation(:identities, identity, request, key_root) do
    with :ok <- Reconciler.ensure_enrolled(identity, request, key_root || KeyStore.root()),
         {:ok, reply} <- request.("identities", identity_payload(identity)),
         identities when is_list(identities) and length(identities) <= 128 <-
           Lookup.value(reply, "identities") do
      encode_identities(identities)
    else
      _ -> {:error, :identities_unavailable}
    end
  end

  defp sign_operation({:sign, blob, data, flags}, identity, request, key_root) do
    with {:ok, public} <- Key.decode_public(Base.encode64(blob)),
         {:ok, local} <- KeyStore.find_by_blob(identity.uid, blob, key_root || KeyStore.root()),
         {:ok, reply} <-
           request.("authorize_sign", Map.put(identity_payload(identity), "public_key", public.encoded)),
         true <- Lookup.value(reply, "allowed") == true,
         {:ok, returned} <- Key.decode_public(Lookup.value(reply, "public_key")),
         true <- returned.blob == blob,
         {:ok, signature} <- Key.sign(local.private_pem, data, flags) do
      {:ok, Protocol.signature(signature)}
    else
      _ -> {:error, :signing_unavailable}
    end
  end
```

   Also update the call site in `serve/3` (`kind: :signing`) to `signing(payload, uid, request(config, deadline), deadline, config[:key_root])`. Update the alias line to `alias SecretHub.Agent.SSH.{Identity, KeyStore, Lookup, Protocol, Reconciler}`, keeping any aliases the file already has.

3. The `Protocol.decode/1` sign tuple keeps its existing shape `{:sign, blob, data, flags}`. Do not change `protocol.ex`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_agent/test/`
Expected: all Agent tests pass.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_agent/lib/secrethub_agent/ssh/server.ex apps/secrethub_agent/test/secrethub_agent/ssh/server_test.exs
git commit -m "feat(agent): sign SSH challenges with device-local keys"
```

---

### Task 11: Preview sentences

**Files:**
- Create: `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/preview.ex`
- Test: `apps/secrethub_web/test/secrethub_web/live/ssh_access/preview_test.exs`

- [ ] **Step 1: Write the failing test**

```elixir
defmodule SecretHub.Web.SSHAccess.PreviewTest do
  use ExUnit.Case, async: true
  alias SecretHub.Web.SSHAccess.Preview

  @inventory %{
    agents: [%{agent_id: "a1", name: "vultr-01"}, %{agent_id: "a2", name: "vultr-02"}],
    identities: [%{id: "i1", name: "gao@laptop"}],
    groups: [%{id: "servers", name: "Servers", kind: "host"}]
  }

  test "groups edges by identity and user into readable sentences" do
    preview = %{
      gained: [
        %{identity_id: "i1", destination_agent_id: "a1", destination_user: "gao"},
        %{identity_id: "i1", destination_agent_id: "a2", destination_user: "gao"}
      ],
      lost: [%{identity_id: "i9", destination_agent_id: "a1", destination_user: "deploy"}],
      changes: [],
      identity_names: %{"i9" => "gh-deploy"}
    }

    assert Preview.edges(preview, @inventory) == [
             {:gained, "gao@laptop can log in as gao on vultr-01, vultr-02"},
             {:lost, "gh-deploy can no longer log in as deploy on vultr-01"}
           ]
  end

  test "describes configuration operations without key material" do
    changes = [
      %{"op" => "identity_approve", "id" => "i1"},
      %{"op" => "identity_external_add", "name" => "ci", "public_key" => "ssh-ed25519 AAAA"},
      %{"op" => "endpoint_upsert", "agent_id" => "a1", "host_keys" => ["k"], "approved" => true},
      %{"op" => "rule_delete", "id" => "r"}
    ]

    assert Preview.changes(changes, @inventory) == [
             "Approve identity gao@laptop",
             "Add external identity ci",
             "Trust 1 host key for vultr-01",
             "Remove 1 access rule"
           ]
  end
end
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access/preview_test.exs`
Expected: `Preview` is undefined.

- [ ] **Step 3: Implement**

```elixir
defmodule SecretHub.Web.SSHAccess.Preview do
  @moduledoc "Human-readable SSH change previews: configuration steps and gained/lost access."

  def edges(preview, inventory) do
    names = Map.merge(identity_names(inventory), Map.get(preview, :identity_names, %{}))

    for {kind, edges} <- [gained: preview.gained, lost: preview.lost],
        {{identity, user}, group} <- Enum.group_by(edges, &{&1.identity_id, &1.destination_user}) |> Enum.sort() do
      hosts = group |> Enum.map(&agent_name(inventory, &1.destination_agent_id)) |> Enum.sort() |> Enum.join(", ")
      verb = if kind == :gained, do: "can log in", else: "can no longer log in"
      {kind, "#{Map.get(names, identity, identity)} #{verb} as #{user} on #{hosts}"}
    end
  end

  def changes(changes, inventory) do
    {deletes, others} = Enum.split_with(changes, &(&1["op"] == "rule_delete"))
    {upserts, others} = Enum.split_with(others, &(&1["op"] == "rule_upsert"))

    Enum.map(others, &describe(&1, inventory)) ++
      count(upserts, "Set", "access rule") ++ count(deletes, "Remove", "access rule")
  end

  defp describe(%{"op" => "identity_approve", "id" => id}, inv), do: "Approve identity #{identity(inv, id)}"
  defp describe(%{"op" => "identity_revoke", "id" => id}, inv), do: "Revoke identity #{identity(inv, id)}"
  defp describe(%{"op" => "identity_delete", "id" => id}, inv), do: "Delete identity #{identity(inv, id)}"
  defp describe(%{"op" => "identity_rotate", "id" => id}, inv), do: "Rotate identity #{identity(inv, id)} now"

  defp describe(%{"op" => "identity_rotation", "id" => id, "rotation_days" => nil}, inv),
    do: "Disable scheduled rotation for #{identity(inv, id)}"

  defp describe(%{"op" => "identity_rotation", "id" => id, "rotation_days" => days}, inv),
    do: "Rotate #{identity(inv, id)} every #{days} days"

  defp describe(%{"op" => "identity_external_add", "name" => name}, _), do: "Add external identity #{name}"

  defp describe(%{"op" => "identity_external_replace", "id" => id}, inv),
    do: "Replace the public key of #{identity(inv, id)}"

  defp describe(%{"op" => "endpoint_upsert", "agent_id" => id, "host_keys" => keys}, inv),
    do: "Trust #{length(keys)} host key#{if length(keys) == 1, do: "", else: "s"} for #{agent_name(inv, id)}"

  defp describe(%{"op" => "endpoint_delete", "agent_id" => id}, inv), do: "Remove SSH endpoint #{agent_name(inv, id)}"
  defp describe(%{"op" => "group_upsert", "name" => name}, _), do: "Save group #{name}"
  defp describe(%{"op" => "group_members", "member_ids" => ids}, _), do: "Set #{length(ids)} group members"
  defp describe(%{"op" => "group_delete", "id" => id}, inv), do: "Delete group #{group(inv, id)}"
  defp describe(%{"op" => op}, _), do: op

  defp count([], _, _), do: []
  defp count(list, verb, noun), do: ["#{verb} #{length(list)} #{noun}#{if length(list) == 1, do: "", else: "s"}"]

  defp identity_names(inventory), do: Map.new(inventory.identities, &{&1.id, &1.name})
  defp identity(inv, id), do: Map.get(identity_names(inv), id, id)

  defp agent_name(inv, id),
    do: Enum.find_value(inv.agents, id, &(&1.agent_id == id && (&1.name || id)))

  defp group(inv, id), do: Enum.find_value(inv.groups, id, &(&1.id == id && &1.name))
end
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access/preview_test.exs`
Expected: 2 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_web/lib/secret_hub/web/live/ssh_access/preview.ex apps/secrethub_web/test/secrethub_web/live/ssh_access/preview_test.exs
git commit -m "feat(web): describe SSH changes as readable sentences"
```

---

### Task 12: LiveView shell and Devices tab

**Files:**
- Rewrite: `apps/secrethub_web/lib/secret_hub/web/live/ssh_access_live.ex`
- Create: `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/devices.ex`
- Rewrite: `apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`

Read `phoenix-duskmoon-ui` and `phoenix-duskmoon-design` before writing HEEx. Keep the `log: false` LiveView option, the `Pending` struct, the PubSub subscription, the `stage/2`/`confirm` flow, `error_message/1`, and the profiles form. The old `selection_checkbox` helper becomes unused, so delete it. Task 14's group drawer uses native array checkboxes for the same reason (duskmoon-dev/phoenix-duskmoon-ui#205). Move the helper's `# TODO(upstream): duskmoon-dev/phoenix-duskmoon-ui#205` and `# WORKAROUND(upstream)` comments onto that `<fieldset>` as a HEEx comment (`<%!-- ... --%>`), so the upstream link is kept.

- [ ] **Step 1: Write the failing LiveView tests**

Keep the existing `setup` (Agents `source` and `destination` with both capabilities). Replace the tests with:

```elixir
  test "renders three tabs, default deny and no application login", %{conn: conn} do
    {:ok, view, html} = live_isolated(conn, SSHAccessLive)
    assert html =~ "SSH Access"
    assert html =~ "Default deny"
    assert has_element?(view, "#ssh-tab-devices")
    assert has_element?(view, "#ssh-tab-identities")
    assert has_element?(view, "#ssh-tab-access")
    refute html =~ "PRIVATE KEY"
    assert %{plug: Phoenix.LiveView.Plug} =
             Phoenix.Router.route_info(SecretHub.Web.Router, "GET", "/admin/ssh-access", "localhost")
  end

  test "reported host keys appear as pending and trust stages a readable preview", %{conn: conn} do
    {:ok, host} = Key.generate("ed25519")
    report_host_key("destination", host.public.public_line)
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    assert has_element?(view, "#pending-host-destination")
    assert render(element(view, "#ssh-tab-devices")) =~ "1"

    html =
      view
      |> form("#endpoint-form-destination", %{"endpoint" => %{"aliases" => "dest.example", "port" => "22"}})
      |> render_submit(%{"trust" => "candidates"})

    assert html =~ "Trust 1 host key for destination"
    assert SSH.snapshot().endpoints |> Enum.all?(&(not &1.approved))
    view |> element("#ssh-confirm") |> render_click()
    assert [%{approved: true, host_keys: [_]}] = SSH.snapshot().endpoints
  end
```

Add a helper that reports a candidate host key through the runtime path. Copy `cert_agent/2` from the Core store test helpers, or set `certificate_id` on the setup Agents with an inserted `Certificate`, as `store_test.exs`'s `agent/2` does:

```elixir
  defp report_host_key(agent_id, key) do
    agent = Repo.get_by!(Agent, agent_id: agent_id)

    {:ok, _} =
      SSH.runtime_operation(%{agent_id: agent_id, certificate_id: agent.certificate_id}, "inventory", %{
        "host_keys" => [key], "users" => []
      })
  end
```

Change the test `setup` so that both Agents get certificates, using the same `Certificate` insert as `store_test.exs`'s `agent/2`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`
Expected: the tab elements are missing.

- [ ] **Step 3: Write the LiveView shell**

The full module `apps/secrethub_web/lib/secret_hub/web/live/ssh_access_live.ex`:

```elixir
defmodule SecretHub.Web.SSHAccessLive do
  @moduledoc "SSH devices, identities and access with revisioned, readable batch previews."
  use Phoenix.LiveView, layout: {SecretHub.Web.Layouts, :app}, log: false
  use PhoenixDuskmoon.Component
  use SecretHub.Web, :verified_routes
  alias SecretHub.Core.SSH
  alias SecretHub.Shared.SSH.Profiles
  alias SecretHub.Web.SSHAccess.{Access, Devices, Identities, Preview}

  defmodule Pending do
    @moduledoc false
    @derive {Inspect, except: [:changes]}
    defstruct [:changes, :preview, :revision]
  end

  @tabs ~w(devices identities access)

  @impl true
  def mount(_, _, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, "ssh:policy")

    {:ok,
     socket
     |> assign(page_title: "SSH Access", tab: "devices", pending: nil, message: nil,
       editing_group: nil, profile: nil)
     |> reload()}
  end

  @impl true
  def handle_event("tab", %{"tab" => tab}, socket) when tab in @tabs,
    do: {:noreply, assign(socket, tab: tab)}

  def handle_event("endpoint", %{"endpoint" => %{"agent_id" => id} = attrs} = params, socket) do
    endpoint = Enum.find(socket.assigns.inventory.endpoints, &(&1.agent_id == id)) || %{}

    keys =
      if params["trust"] == "candidates",
        do: Map.get(endpoint, :candidate_host_keys, []),
        else: Map.get(endpoint, :host_keys, [])

    stage(socket, [
      %{"op" => "endpoint_upsert", "agent_id" => id, "aliases" => words(attrs["aliases"]),
        "port" => integer(attrs["port"]), "host_keys" => keys, "approved" => keys != []}
    ])
  end

  def handle_event("endpoint_delete", %{"agent_id" => id}, socket),
    do: stage(socket, [%{"op" => "endpoint_delete", "agent_id" => id}])

  def handle_event("identity", %{"op" => op, "id" => id}, socket)
      when op in ~w(identity_approve identity_revoke identity_rotate identity_delete),
      do: stage(socket, [%{"op" => op, "id" => id}])

  def handle_event("identity_rotation", %{"rotation" => %{"id" => id, "days" => days}}, socket),
    do: stage(socket, [%{"op" => "identity_rotation", "id" => id, "rotation_days" => integer(days)}])

  def handle_event("external_add", %{"external" => attrs}, socket),
    do:
      stage(socket, [
        %{"op" => "identity_external_add", "name" => String.trim(attrs["name"] || ""),
          "public_key" => String.trim(attrs["public_key"] || ""),
          "rotation_days" => integer(attrs["rotation_days"])}
      ])

  def handle_event("external_replace", %{"replace" => %{"id" => id, "public_key" => key}}, socket),
    do: stage(socket, [%{"op" => "identity_external_replace", "id" => id, "public_key" => String.trim(key)}])

  def handle_event("cell", %{"cell" => attrs}, socket),
    do: stage(socket, Access.cell_changes(socket.assigns.inventory, attrs))

  def handle_event("group_edit", %{"id" => id}, socket),
    do: {:noreply, assign(socket, editing_group: Enum.find(socket.assigns.inventory.groups, &(&1.id == id)))}

  def handle_event("group_new", %{"kind" => kind}, socket) when kind in ["host", "identity"],
    do: {:noreply, assign(socket, editing_group: %{id: nil, name: "", kind: kind})}

  def handle_event("group_close", _, socket), do: {:noreply, assign(socket, editing_group: nil)}

  def handle_event("group_save", %{"group" => attrs}, socket) do
    id = if attrs["id"] in [nil, ""], do: Ecto.UUID.generate(), else: attrs["id"]

    stage(socket, [
      %{"op" => "group_upsert", "id" => id, "name" => attrs["name"], "kind" => attrs["kind"]},
      %{"op" => "group_members", "group_id" => id, "member_ids" => List.wrap(attrs["member_ids"])}
    ])
  end

  def handle_event("group_delete", %{"id" => id}, socket),
    do: stage(socket, [%{"op" => "group_delete", "id" => id}])

  def handle_event("cancel", _, socket), do: {:noreply, assign(socket, pending: nil, message: nil)}

  def handle_event("refresh", _, socket),
    do: {:noreply, reload(socket) |> assign(pending: nil, message: nil)}

  def handle_event("confirm", _, %{assigns: %{pending: %Pending{} = pending}} = socket) do
    case SSH.apply_changes(pending.changes, pending.revision) do
      {:ok, _} ->
        {:noreply, socket |> assign(pending: nil, editing_group: nil, message: "SSH changes saved.") |> reload()}

      {:error, reason} ->
        {:noreply, socket |> assign(pending: nil, message: error_message(reason)) |> reload()}
    end
  rescue
    _ -> {:noreply, assign(socket, pending: nil, message: "SSH changes could not be saved.")}
  end

  def handle_event("profiles", %{"profile" => attrs}, socket) do
    opts = [base: attrs["base"], hosts: words(attrs["hosts"]), lookup_socket: attrs["lookup_socket"],
      signing_socket: attrs["signing_socket"], users: words(attrs["users"])]

    with {:ok, client} <- Profiles.client(opts), {:ok, server} <- Profiles.server(opts) do
      {:noreply, assign(socket, :profile, %{client: client, server: server})}
    else
      _ -> {:noreply, assign(socket, message: "Use absolute paths without spaces and explicit Unix usernames.", profile: nil)}
    end
  end

  def handle_event(_, _, socket), do: {:noreply, socket}

  @impl true
  def handle_info({:ssh_policy_changed, _}, socket), do: {:noreply, reload(socket)}

  defp stage(socket, changes) when changes == [] or length(changes) > 500,
    do: {:noreply, assign(socket, pending: nil, message: "Select between 1 and 500 changes.")}

  defp stage(socket, changes) do
    revision = socket.assigns.inventory.revision

    case SSH.preview(changes, revision) do
      {:ok, preview} ->
        {:noreply, assign(socket, pending: %Pending{changes: changes, preview: preview, revision: revision}, message: nil)}

      {:error, reason} ->
        {:noreply, socket |> assign(pending: nil, message: error_message(reason)) |> reload()}
    end
  rescue
    _ -> {:noreply, assign(socket, pending: nil, message: "SSH changes are invalid or Core is unavailable.")}
  end

  defp reload(socket) do
    case SSH.snapshot() do
      %{revision: _} = inventory -> assign(socket, inventory: inventory, counts: counts(inventory))
      _ -> assign(socket, :message, "SSH inventory is unavailable.")
    end
  end

  # Inventory reports always create an endpoint record holding candidate_host_keys,
  # so counting endpoints also covers Agents that have never been trusted.
  defp counts(inventory) do
    %{
      "devices" =>
        Enum.count(inventory.endpoints, fn e -> Map.get(e, :candidate_host_keys, []) not in [[], e.host_keys] end),
      "identities" => Enum.count(inventory.identities, &(&1.status == "pending" or &1.rotation_overdue)),
      "access" => 0
    }
  end

  defp words(value), do: value |> to_string() |> String.split(~r/[\s,]+/, trim: true)

  defp integer(value) when is_integer(value), do: value

  defp integer(value) do
    case Integer.parse(to_string(value)) do
      {number, ""} -> number
      _ -> nil
    end
  end

  defp error_message(:stale_revision), do: "SSH configuration changed. Review a new preview before saving."
  defp error_message(:sealed), do: "Unseal the Vault before changing SSH configuration."
  defp error_message(:duplicate_key), do: "That public key is already used by another identity."
  defp error_message(:invalid_name), do: "Use a unique name of letters, digits, '.', '_', '-' or '@'."
  defp error_message(:invalid_public_key), do: "Paste one OpenSSH public key line."
  defp error_message(:invalid_rotation), do: "Rotation days must be between 1 and 3650, or blank to disable."
  defp error_message(:endpoint_conflict), do: "That endpoint alias and port already belong to another machine."
  defp error_message(:identity_in_use), do: "Remove this identity's access cells and group memberships before deleting it."
  defp error_message(:name_taken), do: "That identity name is already used."
  defp error_message(:group_in_use), do: "Remove this group's access cells before deleting the group."
  defp error_message(_), do: "SSH changes are invalid or Core is unavailable."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto space-y-6 p-4 text-on-surface">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold">SSH Access</h1>
          <p class="text-sm text-on-surface-variant">
            Default deny · matching deny wins · configuration revision {@inventory.revision}
          </p>
        </div>
        <.dm_btn variant="ghost" phx-click="refresh">Refresh</.dm_btn>
      </div>

      <div role="tablist" class="flex gap-2 border-b border-outline">
        <button :for={{tab, label} <- [{"devices", "Devices"}, {"identities", "Identities"}, {"access", "Access"}]}
          id={"ssh-tab-" <> tab} role="tab" aria-selected={to_string(@tab == tab)}
          phx-click="tab" phx-value-tab={tab}
          class={["px-4 py-2 -mb-px border-b-2", if(@tab == tab, do: "border-primary font-semibold", else: "border-transparent text-on-surface-variant")]}>
          {label}
          <.dm_badge :if={@counts[tab] > 0} variant="warning">{@counts[tab]}</.dm_badge>
        </button>
      </div>

      <.dm_alert :if={@message} variant="info" id="ssh-message">{@message}</.dm_alert>

      <.dm_card :if={@pending} id="ssh-preview" class="border border-outline">
        <:title>Review changes</:title>
        <p :if={@pending.revision != @inventory.revision} class="text-error">
          Configuration changed. This preview must be regenerated.
        </p>
        <ul class="text-sm list-disc pl-5">
          <li :for={line <- Preview.changes(@pending.changes, @inventory)}>{line}</li>
        </ul>
        <ul class="text-sm mt-2">
          <li :for={{kind, line} <- Preview.edges(@pending.preview, @inventory)}
            class={if kind == :gained, do: "text-success", else: "text-error"}>
            {if kind == :gained, do: "+ ", else: "− "}{line}
          </li>
        </ul>
        <p class="text-xs text-on-surface-variant mt-2">
          Each runtime request also checks current certificates, capabilities and local user identity.
        </p>
        <:action>
          <.dm_btn variant="ghost" phx-click="cancel">Cancel</.dm_btn>
          <.dm_btn id="ssh-confirm" variant="primary" phx-click="confirm">Confirm changes</.dm_btn>
        </:action>
      </.dm_card>

      <Devices.tab :if={@tab == "devices"} inventory={@inventory} profile={@profile} />
      <Identities.tab :if={@tab == "identities"} inventory={@inventory} />
      <Access.tab :if={@tab == "access"} inventory={@inventory} editing_group={@editing_group} />
    </div>
    """
  end
end
```

- [ ] **Step 4: Write the Devices component**

`apps/secrethub_web/lib/secret_hub/web/live/ssh_access/devices.ex`:

```elixir
defmodule SecretHub.Web.SSHAccess.Devices do
  @moduledoc "Devices tab: pending host keys and one card per Agent as SSH target and source."
  use Phoenix.Component
  use PhoenixDuskmoon.Component
  alias SecretHub.Core.SSH.Identities
  alias SecretHub.Shared.SSH.Key

  attr :inventory, :map, required: true
  attr :profile, :map, default: nil

  def tab(assigns) do
    assigns = assign(assigns, :now, DateTime.utc_now())

    ~H"""
    <div class="space-y-6">
      <div class="grid gap-4 md:grid-cols-2">
        <.dm_card :for={agent <- @inventory.agents} id={"device-" <> agent.agent_id}>
          <:title>
            <span class="flex items-center justify-between w-full">
              <span>{agent.name || agent.agent_id}</span>
              <.dm_badge variant={if agent.status == :trusted_connected, do: "success", else: "neutral"}>
                {agent.status}
              </.dm_badge>
            </span>
          </:title>
          <% endpoint = endpoint(@inventory, agent.agent_id) %>
          <% candidates = pending_keys(endpoint) %>
          <div :if={candidates != []} id={"pending-host-" <> agent.agent_id}
            class="border border-dashed border-warning rounded p-2 mb-3 text-sm">
            <p class="font-semibold">{if endpoint.host_keys == [], do: "New host keys reported", else: "Host keys changed"}</p>
            <p :for={key <- candidates} class="font-mono text-xs break-all">{fingerprint(key)}</p>
            <p :for={key <- endpoint.host_keys -- candidates} class="font-mono text-xs break-all line-through">
              {fingerprint(key)}
            </p>
          </div>

          <section :if={"ssh_lookup_v1" in agent.runtime_capabilities} class="space-y-2">
            <h4 class="text-sm text-on-surface-variant">As target</h4>
            <.form for={%{}} id={"endpoint-form-" <> agent.agent_id} phx-submit="endpoint"
              class="grid grid-cols-3 gap-2 items-end">
              <input type="hidden" name="endpoint[agent_id]" value={agent.agent_id} />
              <div class="col-span-2">
                <.dm_input id={"aliases-" <> agent.agent_id} name="endpoint[aliases]" label="Aliases"
                  value={Enum.join((endpoint && endpoint.aliases) || [], " ")} />
              </div>
              <.dm_input id={"port-" <> agent.agent_id} name="endpoint[port]" label="Port"
                value={(endpoint && endpoint.port) || 22} />
              <div class="col-span-3 flex gap-2">
                <.dm_btn :if={candidates != []} type="submit" name="trust" value="candidates" variant="primary">
                  Trust reported keys
                </.dm_btn>
                <.dm_btn type="submit" name="trust" value="keep" variant="ghost">
                  {if candidates != [], do: "Keep current keys", else: "Save"}
                </.dm_btn>
              </div>
            </.form>
            <p class="text-xs">
              Logins: {logins(@inventory, agent.agent_id)}
            </p>
          </section>
          <p :if={"ssh_lookup_v1" not in agent.runtime_capabilities} class="text-xs text-on-surface-variant">
            Not an SSH target (lookup capability not enabled).
          </p>

          <section class="space-y-1 mt-3">
            <h4 class="text-sm text-on-surface-variant">As source</h4>
            <p :for={identity <- agent_identities(@inventory, agent.agent_id)} class="text-xs">
              {identity.name} · {identity.status} · {next_rotation(identity)}
            </p>
            <p :if={agent_identities(@inventory, agent.agent_id) == []} class="text-xs text-on-surface-variant">
              No identities yet. A local user's first use of the signing socket enrolls one.
            </p>
          </section>
        </.dm_card>
      </div>

      <.dm_card id="ssh-profiles">
        <:title>OpenSSH profiles</:title>
        <.form for={%{}} id="ssh-profile-form" phx-submit="profiles" class="grid gap-3 md:grid-cols-2">
          <.dm_input id="profile-base" name="profile[base]" label="Agent binary" value="/run/current-system/sw/bin" />
          <.dm_input id="profile-hosts" name="profile[hosts]" label="Hosts" value="" />
          <.dm_input id="profile-lookup" name="profile[lookup_socket]" label="Lookup socket" value="/run/secrethub-agent/ssh-lookup.sock" />
          <.dm_input id="profile-signing" name="profile[signing_socket]" label="Signing socket" value="/run/secrethub-agent/ssh-signing.sock" />
          <.dm_input id="profile-users" name="profile[users]" label="Users" value="" />
          <div class="flex items-end"><.dm_btn type="submit" variant="secondary">Generate</.dm_btn></div>
        </.form>
        <div :if={@profile} class="grid gap-3 md:grid-cols-2 mt-3">
          <pre class="text-xs overflow-auto">{@profile.client}</pre>
          <pre class="text-xs overflow-auto">{@profile.server}</pre>
        </div>
      </.dm_card>
    </div>
    """
  end

  defp endpoint(inventory, agent_id), do: Enum.find(inventory.endpoints, &(&1.agent_id == agent_id))

  defp pending_keys(nil), do: []

  defp pending_keys(endpoint) do
    candidates = Map.get(endpoint, :candidate_host_keys, [])
    if candidates == endpoint.host_keys, do: [], else: candidates
  end

  defp agent_identities(inventory, agent_id), do: Enum.filter(inventory.identities, &(&1.agent_id == agent_id))

  defp logins(inventory, agent_id) do
    inventory.edges
    |> Enum.filter(&(&1.destination_agent_id == agent_id))
    |> Enum.map(fn edge ->
      name = Enum.find_value(inventory.identities, edge.identity_id, &(&1.id == edge.identity_id && &1.name))
      "#{name} → #{edge.destination_user}"
    end)
    |> case do
      [] -> "none"
      list -> Enum.join(list, ", ")
    end
  end

  defp next_rotation(%{next_rotation_at: nil}), do: "no scheduled rotation"
  defp next_rotation(%{next_rotation_at: at}), do: "rotates #{Calendar.strftime(at, "%Y-%m-%d")}"

  defp fingerprint(key) do
    case Key.decode_public(key) do
      {:ok, public} -> public.fingerprint
      _ -> "invalid key"
    end
  end
end
```

Before writing it, copy the profile form's field names and default values from the current `ssh_access_live.ex` render (the "Generate OpenSSH profiles" card). Use those exact `name=` and default values, so that `Profiles.client/1` and `Profiles.server/1` keep receiving the same options. The defaults above are only a shape reference.

Remove the unused `Identities` alias from the module if `mix compile --warnings-as-errors` flags it.

- [ ] **Step 5: Create stub Identities and Access components**

So that the shell compiles before Tasks 13 and 14, create minimal stub modules:

```elixir
defmodule SecretHub.Web.SSHAccess.Identities do
  @moduledoc "Identities tab."
  use Phoenix.Component
  attr :inventory, :map, required: true
  def tab(assigns), do: ~H"<div id='identities-tab'></div>"
end
```

```elixir
defmodule SecretHub.Web.SSHAccess.Access do
  @moduledoc "Access tab."
  use Phoenix.Component
  attr :inventory, :map, required: true
  attr :editing_group, :map, default: nil
  def tab(assigns), do: ~H"<div id='access-tab'></div>"
  def cell_changes(_inventory, _attrs), do: []
end
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`
Expected: 2 tests, 0 failures.

- [ ] **Step 7: Commit**

```bash
git add apps/secrethub_web/lib/secret_hub/web/live/ssh_access_live.ex apps/secrethub_web/lib/secret_hub/web/live/ssh_access/ apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs
git commit -m "feat(web): split SSH access into tabs with a devices view"
```

---

### Task 13: Identities tab

**Files:**
- Rewrite: `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/identities.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`

- [ ] **Step 1: Write the failing tests**

```elixir
  test "pending Agent identities can be approved and rotated from the identities tab", %{conn: conn} do
    {:ok, key} = Key.generate("ed25519")
    agent = Repo.get_by!(Agent, agent_id: "source")

    {:ok, _} =
      SSH.runtime_operation(%{agent_id: "source", certificate_id: agent.certificate_id}, "identity_report", %{
        "uid" => 1000, "username" => "gao", "generation" => 1, "public_key" => key.public.public_line
      })

    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()
    [identity] = SSH.snapshot().identities
    assert has_element?(view, "#identity-#{identity.id}", "pending")

    html = view |> element("#approve-#{identity.id}") |> render_click()
    assert html =~ "Approve identity gao@source"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{status: "active"}] = SSH.snapshot().identities

    html = view |> element("#rotate-#{identity.id}") |> render_click()
    assert html =~ "Rotate identity gao@source now"
  end

  test "external public keys are added with validation and never render private material", %{conn: conn} do
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()

    html =
      view
      |> form("#external-form", %{"external" => %{"name" => "gh-deploy", "public_key" => "not a key", "rotation_days" => "90"}})
      |> render_submit()

    assert html =~ "Paste one OpenSSH public key line."

    {:ok, key} = Key.generate("ed25519")

    html =
      view
      |> form("#external-form", %{"external" => %{"name" => "gh-deploy", "public_key" => key.public.public_line, "rotation_days" => "90"}})
      |> render_submit()

    assert html =~ "Add external identity gh-deploy"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{name: "gh-deploy", origin: "external"}] = SSH.snapshot().identities
    refute render(view) =~ "PRIVATE KEY"
  end
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`
Expected: `#identity-…` and `#external-form` are missing.

- [ ] **Step 3: Implement**

```elixir
defmodule SecretHub.Web.SSHAccess.Identities do
  @moduledoc "Identities tab: Agent-held and external SSH identities with rotation state."
  use Phoenix.Component
  use PhoenixDuskmoon.Component
  alias SecretHub.Core.SSH.Identities, as: Lifecycle

  attr :inventory, :map, required: true

  def tab(assigns) do
    assigns = assign(assigns, :now, DateTime.utc_now())

    ~H"""
    <div class="space-y-6">
      <.dm_card id="ssh-identities">
        <:title>Identities</:title>
        <p :if={@inventory.identities == []} class="text-on-surface-variant">
          No identities. Agents enroll one per local user on first signing use; add external keys below.
        </p>
        <div class="overflow-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-on-surface-variant">
                <th>Identity</th><th>Origin</th><th>Fingerprint</th><th>Status</th><th>Rotation</th><th></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={identity <- @inventory.identities} id={"identity-" <> identity.id} class="border-t border-outline">
                <td class="py-2 font-medium">{identity.name}</td>
                <td>{if identity.origin == "agent", do: "Agent", else: "External"}</td>
                <td class="font-mono text-xs">{current_fingerprint(identity)}</td>
                <td>
                  <.dm_badge variant={status_variant(identity)}>{status(identity, @now)}</.dm_badge>
                </td>
                <td>
                  <.form for={%{}} id={"rotation-" <> identity.id} phx-submit="identity_rotation" class="flex gap-1 items-center">
                    <input type="hidden" name="rotation[id]" value={identity.id} />
                    <input name="rotation[days]" value={identity.rotation_days} size="4"
                      class="w-16 rounded border border-outline bg-surface px-1" aria-label="Rotation days" />
                    <span class="text-xs">days · {due(identity)}</span>
                  </.form>
                </td>
                <td class="flex gap-1 py-2">
                  <.dm_btn :if={identity.status == "pending"} id={"approve-" <> identity.id} size="sm" variant="primary"
                    phx-click="identity" phx-value-op="identity_approve" phx-value-id={identity.id}>Approve</.dm_btn>
                  <.dm_btn :if={identity.status == "active" and identity.origin == "agent"} id={"rotate-" <> identity.id}
                    size="sm" variant="secondary" phx-click="identity" phx-value-op="identity_rotate" phx-value-id={identity.id}>
                    Rotate now
                  </.dm_btn>
                  <.dm_btn :if={identity.status != "retired"} id={"revoke-" <> identity.id} size="sm" variant="error"
                    phx-click="identity" phx-value-op="identity_revoke" phx-value-id={identity.id}>Revoke</.dm_btn>
                  <.dm_btn :if={identity.status in ["pending", "retired"]} id={"delete-" <> identity.id} size="sm" variant="ghost"
                    phx-click="identity" phx-value-op="identity_delete" phx-value-id={identity.id}>Delete</.dm_btn>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.dm_card>

      <div class="grid gap-6 md:grid-cols-2">
        <.dm_card>
          <:title>Add external public key</:title>
          <.form for={%{}} id="external-form" phx-submit="external_add" class="space-y-3">
            <.dm_input id="external-name" name="external[name]" label="Name" value="" />
            <.dm_textarea id="external-key" name="external[public_key]" label="OpenSSH public key" value="" />
            <.dm_input id="external-rotation" name="external[rotation_days]" label="Remind to rotate after (days)" value="90" />
            <.dm_btn type="submit" variant="primary">Preview</.dm_btn>
          </.form>
        </.dm_card>
        <.dm_card :if={externals(@inventory) != []}>
          <:title>Replace external public key</:title>
          <.form for={%{}} id="replace-form" phx-submit="external_replace" class="space-y-3">
            <.dm_select id="replace-id" name="replace[id]" label="Identity"
              options={Enum.map(externals(@inventory), &{&1.id, &1.name})} />
            <.dm_textarea id="replace-key" name="replace[public_key]" label="New OpenSSH public key" value="" />
            <.dm_btn type="submit" variant="secondary">Preview</.dm_btn>
          </.form>
        </.dm_card>
      </div>
    </div>
    """
  end

  defp externals(inventory), do: Enum.filter(inventory.identities, &(&1.origin == "external" and &1.status == "active"))

  defp current_fingerprint(identity),
    do: identity.keys |> Enum.max_by(& &1.generation, fn -> %{fingerprint: "—"} end) |> Map.get(:fingerprint)

  defp status(identity, now) do
    valid = length(Lifecycle.valid_keys(identity, now))

    cond do
      identity.rotation_overdue -> "rotation overdue"
      identity.status == "active" and identity.requested_generation > Lifecycle.current_generation(identity) -> "waiting for device"
      identity.status == "active" and valid > 1 -> "rotating (#{valid} keys valid)"
      true -> identity.status
    end
  end

  defp status_variant(%{rotation_overdue: true}), do: "warning"
  defp status_variant(%{status: "pending"}), do: "warning"
  defp status_variant(%{status: "active"}), do: "success"
  defp status_variant(_), do: "neutral"

  defp due(%{next_rotation_at: nil}), do: "off"
  defp due(%{next_rotation_at: at}), do: "next " <> Calendar.strftime(at, "%Y-%m-%d")
end
```

Native `<table>` and `<input>` elements are used here, as the current file does for the checkbox (#205), because `dm_table` columns cannot hold forms per row. Wrapping or composing like this is allowed; patching `dm_*` component logic is not. Before using `dm_btn` `size="sm"` and the `dm_badge` variants `warning`, `success`, and `neutral`, check that the installed `phoenix_duskmoon` version supports them, using `grep -rn "attr :size\|attr :variant" deps/phoenix_duskmoon/lib/phoenix_duskmoon/component/` (or the actual path). If the package lacks them, use only the variants it supports, and do not add local CSS overrides.

Rotation days are submitted with Enter on the inline form. A blank value maps to `nil` (scheduled rotation off) through `integer/1` in the LiveView.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`
Expected: 4 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_web/lib/secret_hub/web/live/ssh_access/identities.ex apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs
git commit -m "feat(web): manage SSH identities and external keys"
```

---

### Task 14: Access tab (matrix and groups)

**Files:**
- Rewrite: `apps/secrethub_web/lib/secret_hub/web/live/ssh_access/access.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`

**Matrix semantics:**

- **Rows** are active or pending identities and identity groups.
- **Columns** are host groups and approved endpoints.
- **Cells.** A cell represents every rule with that exact `(source_kind, source_id, destination_kind, destination_id)`. Its effective display comes from the rules:
  - `allow as <user>[, <user>]`
  - `deny`
  - `—`
- **Editing.** Editing a cell submits `{source, destination, effect, user}`:
  - `allow`: `rule_delete` for each existing rule in the cell, then one `rule_upsert` that allows that user.
  - `deny`: delete, then upsert a deny rule for that user.
  - `clear`: delete only.
- **User options** are the union of usernames that the destination Agents report (`agent.ssh_users`), plus a free-text fallback.

- [ ] **Step 1: Write the failing tests**

```elixir
  test "matrix cells allow a reported destination user and preview readable gains", %{conn: conn} do
    {:ok, host} = Key.generate("ed25519")
    {:ok, user} = Key.generate("ed25519")

    {:ok, %{identities: [identity]}} =
      SSH.apply_changes(
        [
          %{"op" => "endpoint_upsert", "agent_id" => "destination", "aliases" => ["dest.example"],
            "port" => 22, "host_keys" => [host.public.public_line], "approved" => true},
          %{"op" => "identity_external_add", "name" => "gh-deploy", "public_key" => user.public.public_line,
            "rotation_days" => 90}
        ],
        0
      )

    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()

    html =
      view
      |> form("#cell-identity-#{identity.id}-endpoint-destination", %{"cell" => %{"user" => "deploy"}})
      |> render_submit(%{"cell" => %{"effect" => "allow"}})

    assert html =~ "+ gh-deploy can log in as deploy on destination"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{effect: "allow", destination_user: "deploy"}] = SSH.snapshot().rules

    html =
      view
      |> form("#cell-identity-#{identity.id}-endpoint-destination", %{"cell" => %{"user" => ""}})
      |> render_submit(%{"cell" => %{"effect" => "clear"}})

    assert html =~ "− gh-deploy can no longer log in as deploy on destination"
  end

  test "groups are created in the drawer with typed members", %{conn: conn} do
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()
    view |> element("#new-host-group") |> render_click()

    html =
      view
      |> form("#group-form", %{"group" => %{"name" => "Servers", "kind" => "host", "member_ids" => ["destination"]}})
      |> render_submit()

    assert html =~ "Save group Servers"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{name: "Servers", kind: "host", agent_ids: ["destination"]}] = SSH.snapshot().groups
  end
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs`
Expected: the cell forms are missing.

- [ ] **Step 3: Implement**

```elixir
defmodule SecretHub.Web.SSHAccess.Access do
  @moduledoc "Access tab: identity × destination matrix and typed group drawer."
  use Phoenix.Component
  use PhoenixDuskmoon.Component

  attr :inventory, :map, required: true
  attr :editing_group, :map, default: nil

  def tab(assigns) do
    assigns = assign(assigns, rows: rows(assigns.inventory), columns: columns(assigns.inventory))

    ~H"""
    <div class="space-y-6">
      <.dm_card id="ssh-matrix">
        <:title>
          <span class="flex justify-between w-full">
            <span>Access</span>
            <span class="flex gap-2">
              <.dm_btn id="new-identity-group" size="sm" variant="ghost" phx-click="group_new" phx-value-kind="identity">+ Identity group</.dm_btn>
              <.dm_btn id="new-host-group" size="sm" variant="ghost" phx-click="group_new" phx-value-kind="host">+ Host group</.dm_btn>
            </span>
          </span>
        </:title>
        <p :if={@rows == [] or @columns == []} class="text-on-surface-variant">
          Access needs at least one identity and one trusted endpoint or host group.
        </p>
        <div :if={@rows != [] and @columns != []} class="overflow-auto">
          <table class="text-sm">
            <thead>
              <tr>
                <th class="text-left">Identity \ Destination</th>
                <th :for={{_kind, _id, label} <- @columns} class="px-2">{label}</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={{row_kind, row_id, row_label} <- @rows} class="border-t border-outline">
                <th class="text-left py-2 pr-3">{row_label}</th>
                <td :for={{col_kind, col_id, _} <- @columns} class="px-2 py-1 align-top">
                  <% rules = cell_rules(@inventory, row_kind, row_id, col_kind, col_id) %>
                  <.form for={%{}} id={"cell-#{row_kind}-#{row_id}-#{col_kind}-#{col_id}"} phx-submit="cell" class="space-y-1">
                    <input type="hidden" name="cell[source]" value={"#{row_kind}/#{row_id}"} />
                    <input type="hidden" name="cell[destination]" value={"#{col_kind}/#{col_id}"} />
                    <p class={["text-xs", summary_class(rules)]}>{summary(rules)}</p>
                    <input name="cell[user]" list={"users-#{col_kind}-#{col_id}"} placeholder="user"
                      class="w-24 rounded border border-outline bg-surface px-1 text-xs" aria-label="Destination user" />
                    <datalist id={"users-#{col_kind}-#{col_id}"}>
                      <option :for={user <- destination_users(@inventory, col_kind, col_id)} value={user} />
                    </datalist>
                    <span class="flex gap-1">
                      <button type="submit" name="cell[effect]" value="allow" class="text-xs text-success">allow</button>
                      <button type="submit" name="cell[effect]" value="deny" class="text-xs text-error">deny</button>
                      <button :if={rules != []} type="submit" name="cell[effect]" value="clear" class="text-xs">clear</button>
                    </span>
                  </.form>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.dm_card>

      <.dm_card id="ssh-groups">
        <:title>Groups</:title>
        <ul class="text-sm space-y-1">
          <li :for={group <- @inventory.groups} class="flex justify-between">
            <span>{group.name} <span class="text-on-surface-variant">({group.kind}, {length(members(group))} members)</span></span>
            <span class="flex gap-1">
              <.dm_btn size="sm" variant="ghost" phx-click="group_edit" phx-value-id={group.id}>Edit</.dm_btn>
              <.dm_btn size="sm" variant="error" phx-click="group_delete" phx-value-id={group.id}>Delete</.dm_btn>
            </span>
          </li>
        </ul>
      </.dm_card>

      <.dm_card :if={@editing_group} id="group-drawer" class="border border-primary">
        <:title>{if @editing_group.id, do: "Edit group", else: "New #{@editing_group.kind} group"}</:title>
        <.form for={%{}} id="group-form" phx-submit="group_save" class="space-y-3">
          <input type="hidden" name="group[id]" value={@editing_group.id} />
          <input type="hidden" name="group[kind]" value={@editing_group.kind} />
          <.dm_input id="group-name" name="group[name]" label="Name" value={@editing_group.name} />
          <fieldset class="space-y-1">
            <legend class="text-sm">Members</legend>
            <label :for={{id, label} <- member_options(@inventory, @editing_group.kind)} class="flex gap-2 items-center text-sm">
              <input type="checkbox" name="group[member_ids][]" value={id} checked={id in members(@editing_group)} />
              {label}
            </label>
          </fieldset>
          <span class="flex gap-2">
            <.dm_btn type="submit" variant="primary">Preview</.dm_btn>
            <.dm_btn type="button" variant="ghost" phx-click="group_close">Close</.dm_btn>
          </span>
        </.form>
      </.dm_card>
    </div>
    """
  end

  @doc "Translates one matrix cell edit into a rule batch."
  def cell_changes(inventory, %{"source" => source, "destination" => destination, "effect" => effect} = attrs) do
    with [source_kind, source_id] <- String.split(source, "/", parts: 2),
         [destination_kind, destination_id] <- String.split(destination, "/", parts: 2),
         true <- effect in ["allow", "deny", "clear"] do
      deletes =
        for rule <- cell_rules(inventory, source_kind, source_id, destination_kind, destination_id),
            do: %{"op" => "rule_delete", "id" => rule.id}

      user = String.trim(attrs["user"] || "")

      upsert =
        if effect == "clear",
          do: [],
          else: [
            %{"op" => "rule_upsert", "effect" => effect, "enabled" => true,
              "source_kind" => source_kind, "source_id" => source_id,
              "destination_kind" => destination_kind, "destination_id" => destination_id,
              "destination_user" => user}
          ]

      deletes ++ upsert
    else
      _ -> []
    end
  end

  def cell_changes(_, _), do: []

  defp rows(inventory) do
    Enum.map(Enum.filter(inventory.groups, &(&1.kind == "identity")), &{"identity_group", &1.id, "Group: " <> &1.name}) ++
      for(identity <- inventory.identities, identity.status != "retired", do: {"identity", identity.id, identity.name})
  end

  defp columns(inventory) do
    Enum.map(Enum.filter(inventory.groups, &(&1.kind == "host")), &{"host_group", &1.id, "Group: " <> &1.name}) ++
      for(endpoint <- inventory.endpoints, endpoint.approved, do: {"endpoint", endpoint.agent_id, agent_name(inventory, endpoint.agent_id)})
  end

  defp cell_rules(inventory, source_kind, source_id, destination_kind, destination_id),
    do:
      Enum.filter(inventory.rules, fn rule ->
        rule.source_kind == source_kind and rule.source_id == source_id and
          rule.destination_kind == destination_kind and rule.destination_id == destination_id
      end)

  defp summary([]), do: "—"

  defp summary(rules) do
    {deny, allow} = Enum.split_with(rules, &(&1.effect == "deny"))

    [if(allow != [], do: "allow as " <> Enum.map_join(allow, ", ", & &1.destination_user)),
     if(deny != [], do: "deny " <> Enum.map_join(deny, ", ", & &1.destination_user))]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" · ")
  end

  defp summary_class(rules) do
    cond do
      Enum.any?(rules, &(&1.effect == "deny")) -> "text-error"
      rules != [] -> "text-success"
      true -> "text-on-surface-variant"
    end
  end

  defp destination_users(inventory, "endpoint", agent_id), do: users_of(inventory, [agent_id])

  defp destination_users(inventory, "host_group", id) do
    group = Enum.find(inventory.groups, &(&1.id == id))
    users_of(inventory, (group && group.agent_ids) || [])
  end

  defp users_of(inventory, agent_ids) do
    inventory.agents
    |> Enum.filter(&(&1.agent_id in agent_ids))
    |> Enum.flat_map(&Map.get(&1, :ssh_users, []))
    |> Enum.filter(& &1.unambiguous)
    |> Enum.map(& &1.username)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp member_options(inventory, "host"), do: Enum.map(inventory.agents, &{&1.agent_id, &1.name || &1.agent_id})

  defp member_options(inventory, "identity"),
    do: for(i <- inventory.identities, i.status != "retired", do: {i.id, i.name})

  defp members(%{kind: "host"} = group), do: Map.get(group, :agent_ids, [])
  defp members(%{kind: "identity"} = group), do: Map.get(group, :identity_ids, [])

  defp agent_name(inventory, id), do: Enum.find_value(inventory.agents, id, &(&1.agent_id == id && (&1.name || id)))
end
```

The clicked submit button's `name`/`value` (`cell[effect]`) arrives in the submitted params, because LiveView includes the submitter. `LiveViewTest.form/3` rejects fields that are not inputs, so the tests pass `effect` as the `render_submit/2` value, which deep-merges into the form data.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `test-all apps/secrethub_web/test/secrethub_web/live/`
Expected: all LiveView tests pass.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_web/lib/secret_hub/web/live/ssh_access/access.ex apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs
git commit -m "feat(web): edit SSH access through an identity-destination matrix"
```

---

### Task 15: Docs and spec alignment

**Files:**
- Modify: `docs/deployment/ssh-access-management.md`
- Modify: `docs/superpowers/specs/2026-11-12-ssh-identity-access-design.md` (audit event names)

- [ ] **Step 1: Update the operator document**

In `docs/deployment/ssh-access-management.md`, replace every passage about Core-generated or imported source private keys, `identity_upsert`, and `source_user`. Describe:

- **Identities.** Agent identities enroll on a user's first use of the signing socket and wait for approval on the Identities tab. Their private keys stay at `<state_dir>/ssh-identities/<uid>/` (mode 0600). External identities are added as public keys.
- **Rotation.**
  - Default period: 90 days.
  - Grace period: 3 days with both keys valid.
  - The hourly Styx job is `SSHIdentityRotationWorker`.
  - "Rotate now" requests rotation immediately.
  - External identities only show "rotation overdue". Replace the key, then update the GitHub secret by hand (automation: issue #22).
- **Access.** Rules go from identity or identity group to endpoint or host group, as a destination user. Deny wins, and the default is deny.
- **`authorized_keys`** no longer requires the source device to be online.
- **Out of scope.** Host keys are not rotated, because Agent enrollment and sops-nix depend on them.

- [ ] **Step 2: Align the spec's audit names with the implementation**

In the spec's "Rotation scheduling (Styx)" section, replace the event list with:

> Audit events: management changes are recorded as `ssh.configuration`, including each operation (`identity_approve`, `identity_revoke`, `identity_rotate`, `identity_rotation`, `identity_external_add`, `identity_external_replace`). Agent reports are recorded as `ssh.identity_report`, with the error reason when rejected. The worker records `ssh.identity_rotation_requested`, `ssh.identity_rotation_overdue`, and `ssh.identity_keys_pruned`.

- [ ] **Step 3: Commit**

```bash
git add docs/deployment/ssh-access-management.md docs/superpowers/specs/2026-11-12-ssh-identity-access-design.md
git commit -m "docs(core): document device-held SSH identities and rotation"
```

---

### Task 16: Full verification

- [ ] **Step 1: Run the quality gate**

Run: `./scripts/quality-check.sh`
Expected: format, `compile --warnings-as-errors`, credo strict, dialyzer, and tests all pass. Fix any finding inside the files this plan touches. Record failures outside that scope without fixing them.

- [ ] **Step 2: End-to-end test in local devenv**

1. Run `devenv processes up -d`, then initialize or unseal the vault and approve the Agent in `/admin/pending-agents` if this is the first boot.
2. Enable lookup and signing for the dev Agent. Use the same settings as `docs/deployment/ssh-access-management.md` (the `SECRET_HUB_AGENT_SSH_*` variables). Restart with `devenv processes down && devenv processes up -d`.
3. Run `SSH_AUTH_SOCK=<signing socket> ssh-add -L`. Expected: it prints nothing, and `/admin/ssh-access` → Identities shows `<user>@<agent>` as pending.
4. On the Devices tab, trust the reported host key with alias `localhost`. On the Identities tab, approve the identity. On the Access tab, allow `<identity> → localhost as <user>`, then confirm.
5. With `sshd` configured from the generated profile (`AuthorizedKeysCommand` and `KnownHostsCommand`), run `SSH_AUTH_SOCK=<signing socket> ssh <user>@localhost true`. Expected: exit code 0.
6. Click "Rotate now". Within 30 s (one heartbeat), `ls <state_dir>/ssh-identities/<uid>/` shows `1.key 2.key`, and the identity shows "rotating (2 keys valid)". `ssh` still succeeds.
7. Verify grace expiry without waiting 3 days: in `console`, set generation 1's `not_after` to the past with `Repo.update_all`, then run `SecretHub.Core.SSH.rotate_due()`. After the next heartbeat, `1.key` is pruned. `ssh-add -L` lists only the generation 2 key, and `ssh` still succeeds.

Record the outcome of every step. If a step cannot be run locally (for example, there is no `sshd` in the environment), report it as unverified; do not claim it passed.

- [ ] **Step 3: Review the final diff**

Run: `git log --oneline <start>..HEAD` and `git diff <start>..HEAD --stat`.
Confirm that nothing outside the file table changed, aside from the spec and plan docs.
