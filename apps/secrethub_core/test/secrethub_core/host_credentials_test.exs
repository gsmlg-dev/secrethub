defmodule SecretHub.Core.HostCredentialsTest do
  use ExUnit.Case, async: false
  import Ecto.Query

  alias SecretHub.Core.{
    AccessAudit,
    HostCredentials,
    Policies,
    Repo,
    RuntimeAuthorization,
    RuntimePrincipal,
    Secrets,
    UpgradeGates
  }

  alias SecretHub.Core.HostCredentials.Management
  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.RuntimeDatabaseFixture
  alias SecretHub.Core.RuntimeDatabaseFixture.VaultRepo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, AuditLog, HostCredentialBinding, Policy, Secret}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
  end

  setup do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)
    start_supervised!({SealState, repo: VaultRepo})
    await_vault()
    {:ok, shares} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(Enum.at(shares, 0))
    {:ok, _} = SealState.unseal(Enum.at(shares, 1))
    unique = System.unique_integer([:positive])
    {:ok, _} = CA.generate_root_ca("Host Credential Root #{unique}", "SecretHub", key_size: 2048)

    a = agent!("hc-agent-a-#{unique}")
    b = agent!("hc-agent-b-#{unique}")
    assert {:ok, _} = UpgradeGates.verify_typed_runtime_authorization(actor_id: "operator:test")

    {:ok, source} =
      Secrets.create_secret(%{
        name: "Shared registry token",
        secret_path: "shared.registry.token",
        value_format: "structured",
        secret_data: %{"user" => "deploy", "token" => "shared-token-1"}
      })

    %{a: a, b: b, source: source}
  end

  describe "owned entries" do
    test "store, get, update, list metadata and erase operate on the intended entry", ctx do
      grant!(ctx.a, ~w(credential_read credential_write credential_delete credential_list))

      assert {:ok, %{"status" => "created", "entry_id" => id, "binding_revision" => 1}} =
               call(ctx.a, "credential_put", git("alice", "pw-1"))

      assert {:ok, %{"username" => "alice", "value" => "pw-1", "entry_id" => ^id}} =
               call(ctx.a, "credential_get", git_lookup("alice"))

      # Identical store is an audited no-op; a different value updates in place.
      assert {:ok, %{"status" => "unchanged"}} =
               call(ctx.a, "credential_put", git("alice", "pw-1"))

      assert {:ok, %{"status" => "updated"}} = call(ctx.a, "credential_put", git("alice", "pw-2"))
      assert {:ok, %{"value" => "pw-2"}} = call(ctx.a, "credential_get", git_lookup(nil))

      assert {:ok, %{"entries" => [entry], "next_cursor" => nil}} =
               call(ctx.a, "credential_list", %{"namespace" => "git"})

      assert entry["entry_id"] == id and entry["username"] == "alice"
      refute Map.has_key?(entry, "value")
      refute inspect(entry) =~ "pw-2"

      # A stale value cannot erase the newer replacement.
      stale = Map.put(git_lookup("alice"), "expected_value", "pw-1")
      assert {:ok, %{"status" => "unchanged"}} = call(ctx.a, "credential_delete", stale)

      assert {:ok, %{"status" => "deleted"}} =
               call(ctx.a, "credential_delete", git_lookup("alice"))

      assert {:ok, %{"status" => "absent"}} =
               call(ctx.a, "credential_delete", git_lookup("alice"))

      assert {:error, :not_found} = call(ctx.a, "credential_get", git_lookup("alice"))
      refute Repo.exists?(from(s in Secret, where: like(s.secret_path, "host-credentials.%")))
    end

    test "empty values are values and remain distinct from missing entries", ctx do
      grant!(ctx.a, ~w(credential_read credential_write))
      assert {:ok, _} = call(ctx.a, "credential_put", generic("svc", "user", ""))

      assert {:ok, %{"value" => ""}} =
               call(ctx.a, "credential_get", generic_lookup("svc", "user"))

      assert {:error, :not_found} = call(ctx.a, "credential_get", generic_lookup("svc", "other"))
    end

    test "Git lookups keep account and path scope and refuse ambiguous erase", ctx do
      grant!(ctx.a, ~w(credential_read credential_write credential_delete))
      {:ok, _} = call(ctx.a, "credential_put", git("alice", "a-pw"))
      {:ok, _} = call(ctx.a, "credential_put", git("bob", "b-pw"))

      assert {:error, :ambiguous} = call(ctx.a, "credential_get", git_lookup(nil))
      assert {:ok, %{"value" => "b-pw"}} = call(ctx.a, "credential_get", git_lookup("bob"))
      assert {:error, :ambiguous} = call(ctx.a, "credential_delete", git_lookup(nil))

      with_path = Map.put(git_lookup("alice"), "context", "org/repo.git")
      assert {:error, :not_found} = call(ctx.a, "credential_get", with_path)

      with_port = Map.put(git_lookup("alice"), "authority", "example.com:8443")
      assert {:error, :not_found} = call(ctx.a, "credential_get", with_port)

      assert {:ok, %{"value" => "a-pw"}} = call(ctx.a, "credential_get", git_lookup("alice"))
    end

    test "Docker keeps one credential per registry key and round-trips <token>", ctx do
      grant!(ctx.a, ~w(credential_read credential_write credential_list))
      registry = %{"namespace" => "docker", "service" => "registry.example.com:5000"}

      {:ok, _} =
        call(ctx.a, "credential_put", Map.merge(registry, %{"username" => "u1", "value" => "s1"}))

      token = Map.merge(registry, %{"username" => "<token>", "value" => "id-token"})
      assert {:ok, %{"status" => "updated"}} = call(ctx.a, "credential_put", token)

      assert {:ok, %{"username" => "<token>", "value" => "id-token"}} =
               call(ctx.a, "credential_get", registry)

      assert {:ok, %{"entries" => [%{"service" => "registry.example.com:5000"} = entry]}} =
               call(ctx.a, "credential_list", %{"namespace" => "docker"})

      assert entry["username"] == "<token>"
    end
  end

  describe "authorization" do
    test "an Agent cannot read, mutate or enumerate another Agent's entries", ctx do
      ops = ~w(credential_read credential_write credential_delete credential_list)
      grant!(ctx.a, ops)
      grant!(ctx.b, ops)
      {:ok, %{"entry_id" => id}} = call(ctx.a, "credential_put", git("alice", "a-secret"))

      assert {:error, :not_found} = call(ctx.b, "credential_get", %{"entry_id" => id})
      assert {:error, :not_found} = call(ctx.b, "credential_get", git_lookup("alice"))

      assert {:ok, %{"status" => "absent"}} =
               call(ctx.b, "credential_delete", %{"entry_id" => id})

      assert {:ok, %{"entries" => []}} = call(ctx.b, "credential_list", %{"namespace" => "git"})

      assert {:ok, %{"status" => "created", "entry_id" => other}} =
               call(ctx.b, "credential_put", git("alice", "b-secret"))

      refute other == id
      assert {:ok, %{"value" => "a-secret"}} = call(ctx.a, "credential_get", %{"entry_id" => id})
    end

    test "read-only grants do not permit put, delete or list", ctx do
      grant!(ctx.a, ~w(credential_read credential_write))
      {:ok, _} = call(ctx.a, "credential_put", git("alice", "pw"))
      revoke_all!(ctx.a)

      # A broad static read grant is not a credential write, delete or list grant.
      grant!(ctx.a, ~w(read credential_read), ["host-credentials.**"])

      assert {:ok, %{"value" => "pw"}} = call(ctx.a, "credential_get", git_lookup("alice"))
      assert {:error, :permission_denied} = call(ctx.a, "credential_put", git("alice", "new"))
      assert {:error, :permission_denied} = call(ctx.a, "credential_put", git("eve", "new"))
      assert {:error, :permission_denied} = call(ctx.a, "credential_delete", git_lookup("alice"))

      assert {:error, :permission_denied} =
               call(ctx.a, "credential_list", %{"namespace" => "git"})
    end

    test "a collection create grant cannot overwrite an existing entry", ctx do
      grant!(ctx.a, ~w(credential_write))
      {:ok, %{"entry_id" => id}} = call(ctx.a, "credential_put", git("alice", "pw"))
      revoke_all!(ctx.a)

      grant!(ctx.a, ~w(credential_write), ["host-credentials.#{ctx.a.id}.git"])
      assert {:error, :permission_denied} = call(ctx.a, "credential_put", git("alice", "pw-2"))
      assert {:ok, %{"status" => "created"}} = call(ctx.a, "credential_put", git("bob", "pw"))

      grant!(ctx.a, ~w(credential_read), ["host-credentials.#{ctx.a.id}.git.#{id}"])
      assert {:ok, %{"value" => "pw"}} = call(ctx.a, "credential_get", %{"entry_id" => id})
    end

    test "cached revisions still require current policy and Vault readiness", ctx do
      grant!(ctx.a, ~w(credential_read credential_write))
      {:ok, _} = call(ctx.a, "credential_put", git("alice", "pw"))

      {:ok, %{"entry_id" => id, "binding_revision" => b, "source_revision" => s}} =
        call(ctx.a, "credential_get", git_lookup("alice"))

      cached = Map.put(git_lookup("alice"), "known", known(id, b, s))
      assert {:ok, %{"not_modified" => true} = hit} = call(ctx.a, "credential_get", cached)
      refute Map.has_key?(hit, "value")

      # A stale revision returns the current value instead of not_modified.
      stale = Map.put(git_lookup("alice"), "known", known(id, b, s + 1))
      assert {:ok, %{"value" => "pw"}} = call(ctx.a, "credential_get", stale)

      deny!(ctx.a, "credential_read")
      assert {:error, :permission_denied} = call(ctx.a, "credential_get", cached)

      Repo.delete_all(from(p in Policy, where: p.deny_policy))
      stop_supervised!(SealState)
      start_supervised!({SealState, repo: VaultRepo})
      await_state(:sealed)
      assert {:error, :sealed} = call(ctx.a, "credential_get", cached)
    end

    test "cached revisions are not acknowledged when audit persistence is unavailable", ctx do
      grant!(ctx.a, ~w(credential_read credential_write))
      {:ok, _} = call(ctx.a, "credential_put", git("alice", "pw"))

      {:ok, %{"entry_id" => id, "binding_revision" => b, "source_revision" => s}} =
        call(ctx.a, "credential_get", git_lookup("alice"))

      Repo.query!("ALTER TABLE access_audit_events RENAME TO access_audit_events_unavailable", [])

      for known <- [known(id, b, s), nil] do
        assert {:error, :audit_unavailable} =
                 call(ctx.a, "credential_get", Map.put(git_lookup("alice"), "known", known))
      end

      assert {:error, :audit_unavailable} = call(ctx.a, "credential_put", git("alice", "new"))
      Repo.query!("ALTER TABLE access_audit_events_unavailable RENAME TO access_audit_events", [])
      assert {:ok, %{"value" => "pw"}} = call(ctx.a, "credential_get", git_lookup("alice"))
    end

    test "revoked Agents cannot use previously granted credentials", ctx do
      grant!(ctx.a, ~w(credential_read credential_write))
      {:ok, _} = call(ctx.a, "credential_put", git("alice", "pw"))
      Repo.update_all(from(a in Agent, where: a.id == ^ctx.a.id), set: [status: :revoked])
      assert {:error, reason} = call(ctx.a, "credential_get", git_lookup("alice"))
      assert reason in [:invalid_agent, :revoked]
    end

    test "invalid and identity-bearing requests are rejected with committed evidence", ctx do
      grant!(ctx.a, ~w(credential_read credential_write))

      assert {:error, :invalid_request} =
               call(ctx.a, "credential_get", Map.put(git_lookup("alice"), "agent_id", ctx.b.id))

      assert {:error, :invalid_request} =
               call(
                 ctx.a,
                 "credential_put",
                 Map.put(git("alice", "pw"), "authority", "bad\nhost")
               )

      assert [%{"operation" => "credential_write", "reason_code" => "invalid_request"} | _] =
               observations(ctx.a)
    end

    test "static runtime reads cannot release Agent-owned payloads", ctx do
      grant!(ctx.a, ~w(read credential_write credential_read), ["host-credentials.**"])
      {:ok, _} = call(ctx.a, "credential_put", git("alice", "pw"))

      path =
        Repo.one!(
          from(s in Secret,
            where: like(s.secret_path, "host-credentials.%"),
            select: s.secret_path
          )
        )

      assert {:error, :not_found} =
               RuntimeAuthorization.authorize_agent_static_read(ctx.a.principal, path)
    end
  end

  describe "managed references" do
    setup ctx do
      grant!(ctx.a, ~w(credential_read credential_write credential_delete credential_list))
      grant!(ctx.a, ~w(read), ["shared.registry.token"])

      {:ok, binding} =
        Management.bind_reference(
          ctx.a.id,
          %{
            namespace: "docker",
            service: "https://index.docker.io/v1/",
            username: "deploy",
            secret_id: ctx.source.id,
            username_field: "user",
            value_field: "token"
          },
          "operator:test"
        )

      %{
        binding: binding,
        registry: %{"namespace" => "docker", "service" => "https://index.docker.io/v1/"}
      }
    end

    test "reads authorize the binding and the source; stores never replace it", ctx do
      assert {:ok, %{"username" => "deploy", "value" => "shared-token-1"} = read} =
               call(ctx.a, "credential_get", ctx.registry)

      assert read["source_kind"] == "reference"

      store = Map.merge(ctx.registry, %{"username" => "deploy", "value" => "shared-token-1"})
      assert {:ok, %{"status" => "unchanged"}} = call(ctx.a, "credential_put", store)
      assert {:error, :read_only} = call(ctx.a, "credential_put", %{store | "value" => "other"})

      # Without a current source read grant the binding grant alone is insufficient.
      Repo.delete_all(from(p in Policy, where: p.name == ^"hc-#{ctx.a.id}-read"))
      assert {:error, :permission_denied} = call(ctx.a, "credential_get", ctx.registry)
      assert {:error, :permission_denied} = call(ctx.a, "credential_put", store)
    end

    test "erase disables the binding, keeps the source, and only explicit enable restores it",
         ctx do
      assert {:ok, %{"status" => "disabled"}} = call(ctx.a, "credential_delete", ctx.registry)
      assert {:ok, %{"status" => "disabled"}} = call(ctx.a, "credential_delete", ctx.registry)
      assert {:error, :not_found} = call(ctx.a, "credential_get", ctx.registry)
      assert {:ok, %Secret{}} = Secrets.get_secret(ctx.source.id)

      # Neither an ordinary store nor source rotation reactivates it.
      store = Map.merge(ctx.registry, %{"username" => "deploy", "value" => "shared-token-1"})
      assert {:error, :read_only} = call(ctx.a, "credential_put", store)

      {:ok, _} =
        Secrets.update_secret(ctx.source.id, %{
          "secret_data" => %{"user" => "deploy", "token" => "shared-token-2"},
          "value_format" => "structured"
        })

      assert {:error, :not_found} = call(ctx.a, "credential_get", ctx.registry)

      assert {:ok, %{"entries" => []}} =
               call(ctx.a, "credential_list", %{"namespace" => "docker"})

      assert {:ok, %HostCredentialBinding{state: "active"}} =
               Management.enable_reference(ctx.binding.id, "operator:test")

      assert {:ok, %{"value" => "shared-token-2"}} = call(ctx.a, "credential_get", ctx.registry)
    end

    test "source deletion and same-path recreation never retarget the binding", ctx do
      {:ok, _} = Secrets.delete_secret(ctx.source.id)

      {:ok, recreated} =
        Secrets.create_secret(%{
          name: "Recreated token",
          secret_path: "shared.registry.token",
          value_format: "structured",
          secret_data: %{"user" => "other", "token" => "recreated"}
        })

      assert %HostCredentialBinding{state: "active", secret_id: nil} =
               Repo.get!(HostCredentialBinding, ctx.binding.id)

      assert {:error, :secret_not_found} = call(ctx.a, "credential_get", ctx.registry)

      assert {:error, :source_unavailable} =
               Management.enable_reference(ctx.binding.id, "operator:test")

      assert {:ok, _} =
               Management.rebind_reference(
                 ctx.binding.id,
                 %{secret_id: recreated.id, username_field: "user", value_field: "token"},
                 "operator:test"
               )

      assert {:ok, %{"value" => "recreated"}} = call(ctx.a, "credential_get", ctx.registry)
    end
  end

  test "credential operations record version 2 observations without values", ctx do
    grant!(ctx.a, ~w(credential_read credential_write))
    {:ok, _} = call(ctx.a, "credential_put", git("alice", "canary-value-7f3a"))
    {:ok, _} = call(ctx.a, "credential_get", git_lookup("alice"))

    events = observations(ctx.a)
    ops = events |> Enum.map(& &1["operation"]) |> Enum.uniq() |> Enum.sort()
    assert ops == ["credential_read", "credential_write"]
    assert Enum.all?(events, &(&1["schema_version"] == 2 and is_nil(&1["application_id"])))
    assert Enum.any?(events, &(&1["phase"] == "core_access"))

    refute Repo.all(AuditLog) |> inspect(limit: :infinity) =~ "canary-value-7f3a"
    refute inspect(events, limit: :infinity) =~ "canary-value-7f3a"
  end

  ## Helpers

  defp agent!(public_id) do
    {:ok, cert} = CA.issue_agent_certificate(public_id)
    cert = Repo.update!(Ecto.Changeset.change(cert, entity_id: public_id, entity_type: "agent"))

    agent =
      Repo.insert!(
        Agent.changeset(%Agent{}, %{
          agent_id: public_id,
          name: public_id,
          status: :active,
          certificate_id: cert.id
        })
      )

    {:ok, principal} =
      RuntimePrincipal.resolve_agent_runtime_principal(%{
        agent_id: public_id,
        certificate_id: cert.id
      })

    %{id: agent.id, public_id: public_id, principal: principal}
  end

  # Explicit grants: the collection root and its entries are listed separately
  # because a descendant pattern does not include the collection root.
  defp grant!(agent, operations, patterns \\ nil) do
    patterns =
      patterns ||
        for ns <- ~w(git docker generic),
            suffix <- ["", ".*"],
            do: "host-credentials.#{agent.id}.#{ns}#{suffix}"

    name =
      if operations == ["read"],
        do: "hc-#{agent.id}-read",
        else: "hc-#{agent.id}-#{System.unique_integer([:positive])}"

    {:ok, _} =
      Policies.create_policy(%{
        name: name,
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => patterns,
          "allowed_operations" => operations
        },
        entity_bindings: ["agent:" <> agent.id]
      })
  end

  defp deny!(agent, operation) do
    {:ok, _} =
      Policies.create_policy(%{
        name: "hc-deny-#{System.unique_integer([:positive])}",
        deny_policy: true,
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["host-credentials.**"],
          "allowed_operations" => [operation]
        },
        entity_bindings: ["agent:" <> agent.id]
      })
  end

  defp revoke_all!(agent) do
    Repo.delete_all(from(p in Policy, where: ^("agent:" <> agent.id) in p.entity_bindings))
  end

  defp call(agent, action, params) do
    correlation = %{request_id: Ecto.UUID.generate(), attempt_id: Ecto.UUID.generate()}
    HostCredentials.execute(agent.principal, action, params, correlation)
  end

  defp observations(agent) do
    Repo.all(
      from(o in AccessAudit.Observation,
        where: o.namespace == ^("agent:" <> agent.public_id),
        order_by: [desc: o.received_at, desc: o.producer_sequence],
        select: o.envelope
      )
    )
  end

  defp known(id, binding, source),
    do: %{"entry_id" => id, "binding_revision" => binding, "source_revision" => source}

  defp git(account, value), do: Map.put(git_lookup(account), "value", value)

  defp git_lookup(account) do
    %{
      "namespace" => "git",
      "service" => "https",
      "authority" => "example.com",
      "context" => "",
      "account" => account
    }
  end

  defp generic(service, account, value),
    do: Map.put(generic_lookup(service, account), "value", value)

  defp generic_lookup(service, account),
    do: %{"namespace" => "generic", "service" => service, "account" => account}

  defp await_state(expected, attempts \\ 500)
  defp await_state(_, 0), do: flunk("Vault did not reach expected state")

  defp await_state(expected, attempts) do
    if SealState.status().state == expected do
      :ok
    else
      Process.sleep(10)
      await_state(expected, attempts - 1)
    end
  end

  defp await_vault(attempts \\ 500)
  defp await_vault(0), do: flunk("Vault did not load")

  defp await_vault(attempts) do
    if SealState.status().state == :not_initialized do
      :ok
    else
      Process.sleep(10)
      await_vault(attempts - 1)
    end
  end
end
