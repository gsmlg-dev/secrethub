defmodule SecretHub.Core.AgentSecretWritesTest do
  use ExUnit.Case, async: false
  import Ecto.Query

  alias SecretHub.Core.{
    AccessAudit,
    AgentSecretWrites,
    Policies,
    Repo,
    RuntimeAuthorization,
    RuntimePrincipal,
    UpgradeGates
  }

  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.RuntimeDatabaseFixture
  alias SecretHub.Core.RuntimeDatabaseFixture.VaultRepo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, AuditLog, Secret}

  @path "backplane.llm.openai-main"

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
    {:ok, _} = CA.generate_root_ca("Secret Write Root #{unique}", "SecretHub", key_size: 2048)
    assert {:ok, _} = UpgradeGates.verify_typed_runtime_authorization(actor_id: "operator:test")

    %{publisher: agent!("sw-publisher-#{unique}"), consumer: agent!("sw-consumer-#{unique}")}
  end

  test "a published secret is versioned and consumable by another authorized Agent", ctx do
    grant!(ctx.publisher, ~w(secret_write secret_delete))
    grant!(ctx.consumer, ~w(read))

    assert {:ok, %{"status" => "created", "path" => @path, "version" => 1}} =
             put(ctx.publisher, %{"api_key" => "sk-1"})

    assert {:ok, %{value: %{"api_key" => "sk-1"}}} = consume(ctx.consumer)

    # Republishing the same value is an audited no-op; a new value is a new version.
    assert {:ok, %{"status" => "unchanged", "version" => 1}} =
             put(ctx.publisher, %{"api_key" => "sk-1"})

    assert {:ok, %{"status" => "updated", "version" => 2}} =
             put(ctx.publisher, %{"api_key" => "sk-2"})

    assert {:ok, %{value: %{"api_key" => "sk-2"}}} = consume(ctx.consumer)

    assert {:ok, %{"status" => "deleted"}} =
             call(ctx.publisher, "secret_delete", %{"path" => @path})

    assert {:ok, %{"status" => "absent"}} =
             call(ctx.publisher, "secret_delete", %{"path" => @path})

    assert {:error, :not_found} = consume(ctx.consumer)
  end

  test "expected_version makes writes and deletes compare-and-set", ctx do
    grant!(ctx.publisher, ~w(secret_write secret_delete))

    assert {:error, :conflict} = put(ctx.publisher, %{"k" => "v"}, expected_version: 1)
    assert {:ok, %{"version" => 1}} = put(ctx.publisher, %{"k" => "v1"})
    assert {:error, :conflict} = put(ctx.publisher, %{"k" => "v2"}, expected_version: 2)
    assert {:ok, %{"version" => 2}} = put(ctx.publisher, %{"k" => "v2"}, expected_version: 1)

    stale = %{"path" => @path, "expected_version" => 1}
    assert {:error, :conflict} = call(ctx.publisher, "secret_delete", stale)
    assert Repo.exists?(from(s in Secret, where: s.secret_path == @path))
  end

  test "only the dedicated operations on a matching path authorize writes", ctx do
    # Generic operations used by existing policy templates never apply.
    grant!(ctx.publisher, ~w(read))
    assert {:error, :permission_denied} = put(ctx.publisher, %{"k" => "v"})

    grant!(ctx.publisher, ~w(secret_write), ["backplane.llm.*"])
    assert {:ok, _} = put(ctx.publisher, %{"k" => "v"})

    assert {:error, :permission_denied} =
             call(ctx.publisher, "secret_put", %{
               "path" => "other.team.key",
               "data" => %{"k" => "v"}
             })

    assert {:error, :permission_denied} =
             call(ctx.publisher, "secret_delete", %{"path" => @path})

    refute Repo.exists?(from(s in Secret, where: s.secret_path == "other.team.key"))
  end

  test "invalid requests and reserved paths are refused before any effect", ctx do
    grant!(ctx.publisher, ~w(secret_write), ["**"])

    for params <- [
          %{"path" => "Backplane.Upper", "data" => %{"k" => "v"}},
          %{"path" => @path, "data" => %{}},
          %{"path" => @path, "data" => %{"k" => 1}},
          %{"path" => @path, "data" => %{"k" => "v"}, "extra" => true},
          %{"path" => "host-credentials.x.git", "data" => %{"k" => "v"}}
        ] do
      assert {:error, :invalid_request} = call(ctx.publisher, "secret_put", params)
    end

    assert {:error, :invalid_request} = call(ctx.publisher, "secret_list", %{})
    assert Repo.aggregate(Secret, :count) == 0
  end

  test "a sealed vault refuses publication", ctx do
    grant!(ctx.publisher, ~w(secret_write))
    stop_supervised!(SealState)
    start_supervised!({SealState, repo: VaultRepo})
    await_state(:sealed)

    assert {:error, :sealed} = put(ctx.publisher, %{"k" => "v"})
  end

  test "decisions are audited without values, including denials", ctx do
    assert {:error, :permission_denied} = put(ctx.publisher, %{"k" => "denied-canary"})
    grant!(ctx.publisher, ~w(secret_write))
    assert {:ok, _} = put(ctx.publisher, %{"k" => "allowed-canary"})

    chain =
      Repo.all(
        from(l in AuditLog,
          where: l.event_type == "secret.agent_write" and l.actor_id == ^ctx.publisher.public_id,
          order_by: l.sequence_number
        )
      )

    assert Enum.map(chain, & &1.access_granted) |> Enum.sort() == [false, true]

    envelopes = observations(ctx.publisher)
    assert Enum.any?(envelopes, &(&1["phase"] == "core_access" and &1["secret_version"] == 1))
    assert Enum.all?(envelopes, &(&1["operation"] == "secret_write"))

    dump = inspect({chain, envelopes})
    refute dump =~ "denied-canary"
    refute dump =~ "allowed-canary"
  end

  defp put(agent, data, opts \\ []) do
    params =
      %{"path" => @path, "data" => data}
      |> then(&if(v = opts[:expected_version], do: Map.put(&1, "expected_version", v), else: &1))

    call(agent, "secret_put", params)
  end

  defp call(agent, action, params) do
    correlation = %{request_id: Ecto.UUID.generate(), attempt_id: Ecto.UUID.generate()}
    AgentSecretWrites.execute(agent.principal, action, params, correlation)
  end

  defp consume(agent),
    do: RuntimeAuthorization.authorize_agent_static_read(agent.principal, @path)

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

  defp grant!(agent, operations, patterns \\ ["backplane.**"]) do
    {:ok, _} =
      Policies.create_policy(%{
        name: "sw-#{System.unique_integer([:positive])}",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => patterns,
          "allowed_operations" => operations
        },
        entity_bindings: ["agent:" <> agent.id]
      })
  end

  defp observations(agent) do
    Repo.all(
      from(o in AccessAudit.Observation,
        where: o.namespace == ^("agent:" <> agent.public_id),
        select: o.envelope
      )
    )
  end

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
