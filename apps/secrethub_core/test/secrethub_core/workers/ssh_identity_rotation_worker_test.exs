defmodule SecretHub.Core.Workers.SSHIdentityRotationWorkerTest do
  use ExUnit.Case, async: false
  import Ecto.Query
  alias SecretHub.Core.RuntimeDatabaseFixture

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
  end

  alias SecretHub.Core.{Repo, SSH}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, AuditLog, Certificate}
  alias SecretHub.Shared.SSH.Key

  setup do
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo})
    await_state(:not_initialized)
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    source = agent("source", ["ssh_lookup_v1", "ssh_signing_v1"])
    target = agent("target", ["ssh_lookup_v1"])
    {:ok, host} = Key.generate("ed25519")

    %{source: source, target: target, host: host.public.public_line}
  end

  test "due Agent identities get rotation requests and external ones only a flag", ctx do
    {_, identity} = enroll(ctx)
    grant(ctx, identity)
    {:ok, ext} = Key.generate("ed25519")

    {:ok, _} =
      SSH.apply_changes(
        [
          %{
            "op" => "identity_external_add",
            "name" => "ci",
            "public_key" => ext.public.public_line,
            "rotation_days" => 1
          }
        ],
        SSH.snapshot().revision
      )

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

    assert %{requested_generation: 2} =
             Enum.find(SSH.snapshot().identities, &(&1.id == identity.id))

    assert Repo.exists?(
             from(e in AuditLog, where: e.event_type == "ssh.identity_rotation_requested")
           )

    assert Repo.exists?(
             from(e in AuditLog, where: e.event_type == "ssh.identity_rotation_overdue")
           )
  end

  test "worker performs and returns :ok" do
    assert :ok = SecretHub.Core.Workers.SSHIdentityRotationWorker.perform(nil)
  end

  test "worker returns :ok while sealed" do
    SealState.seal()
    assert :ok = SecretHub.Core.Workers.SSHIdentityRotationWorker.perform(nil)
  end

  defp enroll(ctx, uid \\ 1000, username \\ "gao") do
    {:ok, key} = Key.generate("ed25519")

    assert {:ok, %{revision: _}} =
             SSH.runtime_operation(principal(ctx.source), "identity_report", %{
               "uid" => uid,
               "username" => username,
               "generation" => 1,
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
          endpoint(ctx),
          %{
            "op" => "rule_upsert",
            "id" => "grant",
            "effect" => "allow",
            "source_kind" => "identity",
            "source_id" => identity.id,
            "destination_kind" => "endpoint",
            "destination_id" => "target",
            "destination_user" => "app"
          }
        ],
        rev
      )
  end

  defp endpoint(ctx) do
    %{
      "op" => "endpoint_upsert",
      "agent_id" => "target",
      "aliases" => ["target.example"],
      "port" => 22,
      "host_keys" => [ctx.host],
      "approved" => true
    }
  end

  defp agent(id, capabilities) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    cert =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: id,
        issuer: "fixture",
        common_name: id,
        cert_type: :agent_client,
        entity_type: "agent",
        entity_id: id,
        valid_from: DateTime.add(now, -60),
        valid_until: DateTime.add(now, 3600)
      })

    Repo.insert!(%Agent{
      agent_id: id,
      name: id,
      status: :trusted_connected,
      certificate_id: cert.id,
      runtime_capabilities: capabilities
    })
  end

  defp principal(agent), do: %{agent_id: agent.agent_id, certificate_id: agent.certificate_id}
  defp await_state(expected, attempts \\ 1000)
  defp await_state(_, 0), do: flunk("Vault not ready")

  defp await_state(expected, attempts) do
    if SealState.status().state != expected do
      Process.sleep(10)
      await_state(expected, attempts - 1)
    end
  end
end
