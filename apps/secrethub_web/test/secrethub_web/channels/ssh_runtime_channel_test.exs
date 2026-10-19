defmodule SecretHub.Web.SSHRuntimeChannelTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{Agents, Repo, RuntimeDatabaseFixture, SSH}
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Web.AgentRuntimeChannel

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)

    unless Process.whereis(SecretHub.Web.PubSub) do
      start_supervised!({Phoenix.PubSub, name: SecretHub.Web.PubSub})
    end

    start_supervised!({ConnectionManager, name: ConnectionManager})
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo})
    await_vault()
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    cert =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: "ssh",
        issuer: "fixture",
        common_name: "ssh",
        cert_type: :agent_client,
        entity_type: "agent",
        entity_id: "ssh-source",
        valid_from: DateTime.add(now, -60),
        valid_until: DateTime.add(now, 3600)
      })

    agent =
      Repo.insert!(%Agent{
        agent_id: "ssh-source",
        name: "SSH Source",
        status: :trusted_connected,
        certificate_id: cert.id
      })

    socket = %Phoenix.Socket{
      assigns: %{
        agent_id: agent.agent_id,
        certificate_id: cert.id,
        certificate_serial: cert.serial_number,
        certificate_fingerprint: cert.fingerprint
      }
    }

    %{agent: agent, certificate: cert, socket: socket}
  end

  test "join negotiates SSH capabilities independently and persists only known values", ctx do
    assert {:ok, %{runtime_capabilities: capabilities}, socket} =
             AgentRuntimeChannel.join(
               "agent:runtime",
               %{
                 "runtime_capabilities" => ["uds_auth_v2", "ssh_lookup_v1", "forged"],
                 "agent_id" => "forged"
               },
               ctx.socket
             )

    assert capabilities == ["ssh_lookup_v1", "uds_auth_v2"]
    assert Agents.get_agent("ssh-source").runtime_capabilities == capabilities

    assert {:reply, {:error, %{reason: "SSH_UNAVAILABLE"}}, _} =
             AgentRuntimeChannel.handle_in("ssh:identities", %{}, socket)
  end

  test "older peers join with SSH unavailable", ctx do
    assert {:ok, %{runtime_capabilities: []}, socket} =
             AgentRuntimeChannel.join("agent:runtime", %{}, ctx.socket)

    assert {:reply, {:error, %{reason: "SSH_UNAVAILABLE"}}, _} =
             AgentRuntimeChannel.handle_in("ssh:authorized_keys", %{}, socket)
  end

  test "SSH calls derive the Agent from the certificate and validate current eligibility", ctx do
    assert {:ok, _, socket} =
             AgentRuntimeChannel.join(
               "agent:runtime",
               %{"runtime_capabilities" => ["ssh_lookup_v1", "ssh_signing_v1"]},
               ctx.socket
             )

    assert {:reply, {:ok, %{identities: []}}, _} =
             AgentRuntimeChannel.handle_in(
               "ssh:identities",
               %{"agent_id" => "forged", "uid" => 1000, "username" => "deploy"},
               socket
             )

    assert {:reply, {:error, %{reason: "FORBIDDEN"}}, _} =
             AgentRuntimeChannel.handle_in(
               "ssh:authorize_sign",
               %{
                 "agent_id" => "forged",
                 "uid" => 1000,
                 "username" => "deploy",
                 "public_key" => "invalid"
               },
               socket
             )

    assert SSH.snapshot().revision == 0
    Repo.update!(Ecto.Changeset.change(ctx.certificate, revoked: true))

    assert {:stop, _, {:error, %{reason: "runtime_not_authorized"}}, _} =
             AgentRuntimeChannel.handle_in("ssh:identities", %{}, socket)

    Repo.update!(
      Ecto.Changeset.change(ctx.certificate,
        revoked: false,
        valid_until: DateTime.utc_now() |> DateTime.add(-60) |> DateTime.truncate(:second)
      )
    )

    assert {:stop, _, {:error, %{reason: "runtime_not_authorized"}}, _} =
             AgentRuntimeChannel.handle_in("ssh:authorized_keys", %{}, socket)
  end

  test "invalid SSH payloads and unnegotiated operations fail without key data", ctx do
    {:ok, _, socket} =
      AgentRuntimeChannel.join(
        "agent:runtime",
        %{"runtime_capabilities" => ["ssh_lookup_v1"]},
        ctx.socket
      )

    for payload <- [nil, "invalid", %{"username" => "root\n", "key" => "bad"}] do
      assert {:reply, {:error, %{reason: "FORBIDDEN"}}, _} =
               AgentRuntimeChannel.handle_in("ssh:authorized_keys", payload, socket)
    end
  end

  defp await_vault(attempts \\ 400)
  defp await_vault(0), do: flunk("Vault did not load")

  defp await_vault(attempts) do
    if SealState.status().state == :loading do
      Process.sleep(25)
      await_vault(attempts - 1)
    end
  end
end
