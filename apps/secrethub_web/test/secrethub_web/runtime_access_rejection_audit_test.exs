defmodule SecretHub.Web.RuntimeAccessRejectionAuditTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{AccessAudit, Repo, RuntimeDatabaseFixture}
  alias SecretHub.Shared.Schemas.{Agent, AuthorizationEpoch, Certificate}
  alias SecretHub.Web.AgentRuntimeChannel

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    original_profile = Application.fetch_env(:secrethub_core, :launch_profile)
    Application.delete_env(:secrethub_core, :launch_profile)

    on_exit(fn ->
      case original_profile do
        {:ok, profile} -> Application.put_env(:secrethub_core, :launch_profile, profile)
        :error -> Application.delete_env(:secrethub_core, :launch_profile)
      end
    end)

    agent_id = "runtime-rejection-#{System.unique_integer([:positive])}"
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    certificate =
      Repo.insert!(%Certificate{
        serial_number: Ecto.UUID.generate(),
        fingerprint: Ecto.UUID.generate(),
        certificate_pem: "fixture",
        subject: "fixture",
        issuer: "fixture",
        common_name: agent_id,
        cert_type: :agent_client,
        entity_id: agent_id,
        entity_type: "agent",
        valid_from: now,
        valid_until: DateTime.add(now, 86_400)
      })

    Repo.insert!(%Agent{
      agent_id: agent_id,
      name: "Runtime rejection fixture",
      status: :active,
      certificate_id: certificate.id
    })

    %{socket: %Phoenix.Socket{assigns: %{agent_id: agent_id, certificate_id: certificate.id}}}
  end

  test "malformed runtime reads retain bounded unattributed Core evidence", %{socket: socket} do
    for payload <- [nil, %{}, %{"path" => %{"value" => "REJECTION-SECRET-CANARY"}}] do
      assert {:reply, {:error, %{reason: "FORBIDDEN"}}, ^socket} =
               AgentRuntimeChannel.handle_in("secret:read", payload, socket)
    end

    assert_unattributed_decisions(3, "invalid_request")
    assert {:ok, %{entries: requests}} = AccessAudit.requests()

    for request <- requests do
      assert {:ok, [observation]} = AccessAudit.timeline(request.namespace, request.request_id)
      refute inspect(observation) =~ "REJECTION-SECRET-CANARY"
    end
  end

  test "missing and invalid local auth versions cannot hide a claimed application rejection", %{
    socket: socket
  } do
    for version <- [nil, 0, "2"] do
      payload = %{
        "path" => "audit.rejected.secret",
        "app_id" => Ecto.UUID.generate(),
        "certificate_fingerprint" => String.duplicate("0", 64),
        "local_auth_version" => version
      }

      assert {:reply, {:error, %{reason: "INCOMPATIBLE_VERSION"}}, ^socket} =
               AgentRuntimeChannel.handle_in("secret:read", payload, socket)
    end

    assert_unattributed_decisions(3, "incompatible_version")
  end

  test "bare reads rejected at the active auth floor retain a Core decision", %{socket: socket} do
    Repo.update_all(AuthorizationEpoch, set: [minimum_uds_auth_version: 2])

    assert {:reply, {:error, %{reason: "INCOMPATIBLE_VERSION"}}, ^socket} =
             AgentRuntimeChannel.handle_in(
               "secret:read",
               %{"path" => "audit.rejected.secret"},
               socket
             )

    assert_unattributed_decisions(1, "incompatible_version")
  end

  test "bare reads rejected by the launch profile retain a Core decision", %{socket: socket} do
    Application.put_env(:secrethub_core, :launch_profile, :single_operator)

    assert {:reply, {:error, %{reason: "INCOMPATIBLE_VERSION"}}, ^socket} =
             AgentRuntimeChannel.handle_in(
               "secret:read",
               %{"path" => "audit.rejected.secret"},
               socket
             )

    assert_unattributed_decisions(1, "incompatible_version")
  end

  test "a failed required rejection append returns an explicit unavailable result", %{
    socket: socket
  } do
    Repo.query!("ALTER TABLE access_audit_events RENAME TO access_audit_events_unavailable")

    assert {:reply, {:error, %{reason: "UNAVAILABLE"}}, ^socket} =
             AgentRuntimeChannel.handle_in("secret:read", %{}, socket)
  end

  defp assert_unattributed_decisions(count, reason) do
    assert {:ok, %{requests: ^count, unverified: ^count, incomplete: ^count}} =
             AccessAudit.summary()

    assert {:ok, %{entries: entries}} = AccessAudit.requests()

    assert Enum.all?(
             entries,
             &(&1.application_id == nil and &1.identity_status == "unverified" and
                 &1.core_outcome == "denied" and &1.core_reason_code == reason)
           )
  end
end
