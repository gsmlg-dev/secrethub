defmodule SecretHub.Web.HostCredentialControllerTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, AuditLog, HostCredentialBinding, Secret}

  setup do
    agent =
      Repo.insert!(
        Agent.changeset(%Agent{}, %{
          agent_id: "hc-api-agent-#{System.unique_integer([:positive])}",
          name: "hc-api-agent",
          status: :active
        })
      )

    secret =
      Repo.insert!(
        Secret.changeset(%Secret{}, %{
          name: "Shared registry token",
          secret_path: "shared.registry.api-#{System.unique_integer([:positive])}",
          secret_type: :static,
          value_format: "structured",
          encrypted_data: <<0, 1, 2, 3>>
        })
      )

    %{agent: agent, secret: secret}
  end

  test "requires a valid management CSRF token", %{agent: agent, secret: secret} do
    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      build_conn()
      |> put_private(:plug_skip_csrf_protection, false)
      |> post(references_path(agent), bind_params(secret))
    end

    refute Repo.exists?(HostCredentialBinding)
  end

  test "binds, lists, disables, enables and rebinds a reference without values", %{
    agent: agent,
    secret: secret
  } do
    bound = management_post(references_path(agent), bind_params(secret))
    data = json_response(bound, 201)["data"]
    assert get_resp_header(bound, "cache-control") == ["no-store"]

    assert %{
             "source_kind" => "reference",
             "state" => "active",
             "revision" => 1,
             "source_secret_id" => source_id,
             "entry_id" => id
           } = data

    assert source_id == secret.id
    refute Map.has_key?(data, "value")

    listed = build_conn() |> get("/admin/api/agents/#{agent.agent_id}/host-credentials")
    assert [%{"entry_id" => ^id}] = json_response(listed, 200)["data"]

    disabled = management_post("/admin/api/host-credentials/#{id}/disable", %{})
    assert %{"state" => "disabled", "revision" => 2} = json_response(disabled, 200)["data"]

    enabled = management_post("/admin/api/host-credentials/#{id}/enable", %{})
    assert %{"state" => "active", "revision" => 3} = json_response(enabled, 200)["data"]

    other = insert_secret!("shared.registry.rebound-#{System.unique_integer([:positive])}")

    rebound =
      management_post("/admin/api/host-credentials/#{id}/rebind", %{
        "secret_id" => other.id,
        "value_field" => "token"
      })

    assert %{"source_secret_id" => other_id, "revision" => 4} =
             json_response(rebound, 200)["data"]

    assert other_id == other.id

    events =
      Repo.all(AuditLog)
      |> Enum.map(& &1.event_type)
      |> Enum.filter(&String.starts_with?(&1, "host_credential."))

    assert events == [
             "host_credential.reference_bound",
             "host_credential.reference_disabled",
             "host_credential.reference_enabled",
             "host_credential.reference_rebound"
           ]
  end

  test "rejects unknown Agents, bindings, Agent-owned sources and duplicate identities", %{
    agent: agent,
    secret: secret
  } do
    assert json_response(
             management_post(
               "/admin/api/agents/missing-agent/host-credentials/references",
               bind_params(secret)
             ),
             404
           ) == %{"error" => "agent_not_found"}

    assert json_response(
             management_post("/admin/api/host-credentials/#{Ecto.UUID.generate()}/enable", %{}),
             404
           ) == %{"error" => "binding_not_found"}

    owned = insert_secret!("host-credentials.#{agent.id}.docker.#{Ecto.UUID.generate()}")

    assert json_response(
             management_post(references_path(agent), %{
               bind_params(secret)
               | "secret_id" => owned.id
             }),
             422
           ) == %{"error" => "source_unavailable"}

    assert json_response(management_post(references_path(agent), bind_params(secret)), 201)

    assert json_response(management_post(references_path(agent), bind_params(secret)), 409) ==
             %{"error" => "conflict"}
  end

  defp references_path(agent),
    do: "/admin/api/agents/#{agent.agent_id}/host-credentials/references"

  defp bind_params(secret) do
    %{
      "namespace" => "docker",
      "service" => "registry.example.com:5000",
      "username" => "deploy",
      "secret_id" => secret.id,
      "username_field" => "user",
      "value_field" => "token"
    }
  end

  defp insert_secret!(path) do
    Repo.insert!(
      Secret.changeset(%Secret{}, %{
        name: "Source secret",
        secret_path: path,
        secret_type: :static,
        value_format: "structured",
        encrypted_data: <<0, 1, 2, 3>>
      })
    )
  end

  defp management_post(path, params) do
    csrf_conn = get(build_conn(), "/v1/sys/csrf-token")
    csrf_token = json_response(csrf_conn, 200)["csrf_token"]

    csrf_conn
    |> recycle()
    |> put_private(:plug_skip_csrf_protection, false)
    |> put_req_header("x-csrf-token", csrf_token)
    |> post(path, params)
  end
end
