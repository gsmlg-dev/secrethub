defmodule SecretHub.Web.SecretValueFormatsTest do
  use ExUnit.Case, async: false
  import Plug.Conn
  import Phoenix.ConnTest
  import ExUnit.CaptureLog

  alias SecretHub.Core.{Policies, RuntimeDatabaseFixture, Secrets}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Web.SecretApiController

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid, :normal)
    RuntimeDatabaseFixture.setup(tags)
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo})
    SecretHub.Core.VaultTestHelpers.await_vault_state(:not_initialized)
    {:ok, [a, b | _]} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(a)
    {:ok, _} = SealState.unseal(b)

    {:ok, policy} =
      Policies.create_policy(%{
        name: "secret-value-formats",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["test.formats.*"],
          "allowed_operations" => ["create", "read"]
        }
      })

    %{policy: policy}
  end

  test "Text remains a data wrapper and historical responses use their own format", %{
    policy: policy
  } do
    text = "  {\"value\":\"still text\"}\n"

    assert %{status: 200} =
             write(policy, %{"value_format" => "text", "data" => %{"value" => text}})

    assert %{
             "data" => %{"value" => ^text},
             "metadata" => %{"value_format" => "text", "version" => 1}
           } = read(policy)

    assert %{status: 200} = write(policy, %{"data" => %{"value" => ""}})

    assert %{
             "data" => %{"value" => ""},
             "metadata" => %{"value_format" => "text", "version" => 2}
           } = read(policy)

    object = %{"value" => "application-value", "region" => "custom-region"}
    assert %{status: 200} = write(policy, %{"value_format" => "structured", "data" => object})

    assert %{"data" => ^object, "metadata" => %{"value_format" => "structured", "version" => 3}} =
             read(policy)

    assert %{
             "data" => %{"value" => ^text},
             "metadata" => %{"value_format" => "text", "version" => 1}
           } = read(policy, "1")
  end

  test "Structured accepts empty objects and preserves arbitrary JSON fields", %{policy: policy} do
    assert %{status: 200} = write(policy, %{"value_format" => "structured", "data" => %{}})
    assert %{"data" => %{}, "metadata" => %{"value_format" => "structured"}} = read(policy)

    object = %{
      "value" => "x",
      "data" => [1, true, nil],
      "format" => %{"nested" => "custom"},
      "value_format" => "application-field"
    }

    assert %{status: 200} = write(policy, %{"data" => object})
    assert %{"data" => ^object, "metadata" => %{"value_format" => "structured"}} = read(policy)
  end

  test "omitted format keeps legacy writes and empty legacy requests remain invalid", %{
    policy: policy
  } do
    object = %{"value" => "legacy", "sibling" => "retained"}
    assert %{status: 200} = write(policy, %{"data" => object})
    assert %{"data" => ^object, "metadata" => %{"value_format" => nil}} = read(policy)
    assert %{status: 400} = write(policy, %{"data" => %{}})
    assert {:ok, %{value_format: nil}} = Secrets.get_secret_by_path("test.formats.config")
  end

  test "invalid explicit formats and Text shapes fail without disclosing input", %{policy: policy} do
    logs =
      capture_log(fn ->
        assert %{status: 400} =
                 write(policy, %{
                   "value_format" => "unexpected",
                   "data" => %{"value" => "private-input-marker"}
                 })

        response =
          write(policy, %{
            "value_format" => "text",
            "data" => %{"value" => "private-input-marker", "extra" => "x"}
          })

        assert response.status == 422
        refute response.resp_body =~ "private-input-marker"
      end)

    refute logs =~ "private-input-marker"
    assert {:error, "Secret not found"} = Secrets.get_secret_by_path("test.formats.config")
  end

  defp conn(policy) do
    build_conn()
    |> assign(:current_policies, [policy])
    |> assign(:current_actor, %{type: "system", id: "test-secret-formats"})
  end

  defp write(policy, params),
    do:
      SecretApiController.create_or_update(
        conn(policy),
        Map.put(params, "path", ["test", "formats", "config"])
      )

  defp read(policy, version \\ nil) do
    response =
      SecretApiController.read(conn(policy), %{
        "path" => ["test", "formats", "config"],
        "version" => version
      })

    assert response.status == 200
    Jason.decode!(response.resp_body)
  end
end
