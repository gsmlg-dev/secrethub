defmodule SecretHub.Web.AccessReadAuditTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import Plug.Conn
  alias SecretHub.Core.{AccessAudit, Audit, Policies, Repo, RuntimeDatabaseFixture, Secrets}
  alias SecretHub.Core.RuntimeDatabaseFixture.VaultRepo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Web.SecretApiController

  defmodule ClosedAdapter do
    def send_resp(_, _, _, _), do: raise("DISPOSABLE-AUDIT-VALUE-CANARY TOKEN-CANARY")
  end

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)
    start_supervised!({SealState, repo: VaultRepo})
    await_ready()
    {:ok, shares} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(Enum.at(shares, 0))
    {:ok, _} = SealState.unseal(Enum.at(shares, 1))

    {:ok, secret} =
      Secrets.create_secret(%{
        name: "Audit disposable secret",
        secret_path: "audit.direct.secret",
        value: "DISPOSABLE-AUDIT-VALUE-CANARY"
      })

    {:ok, secret} = Secrets.update_secret(secret.id, %{value: "DISPOSABLE-AUDIT-VALUE-CANARY"})

    {:ok, policy} =
      Policies.create_policy(%{
        name: "direct-audit-reader",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["audit.direct.*"],
          "allowed_operations" => ["read"]
        }
      })

    %{secret: secret, policy: policy}
  end

  test "latest and historical token reads use checked durable facts and preserve token attribution",
       ctx do
    logs =
      capture_log(fn ->
        for version <- [nil, "1"] do
          response =
            SecretApiController.read(conn(ctx.policy), %{
              "path" => ["audit", "direct", "secret"],
              "version" => version
            })

          assert response.status == 200
          assert response.resp_body =~ "DISPOSABLE-AUDIT-VALUE-CANARY"
        end
      end)

    refute logs =~ "DISPOSABLE-AUDIT-VALUE-CANARY"
    refute logs =~ "TOKEN-CANARY"

    assert {:ok, %{requests: 2, success: 2, incomplete: 0, unverified: 2}} = AccessAudit.summary()
    assert {:ok, %{entries: [first, second]}} = AccessAudit.requests()

    for request <- [first, second] do
      assert request.application_id == nil
      assert request.attribution == "token"
      assert {:ok, events} = AccessAudit.timeline(request.namespace, request.request_id)

      assert Enum.map(events, & &1.envelope["phase"]) == [
               "admitted",
               "core_decision",
               "core_access",
               "release_intent",
               "response_sent"
             ]

      refute inspect(events) =~ "DISPOSABLE-AUDIT-VALUE-CANARY"
      refute inspect(events) =~ "TOKEN-CANARY"
    end

    export = Audit.export_to_csv(%{event_type: "access.observed", limit: 100})
    assert export =~ "access.observed"
    refute export =~ "DISPOSABLE-AUDIT-VALUE-CANARY"
    refute export =~ "TOKEN-CANARY"
    assert {:ok, :valid} = Audit.verify_chain()
  end

  test "policy denial, missing version and sealed Vault remain distinct", ctx do
    denied = SecretApiController.read(conn(nil), %{"path" => ["audit", "direct", "secret"]})
    assert denied.status == 403

    missing =
      SecretApiController.read(conn(ctx.policy), %{
        "path" => ["audit", "direct", "secret"],
        "version" => "999"
      })

    assert missing.status == 404
    :ok = stop_supervised(SealState)
    start_supervised!({SealState, repo: VaultRepo})
    await_ready()
    assert SealState.sealed?()

    sealed =
      SecretApiController.read(conn(ctx.policy), %{"path" => ["audit", "direct", "secret"]})

    assert sealed.status == 503
    assert {:ok, %{requests: 3, denied: 1, error: 2}} = AccessAudit.summary()
    assert {:ok, reasons} = AccessAudit.reasons()

    assert MapSet.new(reasons, & &1.reason_code) ==
             MapSet.new(~w(permission_denied not_found sealed))
  end

  test "storage outage refuses latest and historical plaintext before sending", ctx do
    Repo.query!("ALTER TABLE access_audit_events RENAME TO access_audit_events_unavailable", [])

    for version <- [nil, "1"] do
      response =
        SecretApiController.read(conn(ctx.policy), %{
          "path" => ["audit", "direct", "secret"],
          "version" => version
        })

      assert response.status == 503
      assert response.resp_body =~ "audit_unavailable"
      refute response.resp_body =~ "DISPOSABLE-AUDIT-VALUE-CANARY"
    end
  end

  test "HTTP adapter failure records the observed transport error with sanitized exceptions",
       ctx do
    connection = %{conn(ctx.policy) | adapter: {ClosedAdapter, nil}}

    assert_raise Plug.Conn.NotSentError, "Secret response transport failed", fn ->
      SecretApiController.read(connection, %{"path" => ["audit", "direct", "secret"]})
    end

    assert {:ok, %{requests: 1, error: 1, incomplete: 0}} = AccessAudit.summary()
    assert {:ok, %{entries: [request]}} = AccessAudit.requests()
    assert {:ok, events} = AccessAudit.timeline(request.namespace, request.request_id)
    assert List.last(events).envelope["phase"] == "response_failed"
    assert List.last(events).envelope["reason_code"] == "transport_error"
    refute inspect(events) =~ "DISPOSABLE-AUDIT-VALUE-CANARY"
    refute inspect(events) =~ "TOKEN-CANARY"
  end

  defp conn(policy) do
    Plug.Test.conn(:get, "/v1/secret/data/audit/direct/secret")
    |> put_req_header("authorization", "Bearer TOKEN-CANARY")
    |> assign(:current_actor, %{type: "approle", id: Ecto.UUID.generate()})
    |> assign(:current_policies, if(policy, do: [policy], else: []))
  end

  defp await_ready do
    case SealState.status() do
      %{state: :loading} ->
        Process.sleep(10)
        await_ready()

      _ ->
        :ok
    end
  end
end
