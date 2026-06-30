defmodule SecretHub.Core.Auth.CliAccessTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Auth.{AppRole, CliAccess}
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.CliAccessRequest

  setup do
    ensure_current_audit_partition!()
    :ok
  end

  describe "create_request/2" do
    test "creates a pending request with a 6 character user code" do
      assert {:ok, request} =
               CliAccess.create_request(%{"client_name" => "gao-laptop"}, "203.0.113.15")

      assert request.status == :pending
      assert request.user_code =~ ~r/^[A-Z2-7]{6}$/
      assert request.source_ip == "203.0.113.15"
      assert request.metadata["client_name"] == "gao-laptop"
      assert DateTime.compare(request.expires_at, DateTime.utc_now()) == :gt

      assert [pending] = CliAccess.list_pending()
      assert pending.id == request.id
      assert pending.user_code == request.user_code
    end
  end

  describe "approve_request/3 and poll_request/1" do
    test "approves a pending CLI request with an AppRole and returns a token once" do
      {:ok, role} =
        AppRole.create_role("cli-access-role",
          policies: ["secret-read"],
          secret_id_num_uses: 0
        )

      {:ok, request} = CliAccess.create_request(%{"client_name" => "secrethub-cli"}, "127.0.0.1")

      assert {:pending, pending} = CliAccess.poll_request(request.request_id)
      assert pending.user_code == request.user_code

      assert {:ok, approved} = CliAccess.approve_request(request.id, role.role_id, "admin")
      assert approved.status == :approved
      assert approved.role_id == role.role_id
      assert approved.approved_by == "admin"

      assert {:approved, token_response} = CliAccess.poll_request(request.request_id)
      assert token_response.role_name == "cli-access-role"
      assert token_response.policies == ["secret-read"]
      assert token_response.ttl == AppRole.token_ttl_seconds()
      assert {:ok, payload} = AppRole.verify_token(token_response.token)
      assert payload.role_id == role.role_id
      assert payload.cli_access_request_id == request.id

      assert {:error, :already_consumed} = CliAccess.poll_request(request.request_id)

      delivered = Repo.get!(CliAccessRequest, request.id)
      assert delivered.status == :approved
      assert delivered.consumed_at

      assert [visible] = CliAccess.list_visible()
      assert visible.id == request.id
      assert visible.status == :approved
    end

    test "rejects an unknown or non-AppRole role" do
      {:ok, request} = CliAccess.create_request(%{}, "127.0.0.1")

      assert {:error, :role_not_found} =
               CliAccess.approve_request(request.id, Ecto.UUID.generate(), "admin")
    end

    test "revokes delivered CLI access and rejects its issued token" do
      {:ok, role} =
        AppRole.create_role("cli-access-revoked-role",
          policies: ["secret-read"],
          secret_id_num_uses: 0
        )

      {:ok, request} = CliAccess.create_request(%{"client_name" => "revoke-me"}, "127.0.0.1")
      {:ok, _approved} = CliAccess.approve_request(request.id, role.role_id, "admin")
      {:approved, %{token: token}} = CliAccess.poll_request(request.request_id)

      assert {:ok, _payload} = AppRole.verify_token(token)

      assert {:ok, revoked} = CliAccess.revoke_request(request.id, "admin")
      assert revoked.status == :revoked
      assert revoked.revoked_by == "admin"
      assert revoked.revoked_at

      assert {:error, "CLI access has been revoked"} = AppRole.verify_token(token)
      assert {:error, :revoked} = CliAccess.poll_request(request.request_id)
    end
  end

  defp ensure_current_audit_partition! do
    today = Date.utc_today()
    month = String.pad_leading(to_string(today.month), 2, "0")
    partition_name = "audit_logs_y#{today.year}m#{month}"
    from_date = %Date{today | day: 1}
    to_date = Date.add(from_date, Date.days_in_month(from_date))

    Repo.query!("""
    CREATE TABLE IF NOT EXISTS #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{Date.to_iso8601(from_date)}') TO ('#{Date.to_iso8601(to_date)}')
    """)
  end
end
