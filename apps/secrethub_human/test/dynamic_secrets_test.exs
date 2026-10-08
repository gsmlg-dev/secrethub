defmodule SecretHub.Human.DynamicSecretsTest do
  alias SecretHub.HumanWeb.Bitwarden.Token
  use SecretHub.Human.DataCase, async: false
  alias SecretHub.Human.{Accounts, DynamicSecrets, RevealStore}

  defmodule Boundary do
    def list_capabilities(_), do: {:ok, [%{mount_id: "test", role_id: "read", max_ttl: 300}]}
    def authorize(_, _), do: {:ok, %{}}

    def issue_dynamic_secret(_, attrs),
      do:
        {:ok,
         %{
           lease: %{
             id: Ecto.UUID.generate(),
             mount_id: attrs.mount_id,
             role_id: attrs.role_id,
             status: "active",
             expires_at: DateTime.add(DateTime.utc_now(), 300),
             renewable: true
           },
           credentials: %{password: "memory-only-canary"}
         }}

    def read_lease(_, id),
      do: {:ok, %{id: id, status: "active", expires_at: DateTime.add(DateTime.utc_now(), 300)}}

    def abandon_human_lease(_), do: :ok
    def record_human_event(_, _, _, _), do: {:ok, Ecto.UUID.generate()}
  end

  setup do
    encrypted =
      "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

    attrs = %{
      email: "dynamic-#{System.unique_integer([:positive])}@example.test",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted
    }

    {:ok, _} = Accounts.provision(attrs, server_iterations: 1000)

    {:ok, session} =
      Accounts.authenticate(attrs.email, attrs.password_hash, %{identifier: "native"})

    token = Token.issue(session)
    store = start_supervised!({RevealStore, name: nil})
    %{actor: session.actor, token: token, opts: [boundary: Boundary, reveal_store: store]}
  end

  test "references persist metadata; issued values are revealed once and never persisted", %{
    actor: actor,
    token: token,
    opts: opts
  } do
    assert {:ok, reference} =
             DynamicSecrets.create_reference(
               token,
               %{
                 mount_id: "test",
                 role_id: "read",
                 display_name: "Test database",
                 requested_ttl: 300
               },
               opts
             )

    assert {:ok, %{reveal_token: reveal, lease: lease}} =
             DynamicSecrets.request(
               token,
               reference.id,
               %{request_id: Ecto.UUID.generate()},
               opts
             )

    assert {:ok, %{credentials: %{password: "memory-only-canary"}}} =
             DynamicSecrets.reveal(token, reveal, opts)

    assert {:error, :invalid_reveal} = DynamicSecrets.reveal(token, reveal, opts)
    assert {:ok, [metadata]} = DynamicSecrets.stored_leases(actor)
    assert metadata.id == lease.id
    refute inspect(metadata) =~ "memory-only-canary"
    refute inspect(reference) =~ "memory-only-canary"
  end

  test "a revoked session cannot redeem an outstanding reveal", %{
    actor: actor,
    token: token,
    opts: opts
  } do
    {:ok, reference} =
      DynamicSecrets.create_reference(
        token,
        %{mount_id: "test", role_id: "read", requested_ttl: 300},
        opts
      )

    {:ok, %{reveal_token: reveal}} =
      DynamicSecrets.request(token, reference.id, %{request_id: Ecto.UUID.generate()}, opts)

    :ok = Accounts.revoke_session(actor, actor.session_id)
    assert {:error, :unauthenticated} = DynamicSecrets.reveal(token, reveal, opts)
  end
end
