defmodule SecretHub.Human.AccountsTest do
  use SecretHub.Human.DataCase, async: true

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Human.{Accounts, Password, RateLimiter}
  alias SecretHub.Human.Schemas.{AccessToken, Identity, Session}

  defp encrypted do
    "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))
  end

  defp attrs do
    %{
      email: "account-#{System.unique_integer([:positive])}@example.test",
      name: "Owner",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted(),
      public_key: "encrypted-compatible-public-key",
      encrypted_private_key: encrypted()
    }
  end

  defp provision(overrides \\ %{}) do
    input = Map.merge(attrs(), overrides)
    assert {:ok, user} = Accounts.provision(input, server_iterations: 1000)
    {user, input}
  end

  defp authenticate(input, identifier \\ "device-1", opts \\ []) do
    limiter = start_supervised!(Supervisor.child_spec({RateLimiter, name: nil}, id: make_ref()))

    Accounts.authenticate(
      input.email,
      input.password_hash,
      %{identifier: identifier, name: "Browser", type: 9},
      Keyword.merge([rate_limiter: limiter, server_iterations: 1000], opts)
    )
  end

  test "self registration is closed by default" do
    assert {:error, :signup_disabled} = Accounts.register(attrs())
  end

  test "operator provision normalizes identity and does not store the supplied password verifier" do
    {user, input} = provision(%{email: "  OWNER@example.test "})
    assert user.email == "owner@example.test"
    assert user.kdf_iterations == 600_000
    assert user.encrypted_key == input.encrypted_key
    identity = Repo.get_by!(Identity, user_id: user.id)
    refute identity.password_digest == input.password_hash
    refute inspect(identity) =~ input.password_hash
    refute inspect(identity) =~ Base.encode64(identity.password_digest)
    refute inspect(user) =~ input.encrypted_key
  end

  test "valid password establishes device-bound bearer authentication with digests at rest" do
    {user, input} = provision()

    assert {:ok,
            %{
              actor: actor,
              access_token: access,
              refresh_token: refresh,
              expires_in: 900,
              user: dto
            }} = authenticate(input)

    assert dto.id == user.id
    assert {:ok, ^actor} = Accounts.authenticate_session(access)
    assert {:ok, ^actor} = Accounts.validate_actor(actor)
    session = Repo.get!(Session, actor.session_id)
    assert session.access_digest == :crypto.hash(:sha256, access)
    assert session.refresh_digest == :crypto.hash(:sha256, refresh)
    stored_access = Repo.get!(AccessToken, session.access_digest)
    assert stored_access.session_id == session.id
    assert stored_access.expires_at == session.expires_at
    refute inspect(stored_access) =~ access
    refute inspect(stored_access) =~ Base.encode64(stored_access.digest)
    refute inspect(session) =~ access
    refute inspect(session) =~ refresh
    refute inspect(actor) =~ Base.encode64(actor.proof)
  end

  test "bad passwords and unknown identities return the same opaque authentication failure" do
    {_user, input} = provision()

    assert {:error, :invalid_credentials} =
             authenticate(%{input | password_hash: Base.encode64(<<0::256>>)})

    assert {:error, :invalid_credentials} = authenticate(%{input | email: "unknown@example.test"})
  end

  test "password verification supports bounded slow hashing and unknown-user dummy work" do
    verifier = Base.encode64(<<17::256>>)
    assert {:ok, encoded} = Password.hash(verifier, iterations: 1000)
    assert Password.verify(verifier, encoded)
    refute Password.verify(Base.encode64(<<18::256>>), encoded)
    refute Password.verify(verifier, nil, iterations: 1000)
    assert {:error, :invalid_password_hash} = Password.hash("short", iterations: 1000)
    assert {:error, :invalid_iterations} = Password.hash(verifier, iterations: 999)
  end

  test "refresh rotates both bearer credentials and rejects refresh replay" do
    {_user, input} = provision()
    assert {:ok, first} = authenticate(input)
    assert {:ok, second} = Accounts.refresh_session(first.refresh_token)
    refute second.access_token == first.access_token
    refute second.refresh_token == first.refresh_token
    assert {:ok, old_actor} = Accounts.authenticate_session(first.access_token)
    assert old_actor == first.actor
    assert {:ok, _} = Accounts.authorize_actor(first.actor)
    assert {:error, :unauthenticated} = Accounts.refresh_session(first.refresh_token)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(first.access_token)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(first.actor)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(second.access_token)
    assert {:error, :unauthenticated} = Accounts.refresh_session(second.refresh_token)
  end

  test "a request with a captured access token survives a concurrent successful refresh" do
    {_user, input} = provision()
    assert {:ok, first} = authenticate(input)
    parent = self()

    request =
      Task.async(fn ->
        Sandbox.allow(Repo, parent, self())
        captured = first.access_token
        send(parent, :access_captured)
        receive do: (:refresh_committed -> Accounts.authenticate_session(captured))
      end)

    assert_receive :access_captured
    assert {:ok, second} = Accounts.refresh_session(first.refresh_token)
    send(request.pid, :refresh_committed)
    assert {:ok, actor} = Task.await(request)
    assert actor == first.actor
    assert {:ok, _} = Accounts.authorize_actor(actor)
    assert {:ok, _} = Accounts.authenticate_session(second.access_token)
  end

  test "revocation rejects bearer use and cannot target another user's session" do
    {_user, input} = provision()
    {_other, other_input} = provision()
    assert {:ok, own} = authenticate(input)
    assert {:ok, rotated} = Accounts.refresh_session(own.refresh_token)
    assert {:ok, other} = authenticate(other_input)
    assert {:error, :not_found} = Accounts.revoke_session(own.actor, other.actor.session_id)
    assert :ok = Accounts.revoke_session(own.actor, own.actor.session_id)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(own.access_token)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(rotated.access_token)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(own.actor)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(rotated.actor)
    assert {:error, :unauthenticated} = Accounts.refresh_session(own.refresh_token)
  end

  test "device removal revokes its sessions without granting cross-user access" do
    {_user, input} = provision()
    {_other, other_input} = provision()
    assert {:ok, own} = authenticate(input)
    assert {:ok, rotated} = Accounts.refresh_session(own.refresh_token)
    assert {:ok, other} = authenticate(other_input)
    assert {:ok, [device]} = Accounts.list_devices(own.actor)
    assert device.id == own.actor.device_id
    assert {:error, :not_found} = Accounts.remove_device(own.actor, other.actor.device_id)
    assert :ok = Accounts.remove_device(own.actor, device.id)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(own.access_token)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(rotated.access_token)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(own.actor)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(rotated.actor)
    assert {:error, :unauthenticated} = Accounts.refresh_session(own.refresh_token)
    assert {:ok, _} = Accounts.authenticate_session(other.access_token)
  end

  test "actor maps and tampered actor identities cannot authorize commands" do
    {_user, input} = provision()
    assert {:ok, session} = authenticate(input)
    assert {:error, :unauthenticated} = Accounts.list_devices(%{user_id: session.actor.user_id})
    forged = %{session.actor | user_id: Ecto.UUID.generate()}
    assert {:error, :unauthenticated} = Accounts.validate_actor(forged)
    assert {:error, :unauthenticated} = Accounts.remove_device(forged, session.actor.device_id)

    for proof <- [nil, <<0>>, :crypto.strong_rand_bytes(32)] do
      assert {:error, :unauthenticated} = Accounts.validate_actor(%{session.actor | proof: proof})
    end

    assert {:ok, different} = authenticate(input, "other-device")

    assert {:error, :unauthenticated} =
             Accounts.validate_actor(%{session.actor | proof: different.actor.proof})
  end

  test "expired sessions and revoked users are revalidated on every command" do
    {user, input} = provision()
    assert {:ok, session} = authenticate(input)

    Repo.update_all(from(t in AccessToken, where: t.digest == ^session.actor.proof),
      set: [expires_at: ~U[2000-01-01 00:00:00.000000Z]]
    )

    assert {:error, :unauthenticated} = Accounts.authenticate_session(session.access_token)
    assert {:error, :unauthenticated} = Accounts.list_devices(session.actor)
    assert {:ok, fresh} = authenticate(input, "device-2")
    assert {:ok, rotated} = Accounts.refresh_session(fresh.refresh_token)

    Repo.update_all(from(u in SecretHub.Human.Schemas.User, where: u.id == ^user.id),
      set: [disabled_at: DateTime.utc_now()]
    )

    assert {:error, :unauthenticated} = Accounts.authenticate_session(fresh.access_token)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(rotated.access_token)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(fresh.actor)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(rotated.actor)
    assert {:error, :unauthenticated} = Accounts.refresh_session(fresh.refresh_token)
  end

  test "each access token and captured actor retains its own expiry across later refreshes" do
    {_user, input} = provision()
    assert {:ok, first} = authenticate(input)
    original_expiry = Repo.get!(AccessToken, first.actor.proof).expires_at
    assert {:ok, second} = Accounts.refresh_session(first.refresh_token)
    assert {:ok, old_actor} = Accounts.authenticate_session(first.access_token)
    assert old_actor.proof == first.actor.proof
    refute old_actor.proof == second.actor.proof
    assert Repo.get!(AccessToken, first.actor.proof).expires_at == original_expiry

    Repo.update_all(from(t in AccessToken, where: t.digest == ^first.actor.proof),
      set: [expires_at: ~U[2000-01-01 00:00:00.000000Z]]
    )

    assert {:ok, third} = Accounts.refresh_session(second.refresh_token)
    assert {:error, :unauthenticated} = Accounts.authenticate_session(first.access_token)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(first.actor)
    assert {:error, :unauthenticated} = Accounts.authorize_actor(old_actor)
    assert {:ok, _} = Accounts.authenticate_session(second.access_token)
    assert {:ok, _} = Accounts.authorize_actor(second.actor)
    assert {:ok, _} = Accounts.authenticate_session(third.access_token)
    assert Repo.get!(AccessToken, first.actor.proof).expires_at == ~U[2000-01-01 00:00:00.000000Z]

    assert :ok = Accounts.cleanup_refresh_evidence()
    assert Repo.get(AccessToken, first.actor.proof) == nil
    assert Repo.get!(AccessToken, second.actor.proof)
    assert Repo.get!(AccessToken, third.actor.proof)
  end

  test "authentication attempts are bounded by identity including unknown users" do
    limiter = start_supervised!({RateLimiter, name: nil, max_attempts: 2})
    opts = [rate_limiter: limiter, server_iterations: 1000]

    assert {:error, :invalid_credentials} =
             Accounts.authenticate(
               "missing@example.test",
               Base.encode64(<<1::256>>),
               %{identifier: "a"},
               opts
             )

    assert {:error, :invalid_credentials} =
             Accounts.authenticate(
               "missing@example.test",
               Base.encode64(<<1::256>>),
               %{identifier: "a"},
               opts
             )

    assert {:error, :rate_limited} =
             Accounts.authenticate(
               "MISSING@example.test",
               Base.encode64(<<1::256>>),
               %{identifier: "a"},
               opts
             )
  end

  test "invalid input fails before persistence and does not echo credentials" do
    for override <- [
          %{email: "invalid"},
          %{password_hash: ""},
          %{encrypted_key: ""},
          %{kdf: 1},
          %{kdf_iterations: 1},
          %{name: <<0>>}
        ] do
      assert {:error, :invalid_input} =
               Accounts.provision(Map.merge(attrs(), override), server_iterations: 1000)
    end

    {_user, input} = provision()

    assert {:error, :invalid_input} =
             Accounts.authenticate(input.email, input.password_hash, %{
               identifier: String.duplicate("a", 129)
             })

    assert {:error, :unsupported_mfa} =
             Accounts.authenticate(input.email, input.password_hash, %{
               identifier: "a",
               mfa_token: "claimed"
             })

    assert {:error, :unauthenticated} = Accounts.authenticate_session(String.duplicate("a", 1000))
  end

  test "user keys must be encrypted envelopes rather than plaintext or malformed blobs" do
    for override <- [
          %{encrypted_key: "raw-master-key"},
          %{encrypted_key: "2.invalid|ciphertext|mac"},
          %{encrypted_private_key: "raw-private-key"}
        ] do
      assert {:error, :invalid_input} =
               Accounts.provision(Map.merge(attrs(), override), server_iterations: 1000)
    end
  end

  test "profile requires current authentication and prelogin avoids identity enumeration" do
    {user, input} = provision()
    assert {:ok, session} = authenticate(input)
    assert {:ok, %{id: id, encrypted_key: key}} = Accounts.profile(session.actor)
    assert id == user.id
    assert key == input.encrypted_key
    assert {:ok, %{kdf: 0, kdf_iterations: 600_000}} = Accounts.prelogin(input.email)
    assert {:ok, %{kdf: 0, kdf_iterations: 600_000}} = Accounts.prelogin("unknown@example.test")
    assert {:error, :invalid_input} = Accounts.prelogin(nil)
    assert :ok = Accounts.revoke_session(session.actor, session.actor.session_id)
    assert {:error, :unauthenticated} = Accounts.profile(session.actor)
  end

  test "refresh lifetime expires independently and duplicate identities are rejected" do
    {_user, input} = provision()
    assert {:error, :invalid_input} = Accounts.provision(input, server_iterations: 1000)
    assert {:ok, session} = authenticate(input)

    Repo.update_all(from(s in Session, where: s.id == ^session.actor.session_id),
      set: [refresh_expires_at: ~U[2000-01-01 00:00:00.000000Z]]
    )

    assert {:error, :unauthenticated} = Accounts.refresh_session(session.refresh_token)
  end

  test "valid official-client sync refresh bursts remain usable and replay still revokes" do
    {_user, input} = provision()
    {:ok, initial} = authenticate(input)

    sessions =
      Enum.reduce(1..6, [initial], fn _, [session | _] = sessions ->
        assert {:ok, refreshed} = Accounts.refresh_session(session.refresh_token)
        [refreshed | sessions]
      end)

    for session <- sessions do
      assert {:ok, _} = Accounts.authenticate_session(session.access_token)
      assert {:ok, _} = Accounts.authorize_actor(session.actor)
    end

    assert {:error, :unauthenticated} = Accounts.refresh_session(initial.refresh_token)

    for session <- sessions do
      assert {:error, :unauthenticated} = Accounts.authenticate_session(session.access_token)
      assert {:error, :unauthenticated} = Accounts.authorize_actor(session.actor)
    end
  end

  test "rate limiter fails closed when its identity-key capacity is exhausted" do
    limiter = start_supervised!({RateLimiter, name: nil, max_keys: 1})
    assert :ok = RateLimiter.check("one@example.test", limiter)
    assert {:error, :rate_limited} = RateLimiter.check("two@example.test", limiter)
  end

  test "new device registration and login outcomes produce sanitized audit evidence" do
    {user, input} = provision()
    assert {:ok, session} = authenticate(input)
    events = Repo.all(from(e in SecretHub.Human.Audit.Event, order_by: [asc: e.inserted_at]))

    assert Enum.any?(
             events,
             &(&1.event_type == "human.device.registered" and &1.actor_id == user.id)
           )

    assert Enum.any?(events, &(&1.event_type == "human.login.succeeded"))
    refute inspect(events) =~ input.password_hash
    refute inspect(events) =~ input.encrypted_key
    refute inspect(events) =~ session.access_token
  end
end

defmodule SecretHub.Human.SignupConfigurationTest do
  use SecretHub.Human.DataCase, async: false
  alias SecretHub.Human.Accounts

  test "registration requires an explicit operator-enabled signup setting" do
    previous = Application.fetch_env(:secrethub_human, :signup_enabled)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:secrethub_human, :signup_enabled, value)
        :error -> Application.delete_env(:secrethub_human, :signup_enabled)
      end
    end)

    Application.put_env(:secrethub_human, :signup_enabled, true)

    encrypted =
      "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

    assert {:ok, user} =
             Accounts.register(%{
               email: "enabled@example.test",
               password_hash: Base.encode64(<<27::256>>),
               encrypted_key: encrypted
             })

    assert user.email == "enabled@example.test"
  end
end
