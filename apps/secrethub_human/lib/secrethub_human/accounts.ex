defmodule SecretHub.Human.Accounts do
  @moduledoc "Independent Human identity, device and revocable session boundary."
  import Ecto.Query
  alias Ecto.Changeset
  alias SecretHub.Human.Accounts.Actor
  alias SecretHub.Human.Audit
  alias SecretHub.Human.Password
  alias SecretHub.Human.RateLimiter
  alias SecretHub.Human.Repo
  alias SecretHub.Human.Schemas.AccessToken
  alias SecretHub.Human.Schemas.Device
  alias SecretHub.Human.Schemas.Identity
  alias SecretHub.Human.Schemas.Session
  alias SecretHub.Human.Schemas.UsedRefresh
  alias SecretHub.Human.Schemas.User
  alias SecretHub.Human.Vault.Envelope

  @access_seconds 900
  @refresh_seconds 2_592_000

  def provision(attrs, opts \\ []) do
    with {:ok, params, verifier} <- registration_input(attrs),
         {:ok, encoded} <-
           Password.hash(verifier, iterations: Keyword.get(opts, :server_iterations, 210_000)) do
      Repo.transaction(fn ->
        user =
          %User{} |> Changeset.change(params) |> Changeset.unique_constraint(:email) |> insert!()

        %Identity{}
        |> Changeset.change(
          user_id: user.id,
          password_digest: encoded.digest,
          password_salt: encoded.salt,
          password_iterations: encoded.iterations
        )
        |> insert!()

        audit!(Keyword.get(opts, :audit_event, "human.user.provisioned"), nil, %{user_id: user.id})

        user
      end)
    else
      {:error, _} -> {:error, :invalid_input}
    end
  end

  def register(attrs) do
    if Application.get_env(:secrethub_human, :signup_enabled, false),
      do: provision(attrs, audit_event: "human.user.registered"),
      else: {:error, :signup_disabled}
  end

  def authenticate(email, password_hash, device_attrs, opts \\ []) do
    with {:ok, email} <- normalize_email(email),
         true <- Password.valid?(password_hash),
         {:ok, device} <- device_input(device_attrs),
         :ok <- RateLimiter.check(email, Keyword.get(opts, :rate_limiter, RateLimiter)) do
      identity =
        Repo.one(
          from(i in Identity,
            join: u in User,
            on: u.id == i.user_id,
            where: u.email == ^email,
            select: {u, i}
          )
        )

      verify_login(identity, email, password_hash, device, opts)
    else
      false -> {:error, :invalid_input}
      {:error, reason} -> {:error, reason}
    end
  end

  def authenticate_session(raw_token) do
    with {:ok, digest} <- token_digest(raw_token),
         {session, proof} <-
           Repo.one(
             from([s, _d, _u, a] in active_sessions(:access),
               where: a.digest == ^digest,
               select: {s, a.digest}
             )
           ) do
      {:ok, actor(session, proof)}
    else
      _ -> {:error, :unauthenticated}
    end
  end

  def authorize_actor(%Actor{proof: proof} = actor)
      when is_binary(proof) and byte_size(proof) == 32 do
    if valid_actor_identity?(actor) do
      case Repo.one(
             from([s, _d, u, a] in active_sessions(:access),
               where:
                 s.id == ^actor.session_id and s.user_id == ^actor.user_id and
                   s.device_id == ^actor.device_id and a.digest == ^proof,
               select: u
             )
           ) do
        nil -> {:error, :unauthenticated}
        user -> {:ok, user}
      end
    else
      {:error, :unauthenticated}
    end
  end

  def authorize_actor(_), do: {:error, :unauthenticated}

  def validate_actor(actor) do
    with {:ok, _user} <- authorize_actor(actor), do: {:ok, actor}
  end

  def refresh_session(raw_refresh) do
    with {:ok, digest} <- token_digest(raw_refresh) do
      digest |> refresh_transaction() |> refresh_result()
    end
  end

  defp refresh_transaction(digest), do: Repo.transaction(fn -> refresh_digest(digest) end)
  defp refresh_result({:ok, :invalid_refresh}), do: {:error, :unauthenticated}
  defp refresh_result(other), do: other

  defp refresh_digest(digest) do
    case Repo.one(
           from([s, _d, u] in active_sessions(:refresh),
             where: s.refresh_digest == ^digest,
             select: {s, u},
             lock: fragment("FOR UPDATE OF ?", s)
           )
         ) do
      nil ->
        # Commit family revocation on replay; rolling back would retain the attacker's token.
        revoke_replayed_refresh(digest)
        :invalid_refresh

      {session, user} ->
        rotate_refresh(session, user, digest)
    end
  end

  defp revoke_replayed_refresh(digest) do
    case Repo.get(UsedRefresh, digest) do
      %UsedRefresh{session_id: id, expires_at: expiry} ->
        if DateTime.compare(expiry, DateTime.utc_now()) == :gt, do: revoke_refresh_family(id)

      _ ->
        :ok
    end
  end

  defp revoke_refresh_family(id) do
    session = Repo.one(from(s in Session, where: s.id == ^id, lock: "FOR UPDATE"))

    if session && is_nil(session.revoked_at) do
      update!(Changeset.change(session, revoked_at: DateTime.utc_now()))
      audit!("human.session.revoked", actor(session), %{session_id: id, reason: "revoked"})
    end
  end

  defp rotate_refresh(session, user, digest) do
    case RateLimiter.check("refresh:" <> session.id, SecretHub.Human.RefreshRateLimiter) do
      :ok -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end

    Repo.insert!(%UsedRefresh{
      digest: digest,
      session_id: session.id,
      expires_at: session.refresh_expires_at
    })

    {params, access, refresh} = token_params()
    updated = session |> Changeset.change(params) |> update!()
    retain_access!(updated)
    audit!("human.session.refreshed", actor(updated), %{session_id: session.id})
    result(updated, user, access, refresh)
  end

  def cleanup_refresh_evidence do
    now = DateTime.utc_now()
    Repo.delete_all(from(t in UsedRefresh, where: t.expires_at <= ^now))
    Repo.delete_all(from(t in AccessToken, where: t.expires_at <= ^now))
    :ok
  end

  def record_user_key_id(actor, id) when is_binary(id) do
    if Regex.match?(~r/\A[0-9a-f]{32}\z/, id) do
      command(actor, fn -> record_user_key_id!(actor, id) end)
    else
      {:error, :invalid_input}
    end
  end

  def record_user_key_id(_, _), do: {:error, :invalid_input}

  def revoke_session(actor, session_id) do
    command(actor, fn ->
      session = owned!(Session, actor.user_id, session_id)
      session |> Changeset.change(revoked_at: DateTime.utc_now()) |> update!()
      audit!("human.session.revoked", actor, %{session_id: session.id})
      :ok
    end)
  end

  def list_devices(actor) do
    with {:ok, user} <- authorize_actor(actor) do
      {:ok,
       Repo.all(
         from(d in Device,
           where: d.user_id == ^user.id and is_nil(d.removed_at),
           order_by: [asc: d.inserted_at]
         )
       )}
    end
  end

  def remove_device(actor, device_id) do
    command(actor, fn ->
      device = owned!(Device, actor.user_id, device_id)
      now = DateTime.utc_now()
      device |> Changeset.change(removed_at: now) |> update!()

      Repo.update_all(
        from(s in Session,
          where:
            s.user_id == ^actor.user_id and s.device_id == ^device.id and is_nil(s.revoked_at)
        ),
        set: [revoked_at: now]
      )

      audit!("human.device.removed", actor, %{device_id: device.id})
      :ok
    end)
  end

  def profile(actor) do
    with {:ok, user} <- authorize_actor(actor), do: {:ok, user_dto(user)}
  end

  def prelogin(email) do
    with {:ok, _email} <- normalize_email(email), do: {:ok, %{kdf: 0, kdf_iterations: 600_000}}
  end

  defp command(actor, fun) do
    case Repo.transaction(fn -> authorized_command!(actor, fun) end) do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp record_user_key_id!(actor, id) do
    user = Repo.one!(from(u in User, where: u.id == ^actor.user_id, lock: "FOR UPDATE"))
    if user.user_key_id not in [nil, id], do: Repo.rollback(:conflict)
    update!(Changeset.change(user, user_key_id: id))
    audit!("human.user.key_id.updated", actor, %{user_id: user.id})
    :ok
  end

  defp authorized_command!(actor, fun) do
    case authorize_actor(actor) do
      {:ok, _} -> fun.()
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp valid_actor_identity?(actor) do
    actor.id == actor.user_id and actor.authentication_level == :password and
      Enum.all?(
        [actor.user_id, actor.session_id, actor.device_id],
        &match?({:ok, _}, Ecto.UUID.cast(&1))
      )
  end

  defp verify_login(identity, email, password_hash, device, opts) do
    stored =
      case identity do
        {_user, identity} ->
          %{
            salt: identity.password_salt,
            digest: identity.password_digest,
            iterations: identity.password_iterations
          }

        nil ->
          nil
      end

    if Password.verify(password_hash, stored,
         iterations: Keyword.get(opts, :server_iterations, 210_000)
       ),
       do: authenticated_login(identity, email, device),
       else: failed_login(email)
  end

  defp authenticated_login(
         {%User{disabled_at: nil} = user, %Identity{mfa_enabled: false}},
         _email,
         device
       ),
       do: login(user, device)

  defp authenticated_login({_user, %Identity{mfa_enabled: true}}, _email, _device),
    do: {:error, :unsupported_mfa}

  defp authenticated_login(_, email, _device), do: failed_login(email)

  defp login(user, params) do
    Repo.transaction(fn ->
      {device, registered?} =
        case Repo.one(
               from(d in Device,
                 where: d.user_id == ^user.id and d.identifier == ^params.identifier,
                 lock: "FOR UPDATE"
               )
             ) do
          nil ->
            device =
              %Device{}
              |> Changeset.change(Map.put(params, :user_id, user.id))
              |> Changeset.unique_constraint([:user_id, :identifier])
              |> insert!()

            {device, true}

          device ->
            {device |> Changeset.change(Map.put(params, :removed_at, nil)) |> update!(),
             not is_nil(device.removed_at)}
        end

      {tokens, access, refresh} = token_params()

      session =
        %Session{}
        |> Changeset.change(Map.merge(tokens, %{user_id: user.id, device_id: device.id}))
        |> insert!()

      retain_access!(session)

      if registered? do
        audit!("human.device.registered", actor(session), %{device_id: device.id})
      end

      audit!("human.login.succeeded", actor(session), %{
        device_id: device.id,
        session_id: session.id
      })

      result(session, user, access, refresh)
    end)
  end

  defp failed_login(email) do
    case Audit.record("human.login.failed", nil, %{
           email_digest: Base.encode16(:crypto.hash(:sha256, email), case: :lower),
           reason: "invalid_credentials"
         }) do
      :ok -> {:error, :invalid_credentials}
      {:ok, _} -> {:error, :invalid_credentials}
      {:error, reason} -> {:error, reason}
    end
  end

  defp active_sessions(kind) do
    now = DateTime.utc_now()

    query =
      from(s in Session,
        join: d in Device,
        on: d.id == s.device_id and d.user_id == s.user_id,
        join: u in User,
        on: u.id == s.user_id,
        where: is_nil(s.revoked_at) and is_nil(d.removed_at) and is_nil(u.disabled_at)
      )

    case kind do
      :access ->
        from([s] in query,
          join: a in AccessToken,
          on: a.session_id == s.id,
          where: a.expires_at > ^now
        )

      :refresh ->
        from([s] in query, where: s.refresh_expires_at > ^now)
    end
  end

  defp token_params do
    access = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    refresh = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    now = DateTime.utc_now()

    {%{
       access_digest: :crypto.hash(:sha256, access),
       refresh_digest: :crypto.hash(:sha256, refresh),
       expires_at:
         DateTime.add(now, Application.get_env(:secrethub_human, :session_ttl, @access_seconds)),
       refresh_expires_at: DateTime.add(now, @refresh_seconds)
     }, access, refresh}
  end

  defp token_digest(token) when is_binary(token) and byte_size(token) == 43 do
    case Base.url_decode64(token, padding: false) do
      {:ok, value} when byte_size(value) == 32 -> {:ok, :crypto.hash(:sha256, token)}
      _ -> {:error, :unauthenticated}
    end
  end

  defp token_digest(_), do: {:error, :unauthenticated}

  defp retain_access!(session) do
    %AccessToken{}
    |> Changeset.change(
      digest: session.access_digest,
      session_id: session.id,
      expires_at: session.expires_at
    )
    |> insert!()
  end

  defp actor(session), do: actor(session, session.access_digest)

  defp actor(session, proof),
    do: %Actor{
      id: session.user_id,
      user_id: session.user_id,
      session_id: session.id,
      device_id: session.device_id,
      proof: proof
    }

  defp result(session, user, access, refresh),
    do: %{
      actor: actor(session),
      access_token: access,
      refresh_token: refresh,
      expires_in: Application.get_env(:secrethub_human, :session_ttl, @access_seconds),
      expires_at: session.expires_at,
      user: user_dto(user)
    }

  defp user_dto(user),
    do:
      Map.take(user, [
        :id,
        :email,
        :name,
        :encrypted_key,
        :user_key_id,
        :public_key,
        :encrypted_private_key,
        :kdf,
        :kdf_iterations
      ])

  defp owned!(schema, user_id, id) do
    with {:ok, id} <- Ecto.UUID.cast(id),
         record when not is_nil(record) <-
           Repo.one(
             from(r in schema, where: r.id == ^id and r.user_id == ^user_id, lock: "FOR UPDATE")
           ) do
      record
    else
      _ -> Repo.rollback(:not_found)
    end
  end

  defp insert!(changeset) do
    case Repo.insert(changeset) do
      {:ok, value} -> value
      {:error, _} -> Repo.rollback(:invalid_input)
    end
  end

  defp update!(changeset) do
    case Repo.update(changeset) do
      {:ok, value} -> value
      {:error, _} -> Repo.rollback(:invalid_input)
    end
  end

  defp audit!(event, actor, metadata) do
    case Audit.record(event, actor, metadata) do
      :ok -> :ok
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp registration_input(attrs) when is_map(attrs) do
    with {:ok, email} <- normalize_email(value(attrs, :email)),
         true <- Password.valid?(value(attrs, :password_hash)),
         true <-
           bounded?(value(attrs, :encrypted_key), 1, 65_536) and
             Envelope.valid?(value(attrs, :encrypted_key)),
         true <- optional?(value(attrs, :name), 128),
         true <- optional?(value(attrs, :public_key), 65_536),
         true <- optional_envelope?(value(attrs, :encrypted_private_key)),
         true <- value(attrs, :kdf, 0) == 0 and value(attrs, :kdf_iterations, 600_000) == 600_000 do
      params = %{
        email: email,
        name: value(attrs, :name),
        encrypted_key: value(attrs, :encrypted_key),
        public_key: value(attrs, :public_key),
        encrypted_private_key: value(attrs, :encrypted_private_key),
        kdf: 0,
        kdf_iterations: 600_000
      }

      {:ok, params, value(attrs, :password_hash)}
    else
      _ -> {:error, :invalid_input}
    end
  end

  defp registration_input(_), do: {:error, :invalid_input}

  defp device_input(attrs) when is_map(attrs) do
    cond do
      Enum.any?(
        [:mfa_token, :two_factor_token, :two_factor_provider],
        &(value(attrs, &1) not in [nil, ""])
      ) ->
        {:error, :unsupported_mfa}

      not bounded?(value(attrs, :identifier), 1, 128) ->
        {:error, :invalid_input}

      not optional?(value(attrs, :name), 128) ->
        {:error, :invalid_input}

      not (is_integer(value(attrs, :type, 9)) and value(attrs, :type, 9) in 0..30) ->
        {:error, :invalid_input}

      true ->
        {:ok,
         %{
           identifier: value(attrs, :identifier),
           name: value(attrs, :name),
           type: value(attrs, :type, 9)
         }}
    end
  end

  defp device_input(_), do: {:error, :invalid_input}

  defp normalize_email(email) when is_binary(email) and byte_size(email) <= 254 do
    if String.valid?(email) do
      normalized = email |> String.trim() |> String.downcase()

      if bounded?(normalized, 3, 254) and
           Regex.match?(~r/\A[^\s@]+@[^\s@]+\.[^\s@]+\z/u, normalized),
         do: {:ok, normalized},
         else: {:error, :invalid_input}
    else
      {:error, :invalid_input}
    end
  end

  defp normalize_email(_), do: {:error, :invalid_input}

  defp value(attrs, key, default \\ nil),
    do: Map.get(attrs, key, Map.get(attrs, Atom.to_string(key), default))

  defp optional?(nil, _max), do: true
  defp optional?(value, max), do: bounded?(value, 0, max)
  defp optional_envelope?(nil), do: true
  defp optional_envelope?(value), do: bounded?(value, 1, 65_536) and Envelope.valid?(value)

  defp bounded?(value, min, max) when is_binary(value),
    do:
      byte_size(value) >= min and byte_size(value) <= max and String.valid?(value) and
        not String.contains?(value, <<0>>)

  defp bounded?(_, _, _), do: false
end
