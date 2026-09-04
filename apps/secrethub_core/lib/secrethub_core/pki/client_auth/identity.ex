defmodule SecretHub.Core.PKI.ClientAuth.Identity do
  @moduledoc """
  Manages client authentication identities.

  Each client identity represents a distinct authenticated machine client
  with a stable UUID embedded into the certificate CN and URI SAN.
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Core.PKI.ClientAuth.{CRLManager, Notifier}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.{Certificate, ClientAuthAuthority, ClientAuthIdentity}

  @doc """
  Creates a new client identity with a generated UUID.
  """
  @spec create_identity(map()) ::
          {:ok, ClientAuthIdentity.t()}
          | {:error, Ecto.Changeset.t() | term()}
  def create_identity(attrs, opts \\ []) when is_map(attrs) do
    id = Map.get(attrs, "id") || Map.get(attrs, :id) || Ecto.UUID.generate()
    name = Map.get(attrs, "name") || Map.get(attrs, :name)
    metadata = Map.get(attrs, "metadata") || Map.get(attrs, :metadata) || %{}
    actor = Keyword.get(opts, :actor, %{})

    changeset =
      %ClientAuthIdentity{id: id}
      |> ClientAuthIdentity.changeset(%{
        name: name,
        status: "active",
        metadata: metadata
      })

    Repo.transaction(fn ->
      with {:ok, identity} <- Repo.insert(changeset),
           :ok <- record_identity_created_audit(identity, actor) do
        identity
      else
        {:error, {:audit_failed, reason}} ->
          Repo.rollback({:audit_failed, reason})

        {:error, %Ecto.Changeset{} = cs} ->
          Repo.rollback(cs)

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  @doc """
  Lists client identities with optional filters.
  """
  @spec list_identities(keyword()) :: [ClientAuthIdentity.t()]
  def list_identities(opts \\ []) do
    status = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    search = Keyword.get(opts, :search)

    query =
      from(i in ClientAuthIdentity,
        order_by: [asc: i.name],
        limit: ^limit,
        offset: ^offset
      )

    query =
      if status,
        do: where(query, [i], i.status == ^to_string(status)),
        else: query

    query =
      if search && search != "",
        do: where(query, [i], ilike(i.name, ^"%#{search}%")),
        else: query

    Repo.all(query)
  end

  @doc """
  Fetches a single client identity by UUID.
  """
  @spec get_identity(term()) ::
          {:ok, ClientAuthIdentity.t()}
          | {:error, :identity_not_found}
  def get_identity(identity_id) do
    case cast_uuid(identity_id) do
      {:ok, uuid} ->
        case Repo.get(ClientAuthIdentity, uuid) do
          nil -> {:error, :identity_not_found}
          identity -> {:ok, identity}
        end

      :error ->
        {:error, :identity_not_found}
    end
  end

  @doc """
  Disables a client identity and revokes all of its active certificates.
  Transactionally produces a new signed CRL if any active certificates were revoked.
  """
  @spec disable_identity(term(), String.t(), keyword()) ::
          {:ok, ClientAuthIdentity.t()}
          | {:error, :identity_not_found | :vault_sealed | :vault_unavailable | term()}
  def disable_identity(identity_id, reason \\ "operator_disabled", opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))

    with {:ok, uuid} <- cast_uuid(identity_id),
         :ok <- check_unsealed_if_needed(uuid, now) do
      transact_disable_identity(uuid, reason, now, opts)
    else
      :error -> {:error, :identity_not_found}
      error -> error
    end
  end

  # Helpers

  defp transact_disable_identity(identity_id, reason, now, opts) do
    actor = Keyword.get(opts, :actor, %{})

    Repo.transaction(fn ->
      authority = lock_authority()

      case Repo.one(
             from(i in ClientAuthIdentity, where: i.id == ^identity_id, lock: "FOR UPDATE")
           ) do
        nil ->
          Repo.rollback(:identity_not_found)

        %ClientAuthIdentity{} = identity ->
          {:ok, disabled_identity} =
            identity
            |> ClientAuthIdentity.changeset(%{status: "disabled"})
            |> Repo.update()

          # Find active unrevoked certificates for this identity
          active_certs =
            Repo.all(
              from(c in Certificate,
                where: c.client_auth_identity_id == ^identity_id,
                where: c.revoked == false,
                where: c.valid_until > ^now,
                lock: "FOR UPDATE"
              )
            )

          if Enum.empty?(active_certs) do
            :ok = record_identity_disabled_audit(disabled_identity, 0, reason, actor)
            %{identity: disabled_identity, crl_updated: false}
          else
            with {:ok, ca_key} <- decrypt_ca_key(authority.ca_certificate),
                 :ok <- revoke_active_certs(active_certs, now, reason),
                 {:ok, _new_crl, updated_authority} <-
                   CRLManager.generate_crl_locked(authority, ca_key, authority.ca_certificate,
                     now: now,
                     actor: actor
                   ),
                 :ok <-
                   record_identity_disabled_audit(
                     disabled_identity,
                     length(active_certs),
                     reason,
                     actor
                   ) do
              %{
                identity: disabled_identity,
                crl_updated: true,
                generation: updated_authority.current_generation,
                crl_number: updated_authority.current_crl_number
              }
            else
              {:error, rollback_reason} ->
                Repo.rollback(rollback_reason)
            end
          end
      end
    end)
    |> case do
      {:ok, %{identity: identity, crl_updated: true, generation: gen, crl_number: crl_num}} ->
        Notifier.notify_bundle_updated(gen, crl_num, "identity_disabled")
        {:ok, identity}

      {:ok, %{identity: identity}} ->
        {:ok, identity}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp lock_authority do
    Repo.one(
      from(a in ClientAuthAuthority,
        where: a.slug == "client-auth" and a.status == "active",
        preload: [:ca_certificate, :current_crl],
        lock: "FOR UPDATE"
      )
    )
  end

  defp decrypt_ca_key(%Certificate{private_key_encrypted: encrypted_key})
       when is_binary(encrypted_key) do
    with {:ok, master_key} <- get_pki_master_key() do
      case Encryption.decrypt_from_blob(encrypted_key, master_key) do
        {:ok, key_pem} -> {:ok, X509.PrivateKey.from_pem!(key_pem)}
        {:error, _} -> {:error, :vault_unavailable}
      end
    end
  end

  defp get_pki_master_key do
    case Process.whereis(SealState) do
      nil ->
        if dev_pki_unsealed_fallback?(),
          do: {:ok, dev_fallback_key()},
          else: {:error, :vault_unavailable}

      _pid ->
        case SealState.get_master_key() do
          {:ok, key} ->
            {:ok, key}

          {:error, _} ->
            if dev_pki_unsealed_fallback?(),
              do: {:ok, dev_fallback_key()},
              else: {:error, :vault_sealed}
        end
    end
  end

  defp check_unsealed_if_needed(identity_id, now) do
    has_active_certs =
      Repo.exists?(
        from(c in Certificate,
          where: c.client_auth_identity_id == ^identity_id,
          where: c.revoked == false,
          where: c.valid_until > ^now
        )
      )

    if has_active_certs do
      case Process.whereis(SealState) do
        nil ->
          if dev_pki_unsealed_fallback?(), do: :ok, else: {:error, :vault_unavailable}

        _pid ->
          if SealState.sealed?() do
            if dev_pki_unsealed_fallback?(), do: :ok, else: {:error, :vault_sealed}
          else
            :ok
          end
      end
    else
      :ok
    end
  end

  defp dev_pki_unsealed_fallback? do
    Application.get_env(:secrethub_core, :dev_pki_unsealed_fallback, false)
  end

  defp dev_fallback_key do
    :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")
  end

  defp cast_uuid(val) do
    case Ecto.UUID.cast(val) do
      {:ok, uuid} -> {:ok, uuid}
      _ -> :error
    end
  end

  defp record_identity_created_audit(identity, actor) do
    actor_type = Map.get(actor, :actor_type) || Map.get(actor, "actor_type") || "admin"
    actor_id = Map.get(actor, :actor_id) || Map.get(actor, "actor_id") || "admin"

    source_ip =
      Map.get(actor, :source_ip) || Map.get(actor, "source_ip") || Map.get(actor, :client_ip)

    attrs = %{
      event_type: "pki.client_auth.identity_created",
      actor_type: actor_type,
      actor_id: actor_id,
      source_ip: source_ip,
      access_granted: true,
      correlation_id: identity.id,
      hash_version: 2,
      event_data: %{
        "identity_id" => identity.id,
        "name" => identity.name,
        "status" => identity.status
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback({:audit_failed, reason})
    end
  end

  defp record_identity_disabled_audit(identity, revoked_count, reason, actor) do
    actor_type = Map.get(actor, :actor_type) || Map.get(actor, "actor_type") || "admin"
    actor_id = Map.get(actor, :actor_id) || Map.get(actor, "actor_id") || "admin"

    source_ip =
      Map.get(actor, :source_ip) || Map.get(actor, "source_ip") || Map.get(actor, :client_ip)

    attrs = %{
      event_type: "pki.client_auth.identity_disabled",
      actor_type: actor_type,
      actor_id: actor_id,
      source_ip: source_ip,
      access_granted: true,
      correlation_id: identity.id,
      hash_version: 2,
      event_data: %{
        "identity_id" => identity.id,
        "name" => identity.name,
        "revoked_certificates_count" => revoked_count,
        "reason" => reason
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback({:audit_failed, reason})
    end
  end

  defp revoke_active_certs(certs, now, reason) do
    Enum.reduce_while(certs, :ok, fn cert, :ok ->
      changeset =
        Certificate.changeset(cert, %{
          revoked: true,
          revoked_at: now,
          revocation_reason: reason
        })

      case Repo.update(changeset) do
        {:ok, _} -> {:cont, :ok}
        {:error, changeset_err} -> {:halt, {:error, changeset_err}}
      end
    end)
  end
end
