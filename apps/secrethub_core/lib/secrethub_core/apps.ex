defmodule SecretHub.Core.Apps do
  @moduledoc """
  Applications management module.

  Handles registration, authentication, and lifecycle management of applications
  that connect to SecretHub Agents for secret retrieval.

  Applications authenticate via:
  1. One-time bootstrap token to obtain certificate
  2. mTLS with app certificate for ongoing access
  """

  import Ecto.Query
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Application, AppBootstrapToken, AppCertificate}
  require Logger

  @bootstrap_token_ttl 3600
  @bootstrap_token_prefix "hvs"

  ## Application CRUD

  @doc """
  Register a new application.

  Returns the application and a one-time bootstrap token.

  ## Parameters
    - attrs: Map with required keys: name, agent_id, and optional: description, policies, metadata

  ## Examples

      iex> register_app(%{
        name: "payment-service",
        agent_id: "agent-uuid",
        policies: ["prod-payment-db-read"]
      })
      {:ok, %{app: %Application{}, token: "hvs.CAESIJ..."}}
  """
  def register_app(attrs) do
    Repo.transaction(fn ->
      # Create application
      app_changeset =
        %Application{}
        |> Application.changeset(attrs)

      case Repo.insert(app_changeset) do
        {:ok, app} ->
          # Generate bootstrap token
          {:ok, token, token_record} = generate_bootstrap_token(app.id)

          Logger.info("Application registered",
            app_id: app.id,
            app_name: app.name,
            agent_id: app.agent_id
          )

          %{app: app, token: token, token_expires_at: token_record.expires_at}

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Get application by ID.
  """
  def get_app(id) do
    case Repo.get(Application, id) do
      nil -> {:error, :not_found}
      app -> {:ok, app}
    end
  end

  @doc """
  Get application by name.
  """
  def get_app_by_name(name) do
    case Repo.get_by(Application, name: name) do
      nil -> {:error, :not_found}
      app -> {:ok, app}
    end
  end

  @doc """
  List all applications with optional filtering.

  ## Options
    - agent_id: Filter by agent ID
    - status: Filter by status (:active, :suspended, :revoked)
    - limit: Maximum number of results
    - offset: Pagination offset
  """
  def list_apps(opts \\ []) do
    query =
      from(a in Application,
        order_by: [desc: a.created_at]
      )

    query =
      if agent_id = opts[:agent_id] do
        from(a in query, where: a.agent_id == ^agent_id)
      else
        query
      end

    query =
      if status = opts[:status] do
        from(a in query, where: a.status == ^to_string(status))
      else
        query
      end

    query =
      if limit = opts[:limit] do
        from(a in query, limit: ^limit)
      else
        query
      end

    query =
      if offset = opts[:offset] do
        from(a in query, offset: ^offset)
      else
        query
      end

    apps = Repo.all(query)
    {:ok, apps}
  end

  @doc """
  Update application metadata or policies.
  """
  def update_app(id, attrs) do
    case get_app(id) do
      {:ok, app} ->
        changeset = Application.changeset(app, attrs)

        case Repo.update(changeset) do
          {:ok, updated_app} ->
            Logger.info("Application updated",
              app_id: updated_app.id,
              app_name: updated_app.name
            )

            {:ok, updated_app}

          {:error, changeset} ->
            {:error, changeset}
        end

      error ->
        error
    end
  end

  @doc """
  Suspend an application (prevent new connections).
  """
  def suspend_app(id) do
    update_app(id, %{status: "suspended"})
  end

  @doc """
  Reactivate a suspended application.
  """
  def activate_app(id) do
    update_app(id, %{status: "active"})
  end

  @doc """
  Delete an application and revoke all its certificates.
  """
  def delete_app(id) do
    Repo.transaction(fn ->
      case get_app(id) do
        {:ok, app} ->
          # Revoke all app certificates
          revoke_all_app_certificates(id)

          # Delete app (cascade deletes tokens and cert associations)
          case Repo.delete(app) do
            {:ok, deleted_app} ->
              Logger.info("Application deleted",
                app_id: deleted_app.id,
                app_name: deleted_app.name
              )

              deleted_app

            {:error, changeset} ->
              Repo.rollback(changeset)
          end

        {:error, :not_found} ->
          Repo.rollback(:not_found)
      end
    end)
  end

  ## Bootstrap Token Management

  @doc """
  Generate a one-time bootstrap token for certificate issuance.

  Returns: {:ok, token_string, token_record}
  """
  def generate_bootstrap_token(app_id) do
    # Generate secure random token
    token_data = :crypto.strong_rand_bytes(32)
    token_string = "#{@bootstrap_token_prefix}.#{Base.url_encode64(token_data, padding: false)}"

    # Hash token for storage
    token_hash = hash_token(token_string)

    # Create token record
    expires_at = DateTime.add(DateTime.utc_now(), @bootstrap_token_ttl, :second)

    token_attrs = %{
      app_id: app_id,
      token_hash: token_hash,
      expires_at: expires_at,
      used: false
    }

    changeset = AppBootstrapToken.changeset(%AppBootstrapToken{}, token_attrs)

    case Repo.insert(changeset) do
      {:ok, token_record} ->
        Logger.info("Bootstrap token generated",
          app_id: app_id,
          expires_at: expires_at
        )

        {:ok, token_string, token_record}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Validate a bootstrap token and mark it as used.

  Returns: {:ok, app_id} or {:error, reason}
  """
  def validate_bootstrap_token(token_string) do
    token_hash = hash_token(token_string)

    Repo.transaction(fn ->
      query =
        from(t in AppBootstrapToken,
          where: t.token_hash == ^token_hash,
          where: t.used == false,
          where: t.expires_at > ^DateTime.utc_now(),
          lock: "FOR UPDATE"
        )

      case Repo.one(query) do
        nil ->
          Logger.warning("Invalid or expired bootstrap token")
          Repo.rollback(:invalid_token)

        token ->
          # Mark token as used
          changeset =
            AppBootstrapToken.changeset(token, %{used: true, used_at: DateTime.utc_now()})

          case Repo.update(changeset) do
            {:ok, updated_token} ->
              Logger.info("Bootstrap token validated and consumed",
                app_id: updated_token.app_id
              )

              updated_token.app_id

            {:error, changeset} ->
              Repo.rollback(changeset)
          end
      end
    end)
  end

  @doc """
  Cleanup expired bootstrap tokens (older than 24 hours).
  """
  def cleanup_expired_tokens do
    cutoff = DateTime.add(DateTime.utc_now(), -86400, :second)

    query =
      from(t in AppBootstrapToken,
        where: t.expires_at < ^cutoff
      )

    {count, _} = Repo.delete_all(query)

    if count > 0 do
      Logger.info("Cleaned up expired bootstrap tokens", count: count)
    end

    {:ok, count}
  end

  ## Certificate Association

  @doc """
  Associate a certificate with an application.

  Called after certificate issuance to track app certificates.
  """
  def associate_certificate(app_id, certificate_id, expires_at) do
    attrs = %{
      app_id: app_id,
      certificate_id: certificate_id,
      issued_at: DateTime.utc_now(),
      expires_at: expires_at
    }

    changeset = AppCertificate.changeset(%AppCertificate{}, attrs)

    case Repo.insert(changeset) do
      {:ok, app_cert} ->
        Logger.info("Certificate associated with application",
          app_id: app_id,
          certificate_id: certificate_id
        )

        {:ok, app_cert}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Get all certificates for an application.
  """
  def list_app_certificates(app_id) do
    query =
      from(ac in AppCertificate,
        where: ac.app_id == ^app_id,
        where: is_nil(ac.revoked_at),
        order_by: [desc: ac.issued_at],
        preload: [:certificate]
      )

    certs = Repo.all(query)
    {:ok, certs}
  end

  @doc """
  Revoke an application certificate.
  """
  def revoke_app_certificate(app_id, certificate_id, reason \\ "unspecified") do
    query =
      from(ac in AppCertificate,
        where: ac.app_id == ^app_id,
        where: ac.certificate_id == ^certificate_id,
        where: is_nil(ac.revoked_at)
      )

    case Repo.one(query) do
      nil ->
        {:error, :not_found}

      app_cert ->
        changeset =
          AppCertificate.changeset(app_cert, %{
            revoked_at: DateTime.utc_now(),
            revocation_reason: reason
          })

        case Repo.update(changeset) do
          {:ok, updated_cert} ->
            Logger.info("Application certificate revoked",
              app_id: app_id,
              certificate_id: certificate_id,
              reason: reason
            )

            {:ok, updated_cert}

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Revoke all certificates for an application.
  """
  def revoke_all_app_certificates(app_id, reason \\ "app_deleted") do
    query =
      from(ac in AppCertificate,
        where: ac.app_id == ^app_id,
        where: is_nil(ac.revoked_at)
      )

    certs = Repo.all(query)

    Enum.each(certs, fn cert ->
      revoke_app_certificate(app_id, cert.certificate_id, reason)
    end)

    {:ok, length(certs)}
  end

  ## Statistics

  @doc """
  Get application statistics.

  Returns counts by status and other metrics.
  """
  def get_stats do
    total_query = from(a in Application, select: count(a.id))
    active_query = from(a in Application, where: a.status == "active", select: count(a.id))
    suspended_query = from(a in Application, where: a.status == "suspended", select: count(a.id))

    total = Repo.one(total_query)
    active = Repo.one(active_query)
    suspended = Repo.one(suspended_query)

    {:ok,
     %{
       total: total,
       active: active,
       suspended: suspended,
       revoked: total - active - suspended
     }}
  end

  ## Private Helpers

  defp hash_token(token) do
    :crypto.hash(:sha256, token)
    |> Base.encode16(case: :lower)
  end
end
