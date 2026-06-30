defmodule SecretHub.Core.Auth.CliAccess do
  @moduledoc """
  Browser-approved CLI login flow.

  The CLI creates a pending request and shows the short user code to the
  operator. An admin approves the request with an AppRole, and the CLI polling
  request receives a normal AppRole token once.
  """

  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Shared.Schemas.{CliAccessRequest, Role}

  @ttl_seconds 10 * 60
  @poll_interval_seconds 2
  @max_code_attempts 5
  @visible_statuses [:pending, :approved, :revoked]

  @doc """
  Returns the client polling interval in seconds.
  """
  @spec poll_interval_seconds() :: pos_integer()
  def poll_interval_seconds, do: @poll_interval_seconds

  @doc """
  Creates a pending CLI access request.
  """
  @spec create_request(map(), String.t()) :: {:ok, CliAccessRequest.t()} | {:error, term()}
  def create_request(metadata, source_ip) when is_map(metadata) do
    create_request(metadata, source_ip, @max_code_attempts)
  end

  @doc """
  Lists pending, unexpired CLI access requests for admin review.
  """
  @spec list_pending() :: [CliAccessRequest.t()]
  def list_pending do
    now = now()

    from(r in CliAccessRequest,
      where: r.status == :pending and r.expires_at > ^now,
      order_by: [asc: r.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Lists CLI access requests that should remain visible to admins.

  Pending requests disappear after expiry, while approved and revoked requests
  stay in the table so admins can audit and revoke issued CLI access.
  """
  @spec list_visible() :: [CliAccessRequest.t()]
  def list_visible do
    now = now()

    from(r in CliAccessRequest,
      where: r.status in ^@visible_statuses and (r.status != :pending or r.expires_at > ^now),
      order_by: [desc: r.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Approves a pending request and binds it to an AppRole.
  """
  @spec approve_request(String.t(), String.t(), String.t()) ::
          {:ok, CliAccessRequest.t()} | {:error, atom()}
  def approve_request(id, role_id, approved_by) do
    with {:ok, request} <- get_request(id),
         :ok <- ensure_pending(request),
         :ok <- ensure_not_expired(request),
         {:ok, role} <- get_approle(role_id) do
      request
      |> CliAccessRequest.changeset(%{
        status: :approved,
        role_id: role.role_id,
        approved_by: approved_by,
        approved_at: now()
      })
      |> Repo.update()
    end
  end

  @doc """
  Rejects a pending CLI access request.
  """
  @spec reject_request(String.t(), String.t()) :: {:ok, CliAccessRequest.t()} | {:error, atom()}
  def reject_request(id, rejected_by) do
    with {:ok, request} <- get_request(id),
         :ok <- ensure_pending(request) do
      request
      |> CliAccessRequest.changeset(%{
        status: :rejected,
        rejected_by: rejected_by,
        rejected_at: now()
      })
      |> Repo.update()
    end
  end

  @doc """
  Revokes a visible CLI access request and invalidates tokens issued from it.
  """
  @spec revoke_request(String.t(), String.t()) :: {:ok, CliAccessRequest.t()} | {:error, term()}
  def revoke_request(id, revoked_by) do
    with {:ok, request} <- get_request(id),
         :ok <- ensure_revokeable(request) do
      request
      |> CliAccessRequest.changeset(%{
        status: :revoked,
        revoked_by: revoked_by,
        revoked_at: now()
      })
      |> Repo.update()
      |> case do
        {:ok, revoked} ->
          audit_revocation(revoked, revoked_by)
          {:ok, revoked}

        error ->
          error
      end
    end
  end

  @doc """
  Polls a CLI request by request id.
  """
  @spec poll_request(String.t()) ::
          {:pending, CliAccessRequest.t()}
          | {:approved, map()}
          | {:error, atom()}
  def poll_request(request_id) do
    case Repo.get_by(CliAccessRequest, request_id: request_id) do
      nil ->
        {:error, :not_found}

      %{status: :pending} = request ->
        pending_response(request)

      %{status: :approved} = request ->
        approved_response(request)

      %{status: :rejected} ->
        {:error, :rejected}

      %{status: :consumed} ->
        {:error, :already_consumed}

      %{status: :expired} ->
        {:error, :expired}

      %{status: :revoked} ->
        {:error, :revoked}
    end
  end

  defp create_request(_metadata, _source_ip, 0), do: {:error, :user_code_collision}

  defp create_request(metadata, source_ip, attempts_left) do
    attrs = %{
      request_id: Ecto.UUID.generate(),
      user_code: generate_user_code(),
      status: :pending,
      source_ip: source_ip,
      metadata: sanitize_metadata(metadata),
      expires_at: DateTime.add(now(), @ttl_seconds, :second)
    }

    %CliAccessRequest{}
    |> CliAccessRequest.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, request} ->
        {:ok, request}

      {:error, changeset} ->
        if unique_user_code_error?(changeset) do
          create_request(metadata, source_ip, attempts_left - 1)
        else
          {:error, changeset}
        end
    end
  end

  defp pending_response(request) do
    if expired?(request) do
      expire_request(request)
      {:error, :expired}
    else
      {:pending, request}
    end
  end

  defp approved_response(%{consumed_at: consumed_at}) when not is_nil(consumed_at) do
    {:error, :already_consumed}
  end

  defp approved_response(request) do
    if expired?(request) do
      expire_request(request)
      {:error, :expired}
    else
      case Repo.transaction(fn -> approved_response_locked(request.id) end) do
        {:ok, {:approved, token_response}} -> {:approved, token_response}
        {:ok, {:error, reason}} -> {:error, reason}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp approved_response_locked(id) do
    request =
      from(r in CliAccessRequest, where: r.id == ^id, lock: "FOR UPDATE")
      |> Repo.one()

    cond do
      is_nil(request) ->
        {:error, :not_found}

      request.status == :consumed ->
        {:error, :already_consumed}

      not is_nil(request.consumed_at) ->
        {:error, :already_consumed}

      request.status == :revoked ->
        {:error, :revoked}

      expired?(request) ->
        expire_request(request)
        {:error, :expired}

      request.status != :approved ->
        {:error, request.status}

      true ->
        issue_and_consume(request)
    end
  end

  defp issue_and_consume(request) do
    with {:ok, token_response} <-
           AppRole.issue_token_for_role(request.role_id, "cli_access", %{
             cli_access_request_id: request.id
           }),
         {:ok, _request} <- consume_request(request) do
      {:approved, token_response}
    else
      {:error, "Role not found"} -> {:error, :role_not_found}
      {:error, "Role disabled"} -> {:error, :role_disabled}
      {:error, _changeset} -> Repo.rollback(:consume_failed)
    end
  end

  defp consume_request(request) do
    request
    |> CliAccessRequest.changeset(%{consumed_at: now()})
    |> Repo.update()
  end

  defp expire_request(request) do
    request
    |> CliAccessRequest.changeset(%{status: :expired})
    |> Repo.update()
  end

  defp get_request(id) do
    case Repo.get(CliAccessRequest, id) do
      nil -> {:error, :not_found}
      request -> {:ok, request}
    end
  end

  defp ensure_pending(%{status: :pending}), do: :ok
  defp ensure_pending(%{status: :approved}), do: {:error, :already_approved}
  defp ensure_pending(%{status: :consumed}), do: {:error, :already_consumed}
  defp ensure_pending(%{status: :rejected}), do: {:error, :rejected}
  defp ensure_pending(%{status: :expired}), do: {:error, :expired}
  defp ensure_pending(%{status: :revoked}), do: {:error, :revoked}

  defp ensure_revokeable(%{status: status}) when status in [:pending, :approved, :consumed],
    do: :ok

  defp ensure_revokeable(%{status: :revoked}), do: {:error, :already_revoked}
  defp ensure_revokeable(%{status: :rejected}), do: {:error, :rejected}
  defp ensure_revokeable(%{status: :expired}), do: {:error, :expired}

  defp ensure_not_expired(request) do
    if expired?(request), do: {:error, :expired}, else: :ok
  end

  defp expired?(%{expires_at: expires_at}) do
    DateTime.compare(expires_at, now()) != :gt
  end

  defp get_approle(role_id) do
    case Repo.get_by(Role, role_id: role_id, auth_type: "approle", enabled: true) do
      nil -> {:error, :role_not_found}
      role -> {:ok, role}
    end
  end

  defp generate_user_code do
    <<number::32>> = :crypto.strong_rand_bytes(4)

    number
    |> Integer.to_string(32)
    |> String.upcase()
    |> String.pad_leading(6, "0")
    |> String.slice(-6, 6)
    |> String.replace(~r/[0189]/, "A")
  end

  defp sanitize_metadata(metadata) do
    metadata
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      key = to_string(key)

      if allowed_metadata_value?(value) do
        Map.put(acc, key, value)
      else
        acc
      end
    end)
  end

  defp allowed_metadata_value?(value) when is_binary(value), do: true
  defp allowed_metadata_value?(value) when is_boolean(value), do: true
  defp allowed_metadata_value?(value) when is_integer(value), do: true
  defp allowed_metadata_value?(_value), do: false

  defp unique_user_code_error?(changeset) do
    Keyword.has_key?(changeset.errors, :user_code)
  end

  defp audit_revocation(request, revoked_by) do
    Audit.log_event(%{
      event_type: "approle_token_revoked",
      actor_type: "admin",
      actor_id: revoked_by,
      event_data: %{
        cli_access_request_id: request.id,
        role_id: request.role_id,
        user_code: request.user_code
      },
      access_granted: true,
      response_time_ms: 0
    })
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
