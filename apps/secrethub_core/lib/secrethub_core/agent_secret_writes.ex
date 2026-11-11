defmodule SecretHub.Core.AgentSecretWrites do
  @moduledoc """
  Agent-scoped static secret publication (`secret_put`, `secret_delete`).

  A local process on an Agent host publishes a static secret at a Core path so
  that other services can consume it through their own Agents and policies.
  The principal is the Agent resolved from the trusted mTLS socket. Inside one
  transaction the Agent is revalidated, the dedicated `secret_write` or
  `secret_delete` grant is evaluated for the path, the Core decision is
  recorded, the effect is applied through `SecretHub.Core.Secrets` (versioned,
  encrypted), and checked audit evidence is committed. Failed effects abort
  the transaction and are recorded as separate error evidence afterwards.

  Results never contain secret values.
  """
  import Ecto.Query

  alias SecretHub.Core.PKI.ManagedCertificates
  alias SecretHub.Core.Vault.SealState

  alias SecretHub.Core.{
    AccessAudit,
    Audit,
    AuthorizationVersions,
    HostCredentials,
    Repo,
    RuntimeAuthorization,
    RuntimePrincipal,
    Secrets
  }

  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.Schemas.Secret
  alias SecretHub.Shared.StaticSecretWrites, as: Contract

  @chain_events %{
    "secret_write" => "secret.agent_write",
    "secret_delete" => "secret.agent_delete"
  }

  @denied ~w(permission_denied invalid_agent invalid_principal invalid_request revoked disabled
    expired incompatible_version read_only)a

  @doc """
  Executes one action for an Agent-only principal. Returns `{:ok, result}`
  with string keys (`status`, `path`, `version`, `audit_event_id`) or
  `{:error, reason}`.
  """
  def execute(principal, action, params, correlation \\ %{})

  def execute(
        %RuntimePrincipal{application_id: nil, agent_id: agent_id, agent_certificate_id: cert_id} =
          principal,
        action,
        params,
        correlation
      )
      when is_binary(agent_id) and is_binary(cert_id) do
    context = audit_context(correlation)

    case Contract.operation(action) do
      {:ok, operation} ->
        case Contract.validate(action, params) do
          {:ok, request} -> run(principal, operation, request, context)
          {:error, reason} -> rejected(principal, operation, reason, nil, context)
        end

      :error ->
        rejected(principal, "secret_write", :invalid_request, nil, context)
    end
  rescue
    _ in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :audit_unavailable}
  catch
    :exit, _ -> {:error, :audit_unavailable}
  end

  def execute(_, _, _, _), do: {:error, :invalid_principal}

  defp run(principal, operation, request, context) do
    Repo.transaction(fn ->
      AuthorizationVersions.lock_global()
      HostCredentials.lock_identity!(principal)

      decision =
        with :ok <- HostCredentials.current_principal(principal),
             :ok <- grant(principal, request["path"], operation),
             :ok <- vault_ready() do
          decide(operation, request, current(request["path"]))
        end

      decision_event = observe!(principal, operation, evidence(decision, request), context)

      case decision do
        {:ok, plan} ->
          result = perform!(principal, plan)
          access = Map.merge(evidence(decision, request), access_phase(decision_event, result))
          observe!(principal, operation, access, context)
          chain!(principal, operation, {:ok, result}, request["path"], plan[:secret])
          {:ok, Map.put(result, "audit_event_id", decision_event.event_id)}

        {:error, reason} ->
          chain!(principal, operation, {:error, reason}, request["path"], nil)
          {:error, reason}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> failed(principal, operation, reason, request["path"], context)
    end
  end

  defp grant(principal, path, operation) do
    subject = "agent:" <> principal.agent_id

    subject
    |> RuntimeAuthorization.subject_policies()
    |> RuntimeAuthorization.authorize_with_policies(subject, path, operation)
  end

  defp vault_ready do
    case SealState.get_master_key() do
      {:ok, _} -> :ok
      _ -> {:error, :sealed}
    end
  end

  defp current(path),
    do: Repo.one(from(s in Secret, where: s.secret_path == ^path, lock: "FOR UPDATE"))

  ## Decisions (no mutation)

  defp decide("secret_write", %{"expected_version" => expected}, nil) when expected != nil,
    do: {:error, :conflict}

  defp decide("secret_write", request, nil), do: {:ok, %{op: :create, request: request}}

  defp decide("secret_write", request, secret) do
    with :ok <- writable(secret),
         :ok <- expected(secret, request["expected_version"]),
         {:ok, current_data} <- decrypted(secret) do
      if current_data == request["data"],
        do: {:ok, %{op: :unchanged, secret: secret}},
        else: {:ok, %{op: :update, secret: secret, request: request}}
    end
  end

  defp decide("secret_delete", %{"expected_version" => expected}, nil) when expected != nil,
    do: {:error, :conflict}

  defp decide("secret_delete", _request, nil), do: {:ok, %{op: :absent}}

  defp decide("secret_delete", request, secret) do
    with :ok <- writable(secret),
         :ok <- expected(secret, request["expected_version"]),
         do: {:ok, %{op: :delete, secret: secret}}
  end

  # Dynamic secrets and managed certificate outputs have their own lifecycles.
  defp writable(%Secret{secret_type: :static} = secret) do
    if ManagedCertificates.owned_output?(secret.id), do: {:error, :read_only}, else: :ok
  end

  defp writable(_secret), do: {:error, :read_only}

  defp expected(_secret, nil), do: :ok
  defp expected(%Secret{version: version}, version), do: :ok
  defp expected(_secret, _expected), do: {:error, :conflict}

  defp decrypted(secret) do
    case Secrets.read_decrypted(secret.secret_path) do
      {:ok, data, _secret} -> {:ok, data}
      {:error, :sealed} -> {:error, :sealed}
      {:error, _} -> {:error, :authorization_unavailable}
    end
  end

  ## Effects

  defp perform!(principal, %{op: :create, request: request}) do
    request["path"]
    |> create_attrs(request, principal)
    |> Secrets.create_secret()
    |> ok!()
    |> result("created")
  end

  defp perform!(principal, %{op: :update, secret: secret, request: request}) do
    secret.id
    |> Secrets.update_secret(
      %{"secret_data" => request["data"], "value_format" => "structured"},
      created_by: principal.agent_public_id,
      change_description: "Published by Agent " <> principal.agent_public_id
    )
    |> ok!()
    |> result("updated")
  end

  defp perform!(_principal, %{op: :unchanged, secret: secret}), do: result(secret, "unchanged")
  defp perform!(_principal, %{op: :absent}), do: %{"status" => "absent"}

  defp perform!(_principal, %{op: :delete, secret: secret}) do
    secret.id |> Secrets.delete_secret() |> ok!()
    %{"status" => "deleted", "path" => secret.secret_path}
  end

  defp create_attrs(path, request, principal) do
    %{
      name: secret_name(path),
      secret_path: path,
      value_format: "structured",
      secret_data: request["data"],
      description: request["description"] || "Published by Agent " <> principal.agent_public_id,
      metadata: %{"published_by_agent" => principal.agent_public_id},
      created_by: principal.agent_public_id
    }
  end

  # Secret names allow letters, digits, spaces, hyphens and underscores (max 100).
  defp secret_name(path) do
    name = String.replace(path, ".", "_")

    if byte_size(name) <= 100,
      do: name,
      else:
        binary_part(name, 0, 87) <>
          "_" <>
          (:crypto.hash(:sha256, path) |> Base.encode16(case: :lower) |> binary_part(0, 12))
  end

  defp result(secret, status),
    do: %{"status" => status, "path" => secret.secret_path, "version" => secret.version}

  defp ok!({:ok, value}), do: value
  defp ok!({:error, %Ecto.Changeset{}}), do: Repo.rollback(:conflict)
  defp ok!({:error, :sealed}), do: Repo.rollback(:sealed)
  defp ok!({:error, :managed_certificate_output}), do: Repo.rollback(:read_only)
  defp ok!({:error, _}), do: Repo.rollback(:authorization_unavailable)

  ## Evidence

  defp evidence({:ok, plan}, request) do
    %{
      phase: "core_decision",
      outcome: "success",
      reason_code: "allowed",
      secret_path: Event.safe_path(request["path"]),
      secret_id: plan[:secret] && plan.secret.id,
      cache_status: "none"
    }
  end

  defp evidence({:error, reason}, request) do
    %{
      phase: "core_decision",
      outcome: outcome(reason),
      reason_code: Event.reason(reason, 2),
      secret_path: Event.safe_path(request["path"]),
      cache_status: "none"
    }
  end

  defp access_phase(decision_event, result),
    do: %{
      phase: "core_access",
      core_event_id: decision_event.event_id,
      secret_version: result["version"]
    }

  defp outcome(reason) when reason in @denied, do: "denied"
  defp outcome(_), do: "error"

  defp observe!(principal, operation, attrs, context) do
    %{
      schema_version: 2,
      request_id: context.request_id,
      attempt_id: context.attempt_id,
      agent_id: principal.agent_public_id,
      application_id: nil,
      identity_status: "unverified",
      attribution: "none",
      operation: operation,
      duration_us: max(System.monotonic_time(:microsecond) - context.started, 0)
    }
    |> Map.merge(attrs)
    |> AccessAudit.record_core()
    |> case do
      {:ok, observation} -> observation
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp chain!(principal, operation, outcome, path, secret) do
    {granted, status} =
      case outcome do
        {:ok, result} -> {true, result["status"]}
        {:error, reason} -> {false, Event.reason(reason, 2)}
      end

    attrs = %{
      event_type: Map.fetch!(@chain_events, operation),
      actor_type: "agent",
      actor_id: principal.agent_public_id,
      agent_id: principal.agent_public_id,
      access_granted: granted,
      secret_id: secret && secret.id,
      event_data: %{operation: operation, resource: Event.safe_path(path), result: status}
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      _ -> Repo.rollback(:audit_unavailable)
    end
  end

  # Invalid requests and aborted effects still leave committed evidence.
  defp rejected(principal, operation, reason, path, context) do
    Repo.transaction(fn ->
      observe!(principal, operation, evidence({:error, reason}, %{"path" => path}), context)
      chain!(principal, operation, {:error, reason}, path, nil)
      reason
    end)
    |> case do
      {:ok, reason} -> {:error, reason}
      {:error, _} -> {:error, :audit_unavailable}
    end
  end

  defp failed(_principal, _operation, :audit_unavailable, _path, _context),
    do: {:error, :audit_unavailable}

  defp failed(principal, operation, reason, path, context),
    do: rejected(principal, operation, reason, path, context)

  defp audit_context(correlation) do
    %{
      request_id: valid_uuid(correlation[:request_id]),
      attempt_id: valid_uuid(correlation[:attempt_id]),
      started: System.monotonic_time(:microsecond)
    }
  end

  defp valid_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> uuid
      :error -> Ecto.UUID.generate()
    end
  end
end
