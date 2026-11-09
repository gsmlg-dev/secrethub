defmodule SecretHub.Core.HostCredentials.Management do
  @moduledoc """
  Operator-only lifecycle of managed reference bindings.

  These functions are reached through the Core console or the Caddy mTLS
  protected management API, never through the Agent runtime. Ordinary helper
  stores cannot create references, redirect a binding, or reactivate a
  disabled one; only these explicit operations can.
  """
  import Ecto.Query

  alias SecretHub.Core.{Audit, AuthorizationVersions, Repo}
  alias SecretHub.Shared.HostCredentials, as: Contract
  alias SecretHub.Shared.Schemas.{Agent, HostCredentialBinding, Secret}

  @doc """
  Creates an active reference from an Agent's credential identity to an
  existing static Secret, addressed by its stable ID.

  Required attributes: `namespace`, `service`, `secret_id`, `value_field`.
  Optional: `authority`, `account`, `context`, `username`, `username_field`.
  """
  def bind_reference(agent_ref, attrs, actor) when is_map(attrs) do
    attrs = Map.new(attrs, fn {key, value} -> {to_string(key), value} end)

    transaction(fn ->
      with {:ok, agent} <- agent(agent_ref),
           {:ok, identity} <- identity(attrs),
           {:ok, secret} <- source(attrs["secret_id"]),
           {:ok, fields} <- fields(attrs) do
        %HostCredentialBinding{}
        |> HostCredentialBinding.changeset(
          Map.merge(fields, %{
            owner_agent_id: agent.id,
            namespace: identity["namespace"],
            service: identity["service"],
            authority: identity["authority"],
            account: identity["account"] || "",
            context: identity["context"],
            username: identity["username"],
            source_kind: "reference",
            secret_id: secret.id,
            source_secret_id: secret.id,
            state: "active",
            revision: 1
          })
        )
        |> Repo.insert()
        |> audited("host_credential.reference_bound", actor)
      end
    end)
  end

  @doc "Reactivates a disabled reference whose original source still exists."
  def enable_reference(binding_id, actor) do
    transaction(fn ->
      with {:ok, binding} <- reference(binding_id),
           true <- binding.secret_id == binding.source_secret_id || {:error, :source_unavailable},
           {:ok, _secret} <- source(binding.source_secret_id) do
        binding
        |> HostCredentialBinding.changeset(%{state: "active", revision: binding.revision + 1})
        |> Repo.update()
        |> audited("host_credential.reference_enabled", actor)
      end
    end)
  end

  @doc "Points a reference at a new source Secret ID and activates it."
  def rebind_reference(binding_id, attrs, actor) when is_map(attrs) do
    attrs = Map.new(attrs, fn {key, value} -> {to_string(key), value} end)

    transaction(fn ->
      with {:ok, binding} <- reference(binding_id),
           {:ok, secret} <- source(attrs["secret_id"]),
           {:ok, fields} <- fields(Map.put_new(attrs, "value_field", binding.value_field)) do
        binding
        |> HostCredentialBinding.changeset(
          Map.merge(fields, %{
            secret_id: secret.id,
            source_secret_id: secret.id,
            state: "active",
            revision: binding.revision + 1
          })
        )
        |> Repo.update()
        |> audited("host_credential.reference_rebound", actor)
      end
    end)
  end

  @doc "Disables a reference without modifying its source Secret."
  def disable_reference(binding_id, actor) do
    transaction(fn ->
      with {:ok, binding} <- reference(binding_id) do
        binding
        |> HostCredentialBinding.changeset(%{state: "disabled", revision: binding.revision + 1})
        |> Repo.update()
        |> audited("host_credential.reference_disabled", actor)
      end
    end)
  end

  @doc "Lists an Agent's bindings, including disabled references, without values."
  def list_bindings(agent_ref) do
    with {:ok, agent} <- agent(agent_ref) do
      {:ok,
       Repo.all(
         from(b in HostCredentialBinding,
           where: b.owner_agent_id == ^agent.id,
           order_by: [b.namespace, b.service, b.authority, b.account, b.context]
         )
       )
       |> Enum.map(&describe/1)}
    end
  end

  @doc "Management view of one binding: metadata plus source identifiers."
  def describe(%HostCredentialBinding{} = binding) do
    binding
    |> HostCredentialBinding.metadata()
    |> Map.merge(%{
      "owner_agent_id" => binding.owner_agent_id,
      "secret_id" => binding.secret_id,
      "source_secret_id" => binding.source_secret_id,
      "username_field" => binding.username_field,
      "value_field" => binding.value_field
    })
  end

  defp transaction(fun) do
    Repo.transaction(fn ->
      AuthorizationVersions.lock_global()

      case fun.() do
        {:ok, binding} -> binding
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp agent(ref) when is_binary(ref) do
    agent =
      if Contract.uuid?(ref),
        do: Repo.get(Agent, ref) || Repo.get_by(Agent, agent_id: ref),
        else: Repo.get_by(Agent, agent_id: ref)

    if agent, do: {:ok, agent}, else: {:error, :agent_not_found}
  end

  defp agent(_), do: {:error, :agent_not_found}

  # Reuse the runtime identity rules; references never carry a value here.
  defp identity(attrs) do
    attrs
    |> Map.take(~w(namespace service authority context account username))
    |> Map.put("value", "")
    |> then(&Contract.validate("credential_put", &1))
  end

  defp fields(attrs) do
    value_field = attrs["value_field"]
    username_field = attrs["username_field"]

    if field?(value_field) and (is_nil(username_field) or field?(username_field)),
      do: {:ok, %{value_field: value_field, username_field: username_field}},
      else: {:error, :invalid_field_selector}
  end

  defp field?(value), do: is_binary(value) and byte_size(value) in 1..128

  # Agent-owned payloads are not shareable sources; share a normal Secret instead.
  defp source(id) do
    with true <- Contract.uuid?(id),
         %Secret{secret_type: :static} = secret <- Repo.get(Secret, id),
         false <- Contract.reserved_path?(secret.secret_path) do
      {:ok, secret}
    else
      _ -> {:error, :source_unavailable}
    end
  end

  defp reference(id) do
    with true <- Contract.uuid?(id),
         %HostCredentialBinding{source_kind: "reference"} = binding <-
           Repo.one(from(b in HostCredentialBinding, where: b.id == ^id, lock: "FOR UPDATE")) do
      {:ok, binding}
    else
      _ -> {:error, :binding_not_found}
    end
  end

  defp audited({:ok, binding}, event_type, actor) do
    case Audit.log_event(%{
           event_type: event_type,
           actor_type: "admin",
           actor_id: actor_id(actor),
           access_granted: true,
           secret_id: binding.source_secret_id,
           event_data: %{
             binding_id: binding.id,
             owner_agent_id: binding.owner_agent_id,
             namespace: binding.namespace,
             state: binding.state,
             revision: binding.revision
           }
         }) do
      {:ok, _} -> {:ok, binding}
      _ -> {:error, :audit_unavailable}
    end
  end

  defp audited({:error, %Ecto.Changeset{}}, _event_type, _actor), do: {:error, :conflict}
  defp audited({:error, reason}, _event_type, _actor), do: {:error, reason}

  defp actor_id(actor) when is_binary(actor) and byte_size(actor) in 1..128, do: actor
  defp actor_id(_), do: "operator"
end
