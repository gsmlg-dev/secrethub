defmodule SecretHub.Shared.Schemas.HostCredentialBinding do
  @moduledoc """
  Agent-owned host credential entry. Holds lookup metadata, its source Secret
  association and field selectors, never the credential value itself.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias SecretHub.Shared.HostCredentials

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "host_credential_bindings" do
    field(:owner_agent_id, :binary_id)
    field(:namespace, :string)
    field(:service, :string)
    field(:authority, :string, default: "")
    field(:account, :string, default: "")
    field(:context, :string, default: "")
    field(:username, :string)
    field(:source_kind, :string)
    field(:secret_id, :binary_id)
    field(:source_secret_id, :binary_id)
    field(:username_field, :string)
    field(:value_field, :string)
    field(:state, :string, default: "active")
    field(:revision, :integer, default: 1)
    timestamps(type: :utc_datetime_usec)
  end

  @fields ~w(id owner_agent_id namespace service authority account context username source_kind
    secret_id source_secret_id username_field value_field state revision)a

  def changeset(binding, attrs) do
    binding
    |> cast(attrs, @fields)
    |> validate_required(~w(owner_agent_id namespace service source_kind source_secret_id
      value_field state revision)a)
    |> validate_inclusion(:namespace, HostCredentials.namespaces())
    |> validate_inclusion(:source_kind, ~w(owned reference))
    |> validate_inclusion(:state, ~w(active disabled))
    |> validate_number(:revision, greater_than: 0)
    |> validate_length(:username_field, max: 128)
    |> validate_length(:value_field, min: 1, max: 128)
    |> unique_constraint([:owner_agent_id, :namespace, :service, :authority, :account, :context],
      name: :host_credential_bindings_identity
    )
    |> check_constraint(:state, name: :host_credential_owned_active)
  end

  @doc "Metadata safe to return to the owning Agent: no values or secret fields."
  def metadata(%__MODULE__{} = binding) do
    %{
      "entry_id" => binding.id,
      "namespace" => binding.namespace,
      "service" => binding.service,
      "authority" => binding.authority,
      "account" => binding.account,
      "context" => binding.context,
      "username" => binding.username,
      "source_kind" => binding.source_kind,
      "state" => binding.state,
      "revision" => binding.revision
    }
  end
end
