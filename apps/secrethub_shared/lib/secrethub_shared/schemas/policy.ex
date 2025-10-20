defmodule SecretHub.Shared.Schemas.Policy do
  @moduledoc """
  Schema for access control policies.

  Policies define who can access which secrets and under what conditions.
  They support wildcard matching for secret paths (e.g., "prod.db.*.password").

  Entity bindings specify which agents or applications this policy applies to,
  identified by their certificate fingerprints or IDs.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "policies" do
    field :name, :string
    field :description, :string

    # Policy document contains the full policy definition
    # Format:
    # %{
    #   "version" => "1.0",
    #   "allowed_secrets" => ["prod.db.postgres.*", "prod.api.payment.key"],
    #   "allowed_operations" => ["read", "renew"],
    #   "conditions" => %{
    #     "time_of_day" => "00:00-23:59",
    #     "max_ttl" => "1h",
    #     "ip_ranges" => ["10.0.0.0/8"]
    #   }
    # }
    field :policy_document, :map

    # Entity bindings: list of agent_id, app_id, or certificate fingerprints
    # that this policy applies to
    field :entity_bindings, {:array, :string}, default: []

    # Quick access fields for common conditions
    field :max_ttl_seconds, :integer
    field :deny_policy, :boolean, default: false

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating a policy.
  """
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :name,
      :description,
      :policy_document,
      :entity_bindings,
      :max_ttl_seconds,
      :deny_policy
    ])
    |> validate_required([:name, :policy_document])
    |> validate_policy_document()
    |> unique_constraint(:name)
  end

  defp validate_policy_document(changeset) do
    case get_field(changeset, :policy_document) do
      nil ->
        add_error(changeset, :policy_document, "cannot be nil")

      doc when is_map(doc) ->
        cond do
          not Map.has_key?(doc, "version") ->
            add_error(changeset, :policy_document, "must include 'version' field")

          not Map.has_key?(doc, "allowed_secrets") ->
            add_error(changeset, :policy_document, "must include 'allowed_secrets' field")

          true ->
            changeset
        end

      _ ->
        add_error(changeset, :policy_document, "must be a map")
    end
  end
end
