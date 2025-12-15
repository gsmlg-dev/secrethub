defmodule SecretHub.Shared.Schemas.Template do
  @moduledoc """
  Template schema for storing template definitions.

  Templates define how secrets are rendered into configuration files.
  They use EEx syntax with variable bindings to secret paths.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "templates" do
    field(:name, :string)
    field(:description, :string)
    field(:template_content, :string)
    field(:variable_bindings, :map, default: %{})
    field(:status, :string, default: "active")
    field(:created_by, :string)
    field(:version, :integer, default: 1)

    belongs_to(:agent, SecretHub.Shared.Schemas.Agent)
    has_many(:sinks, SecretHub.Shared.Schemas.Sink)

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(template, attrs) do
    template
    |> cast(attrs, [
      :name,
      :description,
      :template_content,
      :variable_bindings,
      :status,
      :agent_id,
      :created_by,
      :version
    ])
    |> validate_required([:name, :template_content, :variable_bindings])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:template_content, min: 1)
    |> validate_inclusion(:status, ["active", "inactive", "archived"])
    |> validate_variable_bindings()
    |> unique_constraint(:name)
  end

  defp validate_variable_bindings(changeset) do
    case get_change(changeset, :variable_bindings) do
      nil ->
        changeset

      bindings when is_map(bindings) ->
        validate_bindings_map(changeset, bindings)

      _ ->
        add_error(changeset, :variable_bindings, "must be a map")
    end
  end

  defp validate_bindings_map(changeset, bindings) do
    if Enum.all?(bindings, fn {k, v} -> is_binary(k) and is_binary(v) end) do
      changeset
    else
      add_error(
        changeset,
        :variable_bindings,
        "must be a map of string keys to string values"
      )
    end
  end
end
