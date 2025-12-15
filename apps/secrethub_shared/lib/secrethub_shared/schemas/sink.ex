defmodule SecretHub.Shared.Schemas.Sink do
  @moduledoc """
  Sink schema for storing sink configurations.

  Sinks define where rendered templates are written (file path, permissions, reload triggers).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "sinks" do
    field(:name, :string)
    field(:file_path, :string)
    field(:permissions, :map, default: %{})
    field(:backup_enabled, :boolean, default: false)
    field(:reload_trigger, :map)
    field(:status, :string, default: "active")
    field(:last_write_at, :utc_datetime)
    field(:last_write_status, :string)
    field(:last_write_error, :string)

    belongs_to(:template, SecretHub.Shared.Schemas.Template)
    has_many(:write_history, SecretHub.Shared.Schemas.SinkWriteHistory)

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(sink, attrs) do
    sink
    |> cast(attrs, [
      :name,
      :template_id,
      :file_path,
      :permissions,
      :backup_enabled,
      :reload_trigger,
      :status,
      :last_write_at,
      :last_write_status,
      :last_write_error
    ])
    |> validate_required([:name, :template_id, :file_path])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:file_path, min: 1, max: 4096)
    |> validate_inclusion(:status, ["active", "inactive", "archived"])
    |> validate_permissions()
    |> validate_reload_trigger()
    |> foreign_key_constraint(:template_id)
    |> unique_constraint([:template_id, :name])
  end

  defp validate_permissions(changeset) do
    case get_change(changeset, :permissions) do
      nil ->
        changeset

      perms when is_map(perms) ->
        validate_permissions_map(changeset, perms)

      _ ->
        add_error(changeset, :permissions, "must be a map")
    end
  end

  defp validate_permissions_map(changeset, perms) do
    cond do
      Map.has_key?(perms, "mode") and not is_integer(perms["mode"]) ->
        add_error(changeset, :permissions, "mode must be an integer")

      Map.has_key?(perms, "owner") and not is_binary(perms["owner"]) ->
        add_error(changeset, :permissions, "owner must be a string")

      Map.has_key?(perms, "group") and not is_binary(perms["group"]) ->
        add_error(changeset, :permissions, "group must be a string")

      true ->
        changeset
    end
  end

  defp validate_reload_trigger(changeset) do
    case get_change(changeset, :reload_trigger) do
      nil ->
        changeset

      trigger when is_map(trigger) ->
        validate_reload_trigger_map(changeset, trigger)

      _ ->
        add_error(changeset, :reload_trigger, "must be a map")
    end
  end

  defp validate_reload_trigger_map(changeset, trigger) do
    type = Map.get(trigger, "type")

    if type && type not in ["signal", "http", "script"] do
      add_error(changeset, :reload_trigger, "type must be signal, http, or script")
    else
      changeset
    end
  end
end
