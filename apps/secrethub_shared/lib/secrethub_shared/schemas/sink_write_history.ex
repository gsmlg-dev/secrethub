defmodule SecretHub.Shared.Schemas.SinkWriteHistory do
  @moduledoc """
  Sink write history schema for auditing sink writes.

  Tracks each write operation to a sink, including status, content hash, and errors.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "sink_write_history" do
    field(:write_status, :string)
    field(:content_hash, :string)
    field(:bytes_written, :integer)
    field(:error_message, :string)
    field(:reload_triggered, :boolean, default: false)
    field(:reload_status, :string)

    belongs_to(:sink, SecretHub.Shared.Schemas.Sink)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc false
  def changeset(history, attrs) do
    history
    |> cast(attrs, [
      :sink_id,
      :write_status,
      :content_hash,
      :bytes_written,
      :error_message,
      :reload_triggered,
      :reload_status
    ])
    |> validate_required([:sink_id, :write_status])
    |> validate_inclusion(:write_status, ["success", "failure", "partial"])
    |> validate_number(:bytes_written, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:sink_id)
  end
end
