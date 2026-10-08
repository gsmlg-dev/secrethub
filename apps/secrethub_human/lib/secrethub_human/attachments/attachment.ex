defmodule SecretHub.Human.Attachments.Attachment do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_attachments" do
    field(:user_id, :binary_id)
    field(:item_id, :binary_id)
    field(:filename, :string)
    field(:encrypted_key, :string)
    field(:byte_size, :integer)
    field(:deleted_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
