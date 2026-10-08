defmodule SecretHub.Human.Audit.Event do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_audit_outbox" do
    field(:event_type, :string)
    field(:actor_id, :binary_id)
    field(:metadata, :map)
    field(:delivered_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
