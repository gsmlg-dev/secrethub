defmodule SecretHub.Core.HumanAccess.Approval do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "core_human_approvals" do
    field(:grant_id, :binary_id)
    field(:grant_revision, :integer)
    field(:subject_id, :binary_id)
    field(:session_id, :binary_id)
    field(:device_id, :binary_id)
    field(:request_id, :binary_id)
    field(:mount_id, :string)
    field(:role_id, :string)
    field(:requested_ttl, :integer)
    field(:max_ttl, :integer)
    field(:status, :string, default: "pending")
    field(:expires_at, :utc_datetime_usec)
    field(:decided_by, :binary_id)
    field(:decided_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end
end
