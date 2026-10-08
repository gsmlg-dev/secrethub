defmodule SecretHub.Core.HumanAccess.Lease do
  @moduledoc "Metadata and nonsecret backend revocation handle only."
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "core_human_leases" do
    field(:grant_id, :binary_id)
    field(:grant_revision, :integer)
    field(:subject_id, :binary_id)
    field(:organization_id, :binary_id)
    field(:session_id, :binary_id)
    field(:device_id, :binary_id)
    field(:request_id, :binary_id)
    field(:mount_id, :string)
    field(:role_id, :string)
    field(:username, :string)
    field(:status, :string, default: "reserved")
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:renewable, :boolean, default: true)
    timestamps(type: :utc_datetime_usec)
  end
end
