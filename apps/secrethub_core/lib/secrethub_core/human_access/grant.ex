defmodule SecretHub.Core.HumanAccess.Grant do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "core_human_grants" do
    field(:subject_id, :binary_id)
    field(:organization_id, :binary_id)
    field(:mount_id, :string)
    field(:role_id, :string)
    field(:allowed_operations, {:array, :string}, default: [])
    field(:max_ttl, :integer)
    field(:require_approval, :boolean, default: false)
    field(:require_device, :boolean, default: true)
    field(:require_mfa, :boolean, default: false)
    field(:approver_subject_ids, {:array, :binary_id}, default: [])
    field(:enabled, :boolean, default: true)
    field(:revision, :integer, default: 1)
    timestamps(type: :utc_datetime_usec)
  end
end
