defmodule SecretHub.Core.AccessAudit.Request do
  @moduledoc "One deterministic projection per namespace/request, separate from phase observations."
  use Ecto.Schema

  schema "access_audit_requests" do
    field(:namespace, :string)
    field(:request_id, Ecto.UUID)
    field(:agent_id, :string)
    field(:application_id, Ecto.UUID)
    field(:identity_status, :string)
    field(:attribution, :string)
    field(:secret_id, Ecto.UUID)
    field(:secret_path, :string)
    field(:operation, :string)
    field(:started_at, :utc_datetime_usec)
    field(:last_observed_at, :utc_datetime_usec)
    field(:last_received_at, :utc_datetime_usec)
    field(:outcome, :string)
    field(:reason_code, :string)
    field(:attempts, :integer)
    field(:incomplete, :boolean)
    field(:contradictory, :boolean)
    field(:core_outcome, :string)
    field(:core_reason_code, :string)
    field(:delivery_outcome, :string)
    field(:cache_status, :string)
  end
end
