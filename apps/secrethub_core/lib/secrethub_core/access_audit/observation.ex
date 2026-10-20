defmodule SecretHub.Core.AccessAudit.Observation do
  @moduledoc "Immutable received access observation and its checked audit-chain reference."
  use Ecto.Schema

  schema "access_audit_events" do
    field(:namespace, :string)
    field(:event_id, Ecto.UUID)
    field(:producer_id, Ecto.UUID)
    field(:producer_sequence, :integer)
    field(:request_id, Ecto.UUID)
    field(:envelope, :map)
    field(:canonical, :string)
    field(:observed_at, :utc_datetime_usec)
    field(:received_at, :utc_datetime_usec)
    field(:audit_log_id, :integer)
    field(:audit_log_timestamp, :utc_datetime)
  end
end
