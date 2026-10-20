defmodule SecretHub.Core.AccessAudit.Producer do
  @moduledoc "Received producer progress; sequence gaps are retained rather than rejected."
  use Ecto.Schema

  schema "access_audit_producers" do
    field(:namespace, :string)
    field(:producer_id, Ecto.UUID)
    field(:last_sequence, :integer)
    field(:event_count, :integer)
    field(:last_received_at, :utc_datetime_usec)
    field(:last_observed_at, :utc_datetime_usec)
  end
end
