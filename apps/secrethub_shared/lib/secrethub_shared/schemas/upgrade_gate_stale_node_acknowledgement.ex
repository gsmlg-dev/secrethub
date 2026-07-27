defmodule SecretHub.Shared.Schemas.UpgradeGateStaleNodeAcknowledgement do
  @moduledoc """
  An operator acknowledgement of one exact stale Core-node snapshot.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias SecretHub.Shared.Schemas.UpgradeGate

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @node_statuses ~w(starting initializing sealed unsealed shutdown)
  @sha256_hex ~r/\A[0-9a-f]{64}\z/

  schema "upgrade_gate_stale_node_acknowledgements" do
    belongs_to(:upgrade_gate, UpgradeGate)
    field(:verification_generation, :integer)
    field(:node_id, :string)
    field(:incarnation_id, Ecto.UUID)
    field(:observed_last_seen_at, :utc_datetime)
    field(:observed_status, :string)
    field(:observed_version, :string)
    field(:capabilities_hash, :string)
    field(:reason, :string)
    field(:acknowledged_by, :string)
    field(:acknowledged_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(acknowledgement, attrs) do
    acknowledgement
    |> cast(attrs, [
      :upgrade_gate_id,
      :verification_generation,
      :node_id,
      :incarnation_id,
      :observed_last_seen_at,
      :observed_status,
      :observed_version,
      :capabilities_hash,
      :reason,
      :acknowledged_by,
      :acknowledged_at
    ])
    |> validate_required([
      :upgrade_gate_id,
      :verification_generation,
      :node_id,
      :incarnation_id,
      :observed_last_seen_at,
      :observed_status,
      :capabilities_hash,
      :reason,
      :acknowledged_by,
      :acknowledged_at
    ])
    |> validate_inclusion(:observed_status, @node_statuses)
    |> validate_format(:capabilities_hash, @sha256_hex)
    |> validate_length(:node_id, min: 1, max: 255)
    |> validate_length(:reason, min: 1, max: 1_024)
    |> validate_length(:acknowledged_by, min: 1, max: 255)
    |> validate_number(:verification_generation, greater_than: 0)
    |> foreign_key_constraint(:upgrade_gate_id)
    |> unique_constraint(
      [
        :upgrade_gate_id,
        :verification_generation,
        :node_id,
        :incarnation_id,
        :observed_last_seen_at
      ],
      name: :upgrade_gate_ack_snapshot_unique
    )
  end
end
