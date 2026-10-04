defmodule SecretHub.Core.Repo.Migrations.AddAgentRuntimeCapabilities do
  use Ecto.Migration

  def change do
    create table(:upgrade_gate_stale_agent_acknowledgements) do
      add(:upgrade_gate_id, references(:upgrade_gates, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:verification_generation, :integer, null: false)
      add(:agent_id, :text, null: false)
      add(:snapshot_hash, :text, null: false)
      add(:reason, :text, null: false)
      add(:acknowledged_by, :text, null: false)
    end

    create(
      unique_index(
        :upgrade_gate_stale_agent_acknowledgements,
        [:upgrade_gate_id, :verification_generation, :agent_id],
        name: :stale_agent_ack_generation_index
      )
    )

    alter table(:agents) do
      add(:runtime_capabilities, {:array, :text}, null: false, default: [])
      add(:runtime_capabilities_seen_at, :utc_datetime)
    end
  end
end
