defmodule SecretHub.Core.Repo.Migrations.CreateUpgradeGates do
  use Ecto.Migration

  @gate_names ~w(
    app_certificate_v2
    typed_runtime_authorization
    dynamic_secure_storage
    agent_certificate_bindings
  )
  @node_statuses ~w(starting initializing sealed unsealed shutdown)

  def up do
    create table(:upgrade_gates, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:report_format, :string, null: false)
      add(:report_hash, :string, null: false)
      add(:preflight_version, :string, null: false)
      add(:verified_at, :utc_datetime, null: false)
      add(:verified_by, :string, null: false)
      add(:verification_generation, :bigint, null: false)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:upgrade_gates, [:name]))

    create(
      constraint(:upgrade_gates, :upgrade_gates_known_name,
        check: "name IN (#{sql_values(@gate_names)})"
      )
    )

    create(
      constraint(:upgrade_gates, :upgrade_gates_report_format,
        check: "report_format = 'secrethub.upgrade-gate-report.v1'"
      )
    )

    create(
      constraint(:upgrade_gates, :upgrade_gates_report_hash,
        check: "report_hash ~ '^[0-9a-f]{64}$'"
      )
    )

    create(
      constraint(:upgrade_gates, :upgrade_gates_preflight_version,
        check: "preflight_version = '1'"
      )
    )

    create(
      constraint(:upgrade_gates, :upgrade_gates_verified_by,
        check: "length(btrim(verified_by)) > 0"
      )
    )

    create(
      constraint(:upgrade_gates, :upgrade_gates_positive_generation,
        check: "verification_generation > 0"
      )
    )

    create table(:upgrade_gate_stale_node_acknowledgements, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :upgrade_gate_id,
        references(:upgrade_gates, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:verification_generation, :bigint, null: false)
      add(:node_id, :string, null: false)
      add(:incarnation_id, :uuid, null: false)
      add(:observed_last_seen_at, :utc_datetime, null: false)
      add(:observed_status, :string, null: false)
      add(:observed_version, :string)
      add(:capabilities_hash, :string, null: false)
      add(:reason, :text, null: false)
      add(:acknowledged_by, :string, null: false)
      add(:acknowledged_at, :utc_datetime, null: false)

      timestamps(type: :utc_datetime)
    end

    create(
      unique_index(
        :upgrade_gate_stale_node_acknowledgements,
        [
          :upgrade_gate_id,
          :verification_generation,
          :node_id,
          :incarnation_id,
          :observed_last_seen_at
        ],
        name: :upgrade_gate_ack_snapshot_unique
      )
    )

    create(
      index(
        :upgrade_gate_stale_node_acknowledgements,
        [:upgrade_gate_id, :verification_generation],
        name: :upgrade_gate_ack_generation_index
      )
    )

    create(
      constraint(
        :upgrade_gate_stale_node_acknowledgements,
        :upgrade_gate_ack_positive_generation,
        check: "verification_generation > 0"
      )
    )

    create(
      constraint(
        :upgrade_gate_stale_node_acknowledgements,
        :upgrade_gate_ack_known_status,
        check: "observed_status IN (#{sql_values(@node_statuses)})"
      )
    )

    create(
      constraint(
        :upgrade_gate_stale_node_acknowledgements,
        :upgrade_gate_ack_capabilities_hash,
        check: "capabilities_hash ~ '^[0-9a-f]{64}$'"
      )
    )

    create(
      constraint(
        :upgrade_gate_stale_node_acknowledgements,
        :upgrade_gate_ack_reason,
        check: "length(btrim(reason)) > 0"
      )
    )

    create(
      constraint(
        :upgrade_gate_stale_node_acknowledgements,
        :upgrade_gate_ack_acknowledged_by,
        check: "length(btrim(acknowledged_by)) > 0"
      )
    )
  end

  def down do
    drop(table(:upgrade_gate_stale_node_acknowledgements))
    drop(table(:upgrade_gates))
  end

  defp sql_values(values) do
    values
    |> Enum.map_join(", ", &"'#{&1}'")
  end
end
