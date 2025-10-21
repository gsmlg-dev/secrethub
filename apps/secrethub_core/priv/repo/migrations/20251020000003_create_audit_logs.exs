defmodule SecretHub.Core.Repo.Migrations.CreateAuditLogs do
  use Ecto.Migration

  def change do
    # Create the partitioned table
    execute("""
    CREATE TABLE audit_logs (
        id BIGSERIAL,
        event_id UUID NOT NULL,
        sequence_number BIGINT NOT NULL,
        timestamp TIMESTAMPTZ NOT NULL,
        event_type VARCHAR(100) NOT NULL,

        -- Actor information
        actor_type VARCHAR(50),
        actor_id VARCHAR(255),
        agent_id VARCHAR(255),
        app_id VARCHAR(255),
        admin_id VARCHAR(255),

        -- Certificate fingerprints for non-repudiation
        agent_cert_fingerprint VARCHAR(64),
        app_cert_fingerprint VARCHAR(64),

        -- Secret information
        secret_id VARCHAR(500),
        secret_version INTEGER,
        secret_type VARCHAR(50),
        lease_id UUID,

        -- Access control
        access_granted BOOLEAN,
        policy_matched VARCHAR(255),
        denial_reason TEXT,

        -- Context
        source_ip INET,
        hostname VARCHAR(255),
        kubernetes_namespace VARCHAR(255),
        kubernetes_pod VARCHAR(255),

        -- Full event data
        event_data JSONB,

        -- Tamper-evidence
        previous_hash VARCHAR(64),
        current_hash VARCHAR(64),
        signature VARCHAR(128),

        -- Performance
        response_time_ms INTEGER,
        correlation_id UUID,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        PRIMARY KEY (id, timestamp)
    ) PARTITION BY RANGE (timestamp)
    """)

    # Create indexes on the partitioned table
    create(index(:audit_logs, [:timestamp]))
    create(index(:audit_logs, [:event_id]))
    create(index(:audit_logs, [:sequence_number]))
    create(index(:audit_logs, [:event_type, :timestamp]))
    create(index(:audit_logs, [:actor_id, :timestamp]))
    create(index(:audit_logs, [:agent_id, :timestamp]))
    create(index(:audit_logs, [:secret_id, :timestamp]))

    # Add unique constraints that include the partitioning column
    execute("""
    ALTER TABLE audit_logs 
    ADD CONSTRAINT unique_event_id_timestamp UNIQUE (event_id, timestamp)
    """)

    execute("""
    ALTER TABLE audit_logs 
    ADD CONSTRAINT unique_sequence_number_timestamp UNIQUE (sequence_number, timestamp)
    """)

    # Index for denied access queries
    execute("""
    CREATE INDEX idx_audit_logs_access_denied ON audit_logs(timestamp DESC)
    WHERE access_granted = false
    """)

    # GIN index on JSONB event_data
    create(index(:audit_logs, [:event_data], using: :gin))

    # Create initial partition for current month
    # In production, partitions should be created automatically or via scheduled job
    current_date = Date.utc_today()
    year = current_date.year
    month = current_date.month
    next_month = if month == 12, do: 1, else: month + 1
    next_year = if month == 12, do: year + 1, else: year

    partition_name = "audit_logs_y#{year}m#{String.pad_leading(to_string(month), 2, "0")}"

    from_date = "#{year}-#{String.pad_leading(to_string(month), 2, "0")}-01"
    to_date = "#{next_year}-#{String.pad_leading(to_string(next_month), 2, "0")}-01"

    execute("""
    CREATE TABLE #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{from_date}') TO ('#{to_date}')
    """)
  end
end
