defmodule SecretHub.Core.AuditHashVersionTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Audit, CanonicalJSON, Repo}
  alias SecretHub.Shared.Schemas.AuditLog

  @hmac_secret Application.compile_env(
                 :secrethub_core,
                 :audit_hmac_secret,
                 "dev-audit-secret"
               )
  @sha256_hex ~r/\A[0-9a-f]{64}\z/
  @report_hash String.duplicate("a", 64)
  @snapshot_hash String.duplicate("b", 64)

  setup do
    Repo.delete_all(AuditLog)
    :ok
  end

  describe "version 1 compatibility" do
    test "default events preserve the exact legacy hash and HMAC formulas" do
      assert {:ok, log} =
               Audit.log_event(%{
                 event_type: "secret.accessed",
                 actor_type: "agent",
                 actor_id: "agent-v1",
                 secret_id: "secret-v1",
                 access_granted: true,
                 event_data: %{"not_covered_by_v1" => "legacy"}
               })

      expected_hash =
        [
          log.sequence_number,
          DateTime.to_iso8601(log.timestamp),
          log.event_type,
          log.actor_type || "",
          log.actor_id || "",
          log.secret_id || "",
          log.access_granted || false,
          log.previous_hash
        ]
        |> Enum.join("|")
        |> sha256()

      expected_signature =
        [log.event_id, log.sequence_number, expected_hash]
        |> Enum.join("|")
        |> hmac()

      assert Map.fetch!(log, :hash_version) == 1
      assert log.current_hash == expected_hash
      assert log.signature == expected_signature
      assert {:ok, :valid} = Audit.verify_chain()
    end

    test "explicit castable v1 hash_version is persisted and verified as an integer" do
      assert {:ok, log} =
               Audit.log_event(%{
                 event_type: "secret.accessed",
                 hash_version: "1",
                 actor_type: "agent",
                 actor_id: "agent-explicit-v1",
                 access_granted: true,
                 event_data: %{"source" => "explicit-v1"}
               })

      assert log.hash_version == 1
      assert {:ok, %{hash_version: 1}} = Audit.get_log(log.id)
      assert {:ok, :valid} = Audit.verify_chain()
    end
  end

  describe "version 2 upgrade evidence" do
    test "persists v2 and the exact sanitized gate evidence and verifies the chain" do
      assert {:ok, log} =
               Audit.log_event(
                 gate_event(%{
                   event_data: %{
                     upgrade_gate: %{
                       gate: "agent-security",
                       report_hash: @report_hash,
                       capability: "secret-lifecycle",
                       acknowledgement_snapshot_hash: @snapshot_hash
                     }
                   }
                 })
               )

      assert Map.fetch!(log, :hash_version) == 2
      assert log.current_hash =~ @sha256_hex
      assert log.signature =~ @sha256_hex

      assert log.event_data == %{
               "upgrade_gate" => %{
                 "gate" => "agent-security",
                 "report_hash" => @report_hash,
                 "capability" => "secret-lifecycle",
                 "acknowledgement_snapshot_hash" => @snapshot_hash
               }
             }

      expected_hash =
        %{
          "hash_version" => 2,
          "sequence_number" => log.sequence_number,
          "timestamp" => log.timestamp,
          "event_type" => log.event_type,
          "actor_type" => log.actor_type || "",
          "actor_id" => log.actor_id || "",
          "secret_id" => log.secret_id || "",
          "access_granted" => log.access_granted || false,
          "previous_hash" => log.previous_hash,
          "event_data" => log.event_data
        }
        |> CanonicalJSON.encode!()
        |> sha256()

      expected_signature =
        [log.event_id, log.sequence_number, 2, expected_hash]
        |> Enum.join("|")
        |> hmac()

      assert log.current_hash == expected_hash
      assert log.signature == expected_signature
      assert {:ok, :valid} = Audit.verify_chain()
    end

    test "changing persisted report_hash invalidates the chain" do
      assert {:ok, log} = Audit.log_event(gate_event())

      mutate_event_data(log, "report_hash", String.duplicate("c", 64))

      assert {:error, reason} = Audit.verify_chain()
      assert reason =~ "Current hash mismatch"
    end

    test "changing persisted acknowledgement_snapshot_hash invalidates the chain" do
      assert {:ok, log} = Audit.log_event(gate_event())

      mutate_event_data(
        log,
        "acknowledgement_snapshot_hash",
        String.duplicate("d", 64)
      )

      assert {:error, reason} = Audit.verify_chain()
      assert reason =~ "Current hash mismatch"
    end

    test "changing a first and only v2 row to v1 invalidates the chain" do
      assert {:ok, log} = Audit.log_event(gate_event())
      assert log.sequence_number == 1

      Repo.query!("UPDATE audit_logs SET hash_version = 1 WHERE id = $1", [log.id])

      assert {:error, reason} = Audit.verify_chain()
      assert reason =~ "Current hash mismatch"
    end

    test "changing a persisted v2 row to an unsupported version returns a clear error" do
      assert {:ok, log} = Audit.log_event(gate_event())

      Repo.query!("UPDATE audit_logs SET hash_version = 3 WHERE id = $1", [log.id])

      assert {:error, reason} = Audit.verify_chain()
      assert reason =~ "Unsupported hash version 3"
    end

    test "changing current_hash invalidates the chain" do
      assert {:ok, log} = Audit.log_event(gate_event())

      Repo.query!("UPDATE audit_logs SET current_hash = $1 WHERE id = $2", [
        String.duplicate("0", 64),
        log.id
      ])

      assert {:error, reason} = Audit.verify_chain()
      assert reason =~ "Current hash mismatch"
    end

    test "changing a first and only row signature invalidates the chain" do
      assert {:ok, log} = Audit.log_event(gate_event())
      assert log.sequence_number == 1

      Repo.query!("UPDATE audit_logs SET signature = $1 WHERE id = $2", [
        String.duplicate("0", 64),
        log.id
      ])

      assert {:error, reason} = Audit.verify_chain()
      assert reason =~ "Invalid signature"
    end

    test "both upgrade event types require v2" do
      for event_type <- [
            "system.upgrade_gate_verified",
            "system.upgrade_stale_node_acknowledged"
          ] do
        assert {:error, changeset} =
                 Audit.log_event(gate_event(%{event_type: event_type, hash_version: 1}))

        assert "must use hash version 2" in errors_on(changeset).hash_version
        assert {:ok, %{hash_version: 2}} = Audit.log_event(gate_event(%{event_type: event_type}))
      end
    end

    test "unrelated event types cannot opt into v2" do
      assert {:error, changeset} =
               Audit.log_event(%{
                 event_type: "secret.accessed",
                 hash_version: 2,
                 actor_type: "system",
                 event_data: gate_evidence()
               })

      assert "is only supported for upgrade gate events" in errors_on(changeset).hash_version
    end

    test "unsupported hash versions are rejected by the changeset" do
      assert {:error, changeset} = Audit.log_event(gate_event(%{hash_version: 3}))
      assert "is invalid" in errors_on(changeset).hash_version
    end

    test "rejects malformed, missing, duplicate-normalized, and extra gate evidence" do
      malformed_events = [
        gate_event(%{event_data: %{"upgrade_gate" => "not-an-object"}}),
        gate_event(%{
          event_data: %{
            "upgrade_gate" => Map.delete(gate_evidence()["upgrade_gate"], "report_hash")
          }
        }),
        gate_event(%{
          event_data: put_in(gate_evidence(), ["upgrade_gate", "gate"], "  ")
        }),
        gate_event(%{
          event_data:
            put_in(gate_evidence(), ["upgrade_gate", "report_hash"], String.duplicate("A", 64))
        }),
        gate_event(%{event_data: Map.put(gate_evidence(), "raw_report", %{"secret" => "value"})}),
        gate_event(%{
          event_data: %{
            "upgrade_gate" => Map.put(gate_evidence()["upgrade_gate"], "findings", ["sensitive"])
          }
        }),
        gate_event(%{
          event_data: %{
            :upgrade_gate => gate_evidence()["upgrade_gate"],
            "upgrade_gate" => gate_evidence()["upgrade_gate"]
          }
        })
      ]

      for attrs <- malformed_events do
        assert {:error, changeset} = Audit.log_event(attrs)
        assert errors_on(changeset).event_data != []
      end
    end
  end

  defp gate_event(overrides \\ %{}) do
    Map.merge(
      %{
        event_type: "system.upgrade_gate_verified",
        hash_version: 2,
        actor_type: "system",
        actor_id: "upgrade-gate",
        access_granted: true,
        event_data: gate_evidence()
      },
      overrides
    )
  end

  defp gate_evidence do
    %{
      "upgrade_gate" => %{
        "gate" => "agent-security",
        "report_hash" => @report_hash,
        "capability" => "secret-lifecycle",
        "acknowledgement_snapshot_hash" => @snapshot_hash
      }
    }
  end

  defp mutate_event_data(log, key, value) do
    Repo.query!(
      """
      UPDATE audit_logs
      SET event_data = jsonb_set(event_data, ARRAY['upgrade_gate', $1], to_jsonb($2::text))
      WHERE id = $3
      """,
      [key, value, log.id]
    )
  end

  defp sha256(content) do
    :crypto.hash(:sha256, content)
    |> Base.encode16(case: :lower)
  end

  defp hmac(content) do
    :crypto.mac(:hmac, :sha256, @hmac_secret, content)
    |> Base.encode16(case: :lower)
  end
end
