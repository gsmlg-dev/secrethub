defmodule SecretHub.Core.UpgradeGatesTest do
  use SecretHub.Core.DataCase, async: false

  import ExUnit.CaptureIO

  alias Ecto.{Changeset, UUID}
  alias Mix.Tasks.Secrethub.Upgrade.Verify, as: UpgradeVerifyTask
  alias SecretHub.Core.{Audit, CanonicalJSON, Repo, UpgradeGates}

  alias SecretHub.Shared.Schemas.{
    AuditLog,
    ClusterNode,
    UpgradeGate,
    UpgradeGateStaleNodeAcknowledgement
  }

  @gates [
    "app_certificate_v2",
    "typed_runtime_authorization",
    "dynamic_secure_storage",
    "agent_certificate_bindings"
  ]
  @actor_id "operator:upgrade-test"
  @capability {"upgrade_gates", 1}

  defmodule FailingAudit do
    def log_event(_attrs), do: {:error, :injected_audit_failure}
  end

  defmodule ZeroPreflight do
    def report(gate) do
      %{
        "format" => "secrethub.upgrade-gate-report.v1",
        "gate" => gate,
        "preflight_version" => "1",
        "findings" => []
      }
    end
  end

  defmodule FindingPreflight do
    def report(gate) do
      %{
        "format" => "secrethub.upgrade-gate-report.v1",
        "gate" => gate,
        "preflight_version" => "1",
        "findings" => [
          %{
            "identifier" => "public-row-17",
            "kind" => "sensitive-classification",
            "secret" => "must-not-be-printed-or-persisted"
          },
          %{
            "identifier" => %{"secret" => "nested-identifier-secret"},
            "kind" => "another-sensitive-classification"
          }
        ]
      }
    end
  end

  setup do
    Repo.delete_all(UpgradeGateStaleNodeAcknowledgement)
    Repo.delete_all(UpgradeGate)
    Repo.delete_all(AuditLog)
    Repo.delete_all(ClusterNode)

    original_audit_module =
      Application.get_env(:secrethub_core, :upgrade_gate_audit_module)

    original_preflights =
      Application.get_env(:secrethub_core, :upgrade_gate_preflights)

    original_timeout =
      Application.get_env(:secrethub_core, :cluster_node_freshness_timeout_seconds)

    on_exit(fn ->
      restore_env(:upgrade_gate_audit_module, original_audit_module)
      restore_env(:upgrade_gate_preflights, original_preflights)
      restore_env(:cluster_node_freshness_timeout_seconds, original_timeout)
    end)

    :ok
  end

  describe "verification markers" do
    test "migration stores evidence only and uses a restrictive acknowledgement foreign key" do
      gate_columns =
        Repo.query!("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'upgrade_gates'
        ORDER BY column_name
        """).rows
        |> List.flatten()

      assert gate_columns ==
               ~w(
                 id
                 inserted_at
                 name
                 preflight_version
                 report_format
                 report_hash
                 updated_at
                 verification_generation
                 verified_at
                 verified_by
               )
               |> Enum.sort()

      refute Enum.any?(gate_columns, &(&1 in ~w(report findings raw_report)))

      assert %Postgrex.Result{rows: [["r"]]} =
               Repo.query!("""
               SELECT confdeltype::text
               FROM pg_constraint
               WHERE conrelid =
                       'upgrade_gate_stale_node_acknowledgements'::regclass
                 AND contype = 'f'
               """)
    end

    test "exposes only the four fixed gate names" do
      assert UpgradeGates.gates() == @gates

      for gate <- @gates do
        assert {:ok, %UpgradeGate{name: ^gate, verification_generation: 1}} =
                 UpgradeGates.verify(gate, zero_report(gate), actor_id: @actor_id)
      end

      assert {:error, :unknown_gate} =
               UpgradeGates.verify(
                 "caller_selected_gate",
                 zero_report("caller_selected_gate"),
                 actor_id: @actor_id
               )
    end

    test "hashes the exact zero report canonically and stores no raw report" do
      report =
        Jason.decode!(
          ~s({"preflight_version":"1","findings":[],"gate":"app_certificate_v2","format":"secrethub.upgrade-gate-report.v1"})
        )

      assert {:ok, expected_hash} = UpgradeGates.report_hash(report)

      assert {:ok, gate} =
               UpgradeGates.verify("app_certificate_v2", report, actor_id: @actor_id)

      assert gate.report_hash == expected_hash
      assert gate.report_format == "secrethub.upgrade-gate-report.v1"
      assert gate.preflight_version == "1"
      assert gate.verified_by == @actor_id

      assert Map.keys(Map.from_struct(gate)) |> Enum.sort() ==
               [
                 :__meta__,
                 :id,
                 :inserted_at,
                 :name,
                 :preflight_version,
                 :report_format,
                 :report_hash,
                 :updated_at,
                 :verification_generation,
                 :verified_at,
                 :verified_by
               ]
               |> Enum.sort()

      reordered = %{
        "findings" => [],
        "preflight_version" => "1",
        "format" => "secrethub.upgrade-gate-report.v1",
        "gate" => "app_certificate_v2"
      }

      assert {:ok, ^expected_hash} = UpgradeGates.report_hash(reordered)
    end

    test "gate and finding changes alter the hash while unsupported versions are invalid" do
      report = zero_report("app_certificate_v2")
      assert {:ok, original_hash} = UpgradeGates.report_hash(report)

      assert {:ok, changed_gate_hash} =
               report
               |> Map.put("gate", "typed_runtime_authorization")
               |> UpgradeGates.report_hash()

      assert {:ok, changed_finding_hash} =
               report
               |> Map.put("findings", [%{"identifier" => "public-row-1"}])
               |> UpgradeGates.report_hash()

      refute changed_gate_hash == original_hash
      refute changed_finding_hash == original_hash

      assert {:error, :invalid_report} =
               report
               |> Map.put("preflight_version", "2")
               |> UpgradeGates.report_hash()
    end

    test "rejects nonzero, mismatched, and extra-field reports without persistence" do
      nonzero =
        zero_report("app_certificate_v2")
        |> Map.put("findings", [%{"identifier" => "row-1", "secret" => "do-not-store"}])

      assert {:error, :nonzero_findings} =
               UpgradeGates.verify("app_certificate_v2", nonzero, actor_id: @actor_id)

      assert {:error, :invalid_report} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("typed_runtime_authorization"),
                 actor_id: @actor_id
               )

      assert {:error, :invalid_report} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 Map.put(zero_report("app_certificate_v2"), "checked_at", "now"),
                 actor_id: @actor_id
               )

      assert Repo.aggregate(UpgradeGate, :count) == 0
      assert Repo.aggregate(AuditLog, :count) == 0
    end

    test "requires a nonempty public verifier identity" do
      assert {:error, :invalid_actor} =
               UpgradeGates.verify("app_certificate_v2", zero_report("app_certificate_v2"), [])

      assert {:error, :invalid_actor} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: " "
               )
    end

    test "require_verified!/1 fails closed until a marker exists" do
      assert_raise UpgradeGates.RequirementError, ~r/app_certificate_v2/, fn ->
        UpgradeGates.require_verified!("app_certificate_v2")
      end

      assert {:ok, _gate} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: @actor_id
               )

      assert :ok = UpgradeGates.require_verified!(:app_certificate_v2)
    end

    test "audit failure rolls back the gate write" do
      Application.put_env(
        :secrethub_core,
        :upgrade_gate_audit_module,
        FailingAudit
      )

      assert {:error, :injected_audit_failure} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: @actor_id
               )

      assert Repo.aggregate(UpgradeGate, :count) == 0
      assert Repo.aggregate(UpgradeGateStaleNodeAcknowledgement, :count) == 0
    end

    test "concurrent verification serializes generations and audit evidence" do
      parent = self()

      tasks =
        for _ <- 1..4 do
          Task.async(fn ->
            send(parent, {:ready, self()})

            receive do
              :verify -> :ok
            end

            UpgradeGates.verify(
              "app_certificate_v2",
              zero_report("app_certificate_v2"),
              actor_id: @actor_id
            )
          end)
        end

      task_pids =
        for _task <- tasks do
          assert_receive {:ready, pid}
          pid
        end

      Enum.each(task_pids, &send(&1, :verify))

      assert Enum.all?(Task.await_many(tasks, 15_000), &match?({:ok, %UpgradeGate{}}, &1))

      assert %UpgradeGate{verification_generation: 4} =
               Repo.get_by!(UpgradeGate, name: "app_certificate_v2")

      assert Repo.aggregate(
               from(a in AuditLog,
                 where: a.event_type == "system.upgrade_gate_verified"
               ),
               :count
             ) == 4

      assert {:ok, :valid} = Audit.verify_chain()
    end
  end

  describe "cluster capability evidence" do
    test "fails closed when no fresh active node exists" do
      verify_gate!("app_certificate_v2")

      assert {:error, :no_fresh_active_nodes} =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)

      assert_raise UpgradeGates.RequirementError, ~r/no fresh active nodes/, fn ->
        UpgradeGates.require_cluster_capability!("app_certificate_v2", @capability)
      end
    end

    test "accepts every fresh active status only at or above the required revision" do
      for status <- ~w(starting initializing sealed unsealed) do
        Repo.delete_all(ClusterNode)
        node = insert_node(status: status, capabilities: %{"upgrade_gates" => 0})

        assert {:error, {:incompatible_nodes, [%{node_id: node_id}]}} =
                 UpgradeGates.cluster_capability("app_certificate_v2", @capability)

        assert node_id == node.node_id

        node
        |> Changeset.change(metadata: %{"capabilities" => %{"upgrade_gates" => 1}})
        |> Repo.update!()

        assert :ok =
                 UpgradeGates.cluster_capability("app_certificate_v2", @capability)
      end
    end

    test "excludes shutdown nodes from the compatibility predicate" do
      insert_node(
        node_id: "fresh-capable",
        status: "unsealed",
        capabilities: %{"upgrade_gates" => 1}
      )

      insert_node(
        node_id: "shutdown-old",
        status: "shutdown",
        capabilities: %{"upgrade_gates" => 0}
      )

      assert :ok =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)
    end

    test "requires an exact current-generation acknowledgement for stale nodes" do
      verify_gate!("app_certificate_v2")

      insert_node(
        node_id: "fresh-capable",
        status: "unsealed",
        capabilities: %{"upgrade_gates" => 1}
      )

      stale =
        insert_node(
          node_id: "stale-old",
          status: "sealed",
          capabilities: %{"upgrade_gates" => 0},
          last_seen_at: DateTime.add(now(), -3_600, :second)
        )

      assert {:error, {:stale_nodes, [snapshot]}} =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)

      assert snapshot.node_id == stale.node_id
      assert snapshot.incarnation_id == stale.incarnation_id
      assert snapshot.observed_last_seen_at == stale.last_seen_at
      assert snapshot.observed_status == stale.status
      assert snapshot.observed_version == stale.version
      assert snapshot.capabilities_hash =~ ~r/\A[0-9a-f]{64}\z/

      acknowledgement = Map.put(snapshot, :reason, "node was decommissioned")

      assert {:ok, %UpgradeGate{verification_generation: 2}} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: @actor_id,
                 stale_node_acknowledgements: [acknowledgement]
               )

      assert :ok =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)

      assert %UpgradeGateStaleNodeAcknowledgement{
               node_id: "stale-old",
               acknowledged_by: @actor_id,
               reason: "node was decommissioned",
               verification_generation: 2
             } = Repo.one!(UpgradeGateStaleNodeAcknowledgement)

      audit_types =
        AuditLog
        |> order_by([a], asc: a.sequence_number)
        |> select([a], a.event_type)
        |> Repo.all()

      assert audit_types == [
               "system.upgrade_gate_verified",
               "system.upgrade_stale_node_acknowledged",
               "system.upgrade_gate_verified"
             ]

      acknowledgement_audit =
        Repo.get_by!(AuditLog,
          event_type: "system.upgrade_stale_node_acknowledged"
        )

      assert acknowledgement_audit.hash_version == 2

      assert %{
               "upgrade_gate" => %{
                 "gate" => "app_certificate_v2",
                 "report_hash" => report_hash,
                 "capability" => "preflight@1",
                 "acknowledgement_snapshot_hash" => snapshot_hash
               }
             } = acknowledgement_audit.event_data

      assert report_hash =~ ~r/\A[0-9a-f]{64}\z/
      assert snapshot_hash =~ ~r/\A[0-9a-f]{64}\z/
      refute inspect(acknowledgement_audit.event_data) =~ "node was decommissioned"
      assert {:ok, :valid} = Audit.verify_chain()

      stale
      |> Changeset.change(last_seen_at: DateTime.add(stale.last_seen_at, 1, :second))
      |> Repo.update!()

      assert {:error, {:stale_nodes, [_changed_snapshot]}} =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)
    end

    test "rejects acknowledgements for fresh, shutdown, unknown, or mismatched nodes" do
      fresh = insert_node(node_id: "fresh-node", capabilities: %{"upgrade_gates" => 1})
      snapshot = snapshot_for(fresh)

      for invalid_ack <- [
            Map.put(snapshot, :reason, "fresh"),
            snapshot |> Map.put(:node_id, "unknown-node") |> Map.put(:reason, "unknown"),
            snapshot
            |> Map.put(:capabilities_hash, String.duplicate("0", 64))
            |> Map.put(:reason, "mismatch"),
            snapshot |> Map.put(:reason, "extra") |> Map.put(:extra, "not-allowed")
          ] do
        assert {:error, :invalid_acknowledgement} =
                 UpgradeGates.verify(
                   "app_certificate_v2",
                   zero_report("app_certificate_v2"),
                   actor_id: @actor_id,
                   stale_node_acknowledgements: [invalid_ack]
                 )
      end

      fresh
      |> Changeset.change(status: "shutdown")
      |> Repo.update!()

      assert {:error, :invalid_acknowledgement} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: @actor_id,
                 stale_node_acknowledgements: [
                   Map.put(snapshot_for(Repo.get!(ClusterNode, fresh.id)), :reason, "shutdown")
                 ]
               )
    end

    test "heartbeat, version, capability, incarnation, and status changes invalidate an acknowledgement" do
      mutations = [
        heartbeat: fn node ->
          Changeset.change(node,
            last_seen_at: DateTime.add(node.last_seen_at, 1, :second)
          )
        end,
        version: &Changeset.change(&1, version: "2.0.0"),
        capability: fn node ->
          Changeset.change(node,
            metadata: %{"capabilities" => %{"upgrade_gates" => 2}}
          )
        end,
        incarnation: &Changeset.change(&1, incarnation_id: UUID.generate()),
        status: &Changeset.change(&1, status: "starting")
      ]

      for {_name, mutate} <- mutations do
        clear_upgrade_evidence()
        verify_gate!("app_certificate_v2")

        insert_node(
          node_id: "fresh-capable",
          status: "unsealed",
          capabilities: %{"upgrade_gates" => 1}
        )

        stale =
          insert_node(
            node_id: "stale-old",
            status: "sealed",
            capabilities: %{"upgrade_gates" => 0},
            last_seen_at: DateTime.add(now(), -3_600, :second)
          )

        assert {:error, {:stale_nodes, [snapshot]}} =
                 UpgradeGates.cluster_capability("app_certificate_v2", @capability)

        assert {:ok, _gate} =
                 UpgradeGates.verify(
                   "app_certificate_v2",
                   zero_report("app_certificate_v2"),
                   actor_id: @actor_id,
                   stale_node_acknowledgements: [
                     Map.put(snapshot, :reason, "node decommissioned")
                   ]
                 )

        assert :ok =
                 UpgradeGates.cluster_capability("app_certificate_v2", @capability)

        stale
        |> mutate.()
        |> Repo.update!()

        assert {:error, {:stale_nodes, [_changed_snapshot]}} =
                 UpgradeGates.cluster_capability("app_certificate_v2", @capability)
      end
    end

    test "a later verification generation must explicitly carry acknowledgements forward" do
      verify_gate!("app_certificate_v2")

      insert_node(
        node_id: "fresh-capable",
        status: "unsealed",
        capabilities: %{"upgrade_gates" => 1}
      )

      insert_node(
        node_id: "stale-old",
        status: "sealed",
        capabilities: %{"upgrade_gates" => 0},
        last_seen_at: DateTime.add(now(), -3_600, :second)
      )

      assert {:error, {:stale_nodes, [snapshot]}} =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)

      assert {:ok, %UpgradeGate{verification_generation: 2}} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: @actor_id,
                 stale_node_acknowledgements: [
                   Map.put(snapshot, :reason, "node decommissioned")
                 ]
               )

      assert :ok =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)

      assert {:ok, %UpgradeGate{verification_generation: 3}} =
               UpgradeGates.verify(
                 "app_certificate_v2",
                 zero_report("app_certificate_v2"),
                 actor_id: @actor_id
               )

      assert {:error, {:stale_nodes, [_snapshot]}} =
               UpgradeGates.cluster_capability("app_certificate_v2", @capability)
    end

    test "validates the single configured freshness timeout" do
      Application.put_env(:secrethub_core, :cluster_node_freshness_timeout_seconds, 0)

      assert_raise ArgumentError, ~r/between 1 and 300/, fn ->
        UpgradeGates.cluster_capability("app_certificate_v2", @capability)
      end

      Application.put_env(:secrethub_core, :cluster_node_freshness_timeout_seconds, 301)

      assert_raise ArgumentError, ~r/between 1 and 300/, fn ->
        UpgradeGates.cluster_capability("app_certificate_v2", @capability)
      end
    end
  end

  describe "mix secrethub.upgrade.verify" do
    test "fails closed when no preflight is registered" do
      Application.put_env(:secrethub_core, :upgrade_gate_preflights, %{})

      assert_raise Mix.Error, ~r/no preflight is registered/, fn ->
        UpgradeVerifyTask.run(["app_certificate_v2"])
      end

      assert Repo.aggregate(UpgradeGate, :count) == 0
    end

    test "persists a registered zero-finding report" do
      Application.put_env(:secrethub_core, :upgrade_gate_preflights, %{
        "app_certificate_v2" => ZeroPreflight
      })

      output =
        capture_io(fn ->
          assert :ok =
                   UpgradeVerifyTask.run([
                     "app_certificate_v2",
                     "--actor",
                     @actor_id
                   ])
        end)

      assert output =~ "verified app_certificate_v2"
      assert Repo.get_by!(UpgradeGate, name: "app_certificate_v2")
    end

    test "prints sanitized unresolved identifiers but neither prints nor persists secrets" do
      Application.put_env(:secrethub_core, :upgrade_gate_preflights, %{
        "app_certificate_v2" => FindingPreflight
      })

      output =
        capture_io(fn ->
          assert_raise Mix.Error, ~r/preflight reported 2 unresolved findings/, fn ->
            UpgradeVerifyTask.run([
              "app_certificate_v2",
              "--actor",
              @actor_id
            ])
          end
        end)

      assert output =~ "public-row-17"
      assert output =~ "unidentified"
      refute output =~ "must-not-be-printed-or-persisted"
      refute output =~ "nested-identifier-secret"
      refute output =~ "sensitive-classification"
      assert Repo.aggregate(UpgradeGate, :count) == 0
      assert Repo.aggregate(AuditLog, :count) == 0
    end
  end

  defp verify_gate!(gate) do
    assert {:ok, %UpgradeGate{}} =
             UpgradeGates.verify(gate, zero_report(gate), actor_id: @actor_id)
  end

  defp zero_report(gate) do
    %{
      "format" => "secrethub.upgrade-gate-report.v1",
      "gate" => gate,
      "preflight_version" => "1",
      "findings" => []
    }
  end

  defp insert_node(opts) do
    timestamp = Keyword.get(opts, :last_seen_at, now())

    attrs = %{
      node_id: Keyword.get(opts, :node_id, "node-#{System.unique_integer([:positive])}"),
      incarnation_id: UUID.generate(),
      hostname: "upgrade-test-host",
      status: Keyword.get(opts, :status, "unsealed"),
      leader: false,
      last_seen_at: timestamp,
      started_at: DateTime.add(timestamp, -60, :second),
      sealed: Keyword.get(opts, :status, "unsealed") != "unsealed",
      initialized: true,
      version: Keyword.get(opts, :version, "1.0.0"),
      metadata: %{
        "capabilities" => Keyword.get(opts, :capabilities, %{"upgrade_gates" => 1})
      }
    }

    %ClusterNode{}
    |> ClusterNode.changeset(attrs)
    |> Repo.insert!()
  end

  defp snapshot_for(node) do
    %{
      node_id: node.node_id,
      incarnation_id: node.incarnation_id,
      observed_last_seen_at: node.last_seen_at,
      observed_status: node.status,
      observed_version: node.version,
      capabilities_hash:
        node.metadata
        |> Map.get("capabilities", %{})
        |> CanonicalJSON.encode!()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)
    }
  end

  defp clear_upgrade_evidence do
    Repo.delete_all(UpgradeGateStaleNodeAcknowledgement)
    Repo.delete_all(UpgradeGate)
    Repo.delete_all(AuditLog)
    Repo.delete_all(ClusterNode)
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp restore_env(key, nil), do: Application.delete_env(:secrethub_core, key)
  defp restore_env(key, value), do: Application.put_env(:secrethub_core, key, value)
end
