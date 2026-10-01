#!/usr/bin/env python3
"""Selected G16 static-consumer readback from an operator-prepared restore."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from acceptance import private_json, require
from recovery_acceptance import private_file
from static_acceptance import CORE_EVAL, UUID, StaticHarness, private_result, serving_identity, validate_config


# Reuse only the reviewed owned-VM boot, observer and runtime node-ID checks.
# No initialization, unseal, gate verification/activation or business mutation.
READ_ONLY_BOOT, separator, _ = CORE_EVAL.partition('  result = case input["operation"] do')
require(separator)
RESTORE_INTEGRITY = READ_ONLY_BOOT + r'''
  report = SecretHub.Core.AuthorizationVersions.report()
  true = report.findings == []
  gate = Repo.get_by!(SecretHub.Shared.Schemas.UpgradeGate, name: "typed_runtime_authorization")
  {:ok, report_hash} = SecretHub.Core.UpgradeGates.report_hash(report)
  true = gate.report_hash == report_hash
  true = gate.verification_generation > 0
  floor = SecretHub.Core.UpgradeGates.minimum_uds_auth_version()
  IO.puts("STATIC_PRIVATE=" <> Jason.encode!(%{
    result: %{findings_count: 0, typed_auth_gate_present: true, typed_auth_report_hash: report_hash,
      typed_auth_verification_generation: gate.verification_generation, minimum_uds_auth_version: floor},
    eval_node_id: eval_node_id, serving_before: serving_before, serving_after: serving_snapshot.()}))
rescue
  _ -> IO.puts("STATIC_PRIVATE=false")
catch
  _, _ -> IO.puts("STATIC_PRIVATE=false")
end'''


def restore_started_at(config):
    value = datetime.fromisoformat(config['service_restore_started_at'].replace('Z', '+00:00'))
    require(value.tzinfo is not None)
    return value


def validate_restore_config(config):
    validate_config(config)
    baseline = config['recovery_baseline']
    identity = baseline['agent_identity']
    require(set(identity) == {'agent_id', 'certificate_sha256', 'key_sha256', 'ca_sha256', 'minimum_uds_auth_version'})
    require(re.fullmatch('agent-' + UUID, identity['agent_id']) is not None)
    for key in ('certificate_sha256', 'key_sha256', 'ca_sha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', identity[key]) is not None)
    require(type(identity['minimum_uds_auth_version']) is int and identity['minimum_uds_auth_version'] in (1, 2))
    require(re.fullmatch(UUID, baseline['certificate_id']) is not None)
    ids = baseline['enrollment_ids']
    require(isinstance(ids, list) and ids and len(ids) == len(set(ids)))
    require(all(re.fullmatch(UUID, value) is not None for value in ids))
    require(type(baseline['version']) is int and baseline['version'] == 2)
    require(type(baseline['revision']) is int and baseline['revision'] > 0)
    restore_started_at(config)
    return config


class StaticRestoreHarness(StaticHarness):
    def __init__(self, config, output):
        super().__init__(config, output, None)  # Held shares remain with the operator.
        self.baseline = config['recovery_baseline']
        self.cluster_phase = 'restored_serving_state'

    def core_private(self, operation, extra=None):
        require(operation in ('database_status', 'enrollment_ids', 'preflight', 'restore_integrity'))
        require(extra is None)
        if operation != 'restore_integrity':
            return super().core_private(operation)
        payload = dict(self.fixture, operation=operation, hostname=self.hostname)
        payload.pop('directory')
        raw = self.owned_eval('core', RESTORE_INTEGRITY, json.dumps(payload).encode())
        observed = private_result(raw.stdout)
        before, after = observed['serving_before'], observed['serving_after']
        require(observed['eval_node_id'].startswith(self.owner + '-core-eval-') and observed['eval_node_id'] != before['node_id'])
        preserved = serving_identity(before) == serving_identity(after)
        if self.cluster_observations:
            preserved &= serving_identity(self.cluster_observations[-1]['after']) == serving_identity(before)
        self.cluster_observations.append({'operation': operation, 'phase': self.cluster_phase,
            'eval_node_id': observed['eval_node_id'], 'before': before, 'after': after, 'identity_preserved': preserved})
        require(preserved and isinstance(observed['result'], dict))
        return observed['result']

    def assert_identity(self, row):
        require(row['agent_id'] == self.baseline['agent_identity']['agent_id'])
        require(row['certificate_id'] == self.baseline['certificate_id'] and row['status'] == 'finalized')
        require(self.snapshot() == self.baseline['agent_identity'])
        require(sorted(self.enrollment_ids()) == sorted(self.baseline['enrollment_ids']))

    def integrity(self):
        metadata = self.core_private('preflight')
        require(metadata['secret'] == {key: self.baseline[key] for key in ('version', 'revision')})
        require(metadata['agent_runtime_id'] == self.baseline['agent_identity']['agent_id'])
        integrity = self.core_private('restore_integrity')
        require(integrity['findings_count'] == 0 and integrity['typed_auth_gate_present'] is True)
        require(integrity['minimum_uds_auth_version'] == self.baseline['agent_identity']['minimum_uds_auth_version'])
        return integrity

    def execute(self):
        self.stage = 'restored_protected_core'
        code, _, status = self.core.client.json('/v1/sys/seal-status')
        require(code == 200 and status['initialized'] is True and status['sealed'] is False)
        self.results['protected_core'] = {'status': 'passed', 'operator_prepared_unsealed': True}
        self.stage = 'restored_runtime_identity'
        first = self.wait_connected(not_before=restore_started_at(self.config))
        self.assert_identity(first)
        self.results['runtime_identity'] = {'status': 'passed', 'fresh_post_restore_heartbeat': True,
                                          'identity_enrollment_certificate_floor_preserved': True}
        self.stage = 'restored_authorization_integrity'
        before = self.integrity()
        self.stage = 'restored_consumer_readback'
        consumer = self.allowed(2, self.baseline['revision'])
        require(consumer['version'] == self.baseline['version'])
        self.results['consumer_readback'] = consumer
        self.stage = 'restored_post_read_integrity'
        require(self.integrity() == before)
        rows = self.database_status()
        require(isinstance(rows, list) and len(rows) == 1)
        self.assert_identity(rows[0])
        code, _, status = self.core.client.json('/v1/sys/seal-status')
        require(code == 200 and status['initialized'] is True and status['sealed'] is False)
        self.results['typed_authorization'] = before

    def run(self):
        started = time.monotonic()
        passed = False
        try:
            self.execute()
            passed = True
        except Exception as error:
            self.results['failure'] = {'stage': self.stage, 'error_type': type(error).__name__}
        finally:
            # Only owned transient VMs; no service recovery or policy operations.
            for name in list(self.active_containers):
                try:
                    self.remove_container(name)
                except Exception:
                    passed = False
        report = {key: self.config[key] for key in ('source_sha', 'platform', 'core_image_id', 'agent_image_id', 'consumer_image_id')}
        report.update(complete=False, provisional=self.core.provisional, recovery_hold=True,
            selected_checks='passed' if passed else 'failed', observed_at=datetime.now(timezone.utc).isoformat(),
            service_restore_started_at=self.config['service_restore_started_at'], results=self.results,
            gates={'G16': {'status': 'partial', 'selected_static_consumer_checks': 'passed' if passed else 'failed',
                          'unexecuted': ['full restore/RTO', 'audit-chain recovery', 'PKI/consumer restore']},
                   'G17': {'status': 'unexecuted'}},
            cleanup_confirmed=not self.active_containers, serving_cluster_observations=self.cluster_observations,
            core_eval_node_ids=self.core_eval_node_ids,
            incidental_cluster_rows='retained if evaluator startup registered; no row deletion or backfill',
            consumer_program_sha256=self.program_hash, seconds=round(time.monotonic() - started, 3),
            diagnostics_sha256=hashlib.sha256(b'\n'.join(self.diagnostics + self.core.fixture_logs)).hexdigest(),
            private_material='excluded; preserve restored identity/trust, app key/certificate, expected values and applied file')
        if not report['cleanup_confirmed']:
            passed = False
            report['selected_checks'] = report['gates']['G16']['selected_static_consumer_checks'] = 'failed'
        private_json(self.output / 'static-restore-report.json', report)
        print(json.dumps({'G16': 'partial', 'complete': False, 'selected_checks': report['selected_checks']}))
        return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='private prepared-restore config with preserved public baseline')
    parser.add_argument('--output', required=True, help='new private result directory beside config')
    args = parser.parse_args()
    try:
        checkout = Path(__file__).resolve().parents[2]
        checkout = next((parent.parent for parent in checkout.parents if parent.name == '.trees'), checkout)
        path = private_file(args.config)
        require(not path.is_relative_to(checkout))
        output = Path(args.output).absolute()
        require(output.parent.resolve() == path.parent and not output.resolve().is_relative_to(checkout))
        config = validate_restore_config(json.loads(path.read_text()))
        require(not Path(config['static_fixture']['directory']).is_relative_to(checkout))
        return StaticRestoreHarness(config, output).run()
    except Exception as error:
        print(json.dumps({'complete': False, 'setup': 'failed', 'error_type': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
