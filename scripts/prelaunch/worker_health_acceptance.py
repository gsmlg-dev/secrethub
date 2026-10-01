#!/usr/bin/env python3
"""Selected G20 worker failure/recovery evidence on a quiesced copied database."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from acceptance import CheckFailed, private_json, require
from recovery_acceptance import RecoveryHarness, private_file, sensitive_strings, validate_config


MARKER = 'WORKER_HEALTH_RESULT='
CHECKS = {'core_service_uid', 'no_web_apps_or_listeners', 'loaded_sealed',
          'manual_unseal', 'worker_required', 'persisted_crl_present', 'worker_restarted_pid'}
BOOL_FIELDS = {'running', 'supervised_running', 'worker_enabled', 'checked', 'scheduled',
               'last_error_nil', 'background_ok', 'background_required', 'readiness_ok', 'ready',
               'readiness_background_passing', 'seal_passing', 'sealed', 'liveness_ok',
               'management_ok', 'management_ready', 'health_background_passing'}

# Constant release program: independently held shares arrive only over stdin.
EVAL = r'''try do
  {:ok, _} = Application.ensure_all_started(:secrethub_core)
  worker = SecretHub.Core.Workers.ClientAuthCRLRefresher
  supervisor = SecretHub.Core.Supervisor
  health = SecretHub.Core.Health
  true = SecretHub.Shared.LaunchProfile.enabled?(:client_auth_pki)
  {"1001\n", 0} = System.cmd("id", ["-u"])
  isolated = fn ->
    apps = Application.started_applications() |> Enum.map(&elem(&1, 0))
    Enum.all?([:secrethub_web, :secrethub_agent, :secrethub_human], &(&1 not in apps)) and
      Enum.all?(~w(tcp tcp6 udp udp6), fn protocol ->
        File.read!("/proc/net/" <> protocol) |> String.split("\n", trim: true) |> length() == 1
      end)
  end
  true = isolated.()
  wait = fn wait, predicate, deadline ->
    if predicate.() do
      :ok
    else
      true = System.monotonic_time(:millisecond) < deadline
      Process.sleep(100)
      wait.(wait, predicate, deadline)
    end
  end
  :ok = wait.(wait, fn ->
    status = SecretHub.Core.Vault.SealState.status()
    status.state == :sealed and status.initialized and not status.recovery_required
  end, System.monotonic_time(:millisecond) + 15000)
  status = SecretHub.Core.Vault.SealState.status()
  input = Jason.decode!(IO.read(:stdio, :eof))
  shares = input["shares"]
  true = is_list(shares) and length(Enum.uniq(shares)) == length(shares) and
    length(shares) >= status.threshold
  for encoded <- Enum.take(shares, status.threshold) do
    {:ok, share} = SecretHub.Shared.Crypto.Shamir.decode_share(encoded)
    {:ok, _} = SecretHub.Core.Vault.SealState.unseal(share)
  end
  false = SecretHub.Core.Vault.SealState.status().sealed
  # A required worker must observe actual persisted PKI, not the absent-authority shortcut.
  {:ok, %{rows: [[1]]}} = SecretHub.Core.Repo.query(
    "SELECT count(*) FROM client_auth_authorities a JOIN client_auth_crls c ON c.id = a.current_crl_id WHERE a.slug = 'client-auth' AND a.status = 'active' AND c.next_update IS NOT NULL")
  observe = fn ->
    pid = Process.whereis(worker)
    running = is_pid(pid) and Process.alive?(pid)
    supervised = Enum.any?(Supervisor.which_children(supervisor), fn {id, child, _, _} ->
      id == worker and is_pid(child) and child == pid
    end)
    state = if running, do: :sys.get_state(pid, 500), else: %{}
    {background_status, background} = health.check_background_jobs()
    {readiness_status, readiness} = health.readiness()
    {management_status, management} = health.management_readiness()
    {liveness_status, _} = health.liveness()
    {:ok, details} = health.health()
    %{running: running, supervised_running: supervised,
      worker_enabled: state[:enabled] == true, checked: not is_nil(state[:last_checked_at]),
      scheduled: is_reference(state[:timer]) and Process.read_timer(state[:timer]) != false,
      last_error_nil: running and is_nil(state[:last_error]), retry_attempt: state[:retry_attempt] || 0,
      background_ok: background_status == :ok, background_required: true,
      background_reason: background[:reason] || "none", readiness_ok: readiness_status == :ok,
      ready: readiness.ready, readiness_background_passing: readiness.checks.background_jobs.status == "passing",
      seal_passing: readiness.checks.seal_status.status == "passing", sealed: details.sealed,
      liveness_ok: liveness_status == :ok, management_ok: management_status == :ok,
      management_ready: management.ready,
      health_background_passing: details.checks.background_jobs.status == "passing",
      health_status: Atom.to_string(details.status)}
  end
  healthy = fn ->
    match?({:ok, %{required: true}}, health.check_background_jobs()) and
      match?({:ok, %{ready: true}}, health.readiness())
  end
  :ok = wait.(wait, healthy, System.monotonic_time(:millisecond) + 20000)
  before = observe.()
  previous_pid = Process.whereis(worker)
  :ok = Supervisor.terminate_child(supervisor, worker)
  stopped = observe.()
  false = stopped.running
  false = stopped.supervised_running
  false = stopped.background_ok
  "crl_worker_unavailable" = stopped.background_reason
  false = stopped.readiness_ok
  false = stopped.ready
  true = stopped.seal_passing
  false = stopped.sealed
  true = stopped.liveness_ok and stopped.management_ok and stopped.management_ready
  {:ok, restarted_pid} = Supervisor.restart_child(supervisor, worker)
  true = restarted_pid != previous_pid
  :ok = wait.(wait, healthy, System.monotonic_time(:millisecond) + 20000)
  recovered = observe.()
  true = isolated.()
  IO.puts("WORKER_HEALTH_RESULT=" <> Jason.encode!(%{
    checks: %{core_service_uid: true, no_web_apps_or_listeners: true, loaded_sealed: true,
      manual_unseal: true, worker_required: true, persisted_crl_present: true, worker_restarted_pid: true},
    phases: %{healthy: before, stopped: stopped, recovered: recovered}}))
rescue
  _ -> IO.puts("WORKER_HEALTH_RESULT=false")
catch
  _, _ -> IO.puts("WORKER_HEALTH_RESULT=false")
end'''


def safe_result(stdout):
    lines = [line[len(MARKER):] for line in stdout.decode().splitlines() if line.startswith(MARKER)]
    require(len(lines) == 1)
    result = json.loads(lines[0])
    require(isinstance(result, dict) and set(result) == {'checks', 'phases'})
    require(set(result['checks']) == CHECKS and all(value is True for value in result['checks'].values()))
    require(set(result['phases']) == {'healthy', 'stopped', 'recovered'})
    for phase, row in result['phases'].items():
        require(set(row) == BOOL_FIELDS | {'retry_attempt', 'background_reason', 'health_status'})
        require(all(type(row[key]) is bool for key in BOOL_FIELDS))
        require(type(row['retry_attempt']) is int and row['retry_attempt'] >= 0)
        stopped = phase == 'stopped'
        for key in BOOL_FIELDS - {'sealed'}:
            expected = True if key in {'background_required', 'seal_passing', 'liveness_ok',
                                       'management_ok', 'management_ready'} else not stopped
            require(row[key] is expected)
        require(row['sealed'] is False)
        require(row['background_reason'] == ('crl_worker_unavailable' if stopped else 'none'))
        require(row['health_status'] == ('degraded' if stopped else 'healthy'))
    return result


def no_symlinks(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    require(all(not part.is_symlink() for part in (path, *path.parents)))
    return path


def validate_worker_config(config, checkout):
    require(config.get('copied_database') is True and config.get('quiesced_fixture') is True)
    for key in ('original_fixture_postgres_container', 'original_fixture_database'):
        require(isinstance(config[key], str) and re.fullmatch(r'[a-z0-9_-]+', config[key]) is not None)
        require(config[key] != config[key.removeprefix('original_')])
    for key in ('fixture_root', 'fixture_socket_dir', 'core_input_dir', 'core_env_file'):
        no_symlinks(config[key])
    no_symlinks(Path(config['fixture_socket_dir']) / '.s.PGSQL.5432')
    validate_config(config, checkout)
    inputs = Path(config['core_input_dir'])
    require(inputs.stat().st_uid in (os.getuid(), 1001) and inputs.stat().st_mode & 0o022 == 0)
    environment = dict(line.split('=', 1) for line in Path(config['core_env_file']).read_text().splitlines()
                       if line and not line.startswith('#'))
    require('SECRET_HUB_CLUSTER_NODE_ID_FILE' not in environment)
    for key, value in environment.items():
        if key.endswith('_FILE'):
            host = no_symlinks(inputs / Path(value).relative_to(config['core_input_mount']))
            info = host.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (os.getuid(), 1001))
            require(info.st_mode & 0o007 == 0 and
                    (info.st_mode & 0o070 == 0 or
                     (info.st_gid == 1001 and info.st_mode & 0o070 == 0o040)))
    return config


class WorkerHealthHarness(RecoveryHarness):
    def __init__(self, config, shares):
        super().__init__(config, shares, {})

    def artifacts(self):
        super().artifacts()
        image = json.loads(self.command(['docker', 'image', 'inspect', self.config['core_image_id']]).stdout)[0]
        require(not any(entry.startswith('SECRET_HUB_CLUSTER_NODE_ID_FILE=')
                        for entry in image['Config'].get('Env', [])))

    def quiesced(self):
        # Observation only; do not terminate sessions or change any database.
        require(self.query("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid != pg_backend_pid()") == 0)

    def cleanup(self):
        if self.name is None:
            return
        names = ['docker', 'ps', '-a', '--filter', 'name=^/' + self.name + '$', '--format', '{{.Names}}']
        if self.command(names).stdout.strip():
            info = json.loads(self.command(['docker', 'inspect', self.name]).stdout)[0]
            require((info['Config'].get('Labels') or {}).get('secrethub.prelaunch.owner') == self.name)
            self.command(['docker', 'rm', '-f', self.name], timeout=20)
        require(not self.command(names).stdout.strip())
        self.cleanup_confirmed = True
        self.name = None

    def evaluate(self):
        require(self.name is None and self.cleanup_confirmed)
        name = self.config['fixture_prefix'] + '-worker-health-' + uuid.uuid4().hex[:12]
        require(not self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).stdout.strip())
        args = ['docker', 'create', '--pull', 'never', '--name', name,
                '--label', 'secrethub.prelaunch.owner=' + name, '--network', 'none',
                '--user', '1001:1001', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--no-healthcheck', '-i',
                '--tmpfs', '/app/tmp:rw,noexec,nosuid,uid=1001,gid=1001,mode=700',
                '--env-file', self.config['core_env_file'], '-e', 'SECRET_HUB_CLUSTER_NODE_ID=' + name,
                '-e', 'RELEASE_DISTRIBUTION=none', '-e', 'ERL_CRASH_DUMP=/dev/null',
                '-e', 'SECRETHUB_ROLE=core', '-e', 'PHX_SERVER=',
                '-e', 'SECRET_HUB_AGENT_ENDPOINT_SERVER=false',
                '-e', 'SECRET_HUB_MACHINE_ENDPOINT_SERVER=false',
                '-e', 'SECRET_HUB_ADMIN_ENDPOINT_SERVER=false']
        for source, target in ((self.config['fixture_socket_dir'], '/socket'),
                               (self.config['core_input_dir'], self.config['core_input_mount'])):
            args += ['--mount', 'type=bind,src=' + source + ',dst=' + target + ',readonly']
        args += ['--entrypoint', '/app/bin/secrethub_core', self.config['core_image_id'], 'eval', EVAL]
        # Track before create, including daemon-side creation after a local CLI failure.
        self.name, self.cleanup_confirmed = name, False
        try:
            self.command(args)
            result = self.command(['docker', 'start', '--attach', '--interactive', name],
                                  json.dumps({'shares': self.shares}).encode(), timeout=90)
            return safe_result(result.stdout)
        finally:
            self.cleanup()

    def run(self):
        started = time.monotonic()
        passed, observations = False, {}
        stage = 'artifact_inspection'
        try:
            self.artifacts()
            stage = 'quiescence'
            self.quiesced()
            stage = 'worker_health_lifecycle'
            observations = self.evaluate()
            passed = True
        except Exception:
            observations = {'failure_stage': stage, 'error_code': 'worker_health_check_failed'}
        finally:
            if self.name is not None:
                try:
                    self.cleanup()
                except Exception:
                    passed = False
        raw = b'\n'.join(self.diagnostics)
        redacted = not any(value in raw for value in sensitive_strings(self.shares))
        passed = passed and self.cleanup_confirmed and redacted
        report = {key: self.config[key] for key in ('source_sha', 'platform', 'core_image_id', 'agent_image_id')}
        report.update(complete=False, provisional=True, recovery_hold=True,
                      selected_checks='passed' if passed else 'failed',
                      observed_at=datetime.now(timezone.utc).isoformat(), results=observations,
                      gates={'G20': {'status': 'partial', 'selected_worker_checks': 'passed' if passed else 'failed',
                                     'alert_delivery': 'unexecuted'}}, monitoring='partial',
                      management_availability='internal Health API only; protected HTTP/Caddy unexecuted',
                      agent_executed=False, cleanup_confirmed=self.cleanup_confirmed,
                      diagnostics_redacted=redacted, diagnostics_sha256=hashlib.sha256(raw).hexdigest(),
                      copied_database_mutations='manual-unseal audit, cluster bookkeeping, normal CRL reconciliation; retained',
                      original_fixture_modifications=False, seconds=round(time.monotonic() - started, 3))
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='owner-only copied-fixture config outside checkout')
    parser.add_argument('--shares-file', required=True, help='independently held owner-only JSON shares outside copied fixture')
    parser.add_argument('--output', required=True, help='new private JSON report beside config')
    args = parser.parse_args()
    try:
        checkout = Path(__file__).resolve().parents[2]
        checkout = next((parent.parent for parent in checkout.parents if parent.name == '.trees'), checkout)
        config_path, shares_path = map(lambda path: private_file(no_symlinks(path)), (args.config, args.shares_file))
        require(config_path != shares_path and all(not path.is_relative_to(checkout) for path in (config_path, shares_path)))
        config = validate_worker_config(json.loads(config_path.read_text()), checkout)
        require(not shares_path.is_relative_to(Path(config['fixture_root'])))
        shares = json.loads(shares_path.read_text())
        require(isinstance(shares, list) and 0 < len(shares) <= 255)
        require(all(isinstance(item, str) and 0 < len(item) <= 8192 for item in shares))
        require(len(shares) == len(set(shares)))
        output = no_symlinks(args.output)
        require(output.parent.resolve() == config_path.parent and not output.exists())
        report = WorkerHealthHarness(config, shares).run()
        private_json(output, report)
        print('G20: partial; alerts: unexecuted; complete: false; selected checks: ' + report['selected_checks'])
        return 0 if report['selected_checks'] == 'passed' else 1
    except Exception:
        print('worker health harness failed; private diagnostic detail withheld')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
