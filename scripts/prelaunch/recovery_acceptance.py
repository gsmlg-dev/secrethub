#!/usr/bin/env python3
"""Partial restore evidence only; never reopens issuance or consumers."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import parse_qs, urlsplit
import uuid

from acceptance import CheckFailed, private_json, require


CHECKS = {'worker_stopped_before_unseal', 'worker_absent_after_reads',
          'no_web_apps_or_listeners', 'loaded_sealed', 'manual_unseal',
          'static_secret_matches', 'historical_audit_valid', 'client_auth_key_usable', 'core_service_uid'}
TABLES = ('vault_config', 'client_auth_authorities', 'client_auth_crls',
          'certificates', 'client_auth_identities', 'client_auth_issuance_requests',
          'client_auth_bundle_receipts')

# All private inputs arrive on stdin; this program is constant, including on failure.
EVAL = r'''try do
  {:ok, _} = Application.ensure_all_started(:secrethub_core)
  :ok = Supervisor.terminate_child(SecretHub.Core.Supervisor,
    SecretHub.Core.Workers.ClientAuthCRLRefresher)
  {"1001\n", 0} = System.cmd("id", ["-u"])
  absent = fn ->
    is_nil(Process.whereis(SecretHub.Core.Workers.ClientAuthCRLRefresher)) and
      Enum.all?(Supervisor.which_children(SecretHub.Core.Supervisor), fn {id, pid, _, _} ->
        id != SecretHub.Core.Workers.ClientAuthCRLRefresher or pid == :undefined
      end)
  end
  true = absent.()
  isolated = fn ->
    apps = Application.started_applications() |> Enum.map(&elem(&1, 0))
    no_apps = Enum.all?([:secrethub_web, :secrethub_agent, :secrethub_human], &(&1 not in apps))
    no_inet = Enum.all?(~w(tcp tcp6 udp udp6), fn protocol ->
      File.read!("/proc/net/" <> protocol) |> String.split("\n", trim: true) |> length() == 1
    end)
    no_apps and no_inet
  end
  true = isolated.()
  wait = fn wait, deadline ->
    status = SecretHub.Core.Vault.SealState.status()
    if status.state == :sealed and status.initialized do
      status
    else
      true = System.monotonic_time(:millisecond) < deadline
      Process.sleep(100)
      wait.(wait, deadline)
    end
  end
  status = wait.(wait, System.monotonic_time(:millisecond) + 15000)
  true = status.sealed and not status.recovery_required
  input = Jason.decode!(IO.read(:stdio, :eof))
  shares = input["shares"]
  true = is_list(shares) and length(shares) >= status.threshold
  for encoded <- Enum.take(shares, status.threshold) do
    {:ok, share} = SecretHub.Shared.Crypto.Shamir.decode_share(encoded)
    {:ok, _} = SecretHub.Core.Vault.SealState.unseal(share)
  end
  unsealed = SecretHub.Core.Vault.SealState.status().state == :unsealed
  true = unsealed
  {:ok, data, _} = SecretHub.Core.Secrets.read_decrypted(input["expected"]["secret_path"])
  secret_ok = data == input["expected"]["secret_data"]
  audit_ok = SecretHub.Core.Audit.verify_chain() == {:ok, :valid}
  {:ok, material} = SecretHub.Core.PKI.ClientAuth.get_active_ca_and_key()
  cert = X509.Certificate.from_pem!(material.ca_certificate.certificate_pem)
  challenge = :crypto.strong_rand_bytes(32)
  signature = :public_key.sign(challenge, :sha256, material.ca_key)
  key_ok = :public_key.verify(challenge, :sha256, signature, X509.Certificate.public_key(cert))
  true = absent.() and isolated.()
  IO.puts("RECOVERY_RESULT=" <> Jason.encode!(%{
    core_service_uid: true, worker_stopped_before_unseal: true, worker_absent_after_reads: absent.(),
    no_web_apps_or_listeners: isolated.(), loaded_sealed: true,
    manual_unseal: unsealed, static_secret_matches: secret_ok,
    historical_audit_valid: audit_ok, client_auth_key_usable: key_ok}))
rescue
  _ -> IO.puts("RECOVERY_RESULT=false")
catch
  _, _ -> IO.puts("RECOVERY_RESULT=false")
end'''


def private_file(path):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink())
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid())
    require(info.st_mode & 0o077 == 0 and info.st_size <= 1_000_000)
    return path.resolve()


def safe_result(stdout):
    lines = [line[16:] for line in stdout.decode().splitlines()
             if line.startswith('RECOVERY_RESULT=')]
    require(len(lines) == 1)
    result = json.loads(lines[0])
    require(isinstance(result, dict) and set(result) == CHECKS)
    require(all(type(value) is bool for value in result.values()))
    return result


def sensitive_strings(value):
    if isinstance(value, str):
        return [value.encode()] if value else []
    if isinstance(value, dict):
        return [item for part in value.values() for item in sensitive_strings(part)]
    if isinstance(value, list):
        return [item for part in value for item in sensitive_strings(part)]
    return []


def diagnostics_redacted(diagnostics, shares, expected):
    # Raw output is never exported even when this conservative check fails.
    return not any(value in diagnostics for value in
                   sensitive_strings(shares) + sensitive_strings(expected['secret_data']))


def validate_config(config, checkout):
    require(config.get('isolated_fixture') is True)
    prefix = config['fixture_prefix']
    require(re.fullmatch(r'secrethub-prelaunch-[a-z0-9-]+', prefix) is not None)
    require(config['fixture_postgres_container'].startswith(prefix))
    require(re.fullmatch(r'[a-z0-9_]+', config['fixture_database']) is not None)
    require(config['fixture_database'].startswith('secrethub_prelaunch_'))
    require(re.fullmatch(r'[a-z0-9_]+', config.get('fixture_postgres_user', 'secrethub')) is not None)
    require(config.get('fixture_postgres_socket', '/socket') == '/socket')
    require(config['platform'] == 'linux/amd64')
    require(re.fullmatch(r'[0-9a-f]{40}', config['source_sha']) is not None)
    for role in ('core', 'agent'):
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', config[role + '_image_id']) is not None)
    require(type(config.get('provisional', False)) is bool)
    for key in ('retained_consumer_generation', 'retained_consumer_crl_number'):
        require(type(config[key]) is int and config[key] >= 0)
    root = Path(config['fixture_root']).resolve(strict=True)
    require(root.is_dir() and root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0)
    require(not root.is_relative_to(checkout) and not checkout.is_relative_to(root))
    for key in ('fixture_socket_dir', 'core_input_dir', 'core_env_file'):
        path = Path(config[key])
        require(path.is_absolute() and not path.is_symlink())
        path = path.resolve(strict=True)
        require(path.is_relative_to(root) and ',' not in str(path))
        config[key] = str(path)
    require(Path(config['fixture_socket_dir']).is_dir() and Path(config['core_input_dir']).is_dir())
    require(stat.S_ISSOCK((Path(config['fixture_socket_dir']) / '.s.PGSQL.5432').stat().st_mode))
    env_file = private_file(config['core_env_file'])
    mount = config.get('core_input_mount', '/prelaunch-input')
    require(re.fullmatch(r'/[a-zA-Z0-9_-]+', mount) is not None and mount not in ('/socket', '/app', '/tmp'))
    environment = {}
    for line in env_file.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, value = line.split('=', 1)
        require(re.fullmatch(r'[A-Z][A-Z0-9_]*', key) is not None and key not in environment)
        require(value and '\x00' not in value)
        environment[key] = value
    for key, value in environment.items():
        if key.endswith('_FILE'):
            require(key[:-5] not in environment and value.startswith(mount + '/'))
            relative = Path(value).relative_to(mount)
            require('..' not in relative.parts)
            host_file = Path(config['core_input_dir']) / relative
            require(not host_file.is_symlink() and host_file.resolve().is_relative_to(Path(config['core_input_dir'])))
            require(host_file.is_file() and host_file.stat().st_size <= 4096)
    db_url = environment.get('DATABASE_URL')
    if 'DATABASE_URL_FILE' in environment:
        db_url = (Path(config['core_input_dir']) / Path(environment['DATABASE_URL_FILE']).relative_to(mount)).read_text().rstrip('\r\n')
    require(isinstance(db_url, str))
    uri = urlsplit(db_url)
    require(uri.scheme in ('postgres', 'postgresql') and uri.hostname == 'localhost')
    require(uri.path == '/' + config['fixture_database'] and uri.username == config.get('fixture_postgres_user', 'secrethub'))
    require(uri.port in (None, 5432) and parse_qs(uri.query) == {'socket_dir': ['/socket']})
    config['core_input_mount'] = mount
    return config


class RecoveryHarness:
    def __init__(self, config, shares, expected):
        self.config, self.shares, self.expected = config, shares, expected
        self.diagnostics = []
        self.name = None
        self.cleanup_confirmed = True

    def command(self, args, payload=None, timeout=30, check=True):
        try:
            result = subprocess.run(args, input=payload, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.diagnostics.append((error.stdout or b'') + (error.stderr or b''))
            raise CheckFailed() from None
        self.diagnostics.append(result.stdout + result.stderr)
        if check:
            require(result.returncode == 0)
        return result

    def artifacts(self):
        for role, uid in (('core', '1001'), ('agent', '1002')):
            info = json.loads(self.command(['docker', 'image', 'inspect', self.config[role + '_image_id']]).stdout)[0]
            require(info['Id'] == self.config[role + '_image_id'])
            require(info['Os'] + '/' + info['Architecture'] == self.config['platform'])
            users = (uid, uid + ':' + uid, 'secrethub')
            require(info['Config']['User'] in users)
            if not self.config.get('provisional', False):
                labels = info['Config'].get('Labels') or {}
                require(labels.get('org.opencontainers.image.revision') == self.config['source_sha'])
                require(labels.get('org.opencontainers.image.source') == 'https://github.com/gsmlg-dev/secrethub')
                require(labels.get('org.opencontainers.image.licenses') == 'MIT')

        database = json.loads(self.command(['docker', 'inspect', self.config['fixture_postgres_container']]).stdout)[0]
        require(database['State']['Running'] is True)
        require(any(mount['Type'] == 'bind' and mount['Destination'] == '/socket' and
                    Path(mount['Source']).resolve() == Path(self.config['fixture_socket_dir'])
                    for mount in database['Mounts']))

    def query(self, sql):
        args = ['docker', 'exec', '-i', self.config['fixture_postgres_container'],
                'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-h', '/socket',
                '-U', self.config.get('fixture_postgres_user', 'secrethub'), '-d', self.config['fixture_database']]
        payload = ('BEGIN READ ONLY; SET LOCAL statement_timeout = 20000; ' + sql + '; COMMIT;').encode()
        return json.loads(self.command(args, payload).stdout)

    def snapshot(self, audit_sequence=None):
        pairs = ["'%s', (SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id), '[]') FROM %s t)" % (table, table)
                 for table in TABLES]
        limit = '' if audit_sequence is None else ' WHERE sequence_number <= ' + str(audit_sequence)
        pairs.append("'audit', (SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY sequence_number), '[]') FROM audit_logs t" + limit + ')')
        return self.query('SELECT jsonb_build_object(' + ','.join(pairs) + ')')

    def cleanup(self):
        if self.name is not None:
            # Remove only the unique container created by this invocation. Never DB/state.
            info = json.loads(self.command(['docker', 'inspect', self.name]).stdout)[0]
            require((info['Config'].get('Labels') or {}).get('secrethub.prelaunch.owner') == self.name)
            result = self.command(['docker', 'rm', '-f', self.name], check=False)
            require(result.returncode == 0)
            self.cleanup_confirmed = True
            self.name = None

    def evaluate(self):
        self.name = self.config['fixture_prefix'] + '-recovery-' + uuid.uuid4().hex[:12]
        require(not self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + self.name + '$', '--format', '{{.Names}}']).stdout.strip())
        args = ['docker', 'run', '--rm', '--name', self.name, '--label', 'secrethub.prelaunch.owner=' + self.name, '--network', 'none',
                '--user', '1001:1001', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--no-healthcheck', '-i',
                '--tmpfs', '/app/tmp:rw,noexec,nosuid,uid=1001,gid=1001,mode=700',
                '--env-file', self.config['core_env_file'],
                '-e', 'RELEASE_DISTRIBUTION=none', '-e', 'ERL_CRASH_DUMP=/dev/null',
                '-e', 'SECRETHUB_ROLE=core', '-e', 'PHX_SERVER=',
                '-e', 'SECRET_HUB_AGENT_ENDPOINT_SERVER=false',
                '-e', 'SECRET_HUB_MACHINE_ENDPOINT_SERVER=false',
                '-e', 'SECRET_HUB_ADMIN_ENDPOINT_SERVER=false']
        for source, target in ((self.config['fixture_socket_dir'], '/socket'),
                               (self.config['core_input_dir'], self.config['core_input_mount'])):
            args += ['--mount', 'type=bind,src=' + source + ',dst=' + target + ',readonly']
        args += ['--entrypoint', '/app/bin/secrethub_core', self.config['core_image_id'], 'eval', EVAL]
        self.cleanup_confirmed = False
        try:
            result = self.command(args, json.dumps({'shares': self.shares, 'expected': self.expected}).encode(), timeout=90)
            return safe_result(result.stdout)
        finally:
            # --rm already removed a normally exited container. Absence must be confirmed.
            remaining = self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + self.name + '$', '--format', '{{.Names}}'])
            if remaining.stdout.strip():
                self.cleanup()
            else:
                self.cleanup_confirmed = True
                self.name = None

    def run(self):
        report = {key: self.config[key] for key in ('core_image_id', 'agent_image_id', 'source_sha', 'platform')}
        report.update(complete=False, candidate_status='provisional' if self.config.get('provisional', False) else 'pending_acceptance',
                      created_at=datetime.now(timezone.utc).isoformat(),
                      gates={'G16': {'status': 'partial', 'full_agent_consumer_reconnect': 'unexecuted'},
                             'G17': {'status': 'partial', 'authoritative_reconciliation': 'unexecuted',
                                     'old_bundle_consumer_verification': 'unexecuted'}},
                      commands=['one isolated Core release eval with stdin recovery inputs; read-only PostgreSQL inventory queries'],
                      recovery_hold=True, agent_metadata_validated=False, agent_executed=False,
                      retained_consumer_counter_source='operator-supplied configuration; not independently inspected',
                      live_consumer_watermarks_verified=False,
                      agent_default_numeric_uid_proof='unexecuted_in_this_drill', checks={})
        started = time.monotonic()
        try:
            self.artifacts()
            report['agent_metadata_validated'] = True
            before = self.snapshot()
            require(len(before['vault_config']) == 1 and len(before['client_auth_authorities']) == 1 and before['audit'])
            sequence = max(row['sequence_number'] for row in before['audit'])
            try:
                checks = self.evaluate()
                evaluation_completed = True
            except Exception:
                checks = {}
                evaluation_completed = False
            after = self.snapshot(sequence)
            unchanged = before == after
            vault, authority = before['vault_config'][0], before['client_auth_authorities'][0]
            behind = (authority['current_generation'] < self.config['retained_consumer_generation'] or
                      authority['current_crl_number'] < self.config['retained_consumer_crl_number'])
            checks.update(evaluation_completed=evaluation_completed, vault_pki_inventory_unchanged=unchanged, historical_audit_rows_unchanged=before['audit'] == after['audit'],
                          older_than_retained_consumer=behind)
            report['checks'] = checks
            report['inventory'] = {key: vault[key] for key in ('envelope_version', 'share_version', 'threshold', 'total_shares')}
            report['inventory'].update(publication_generation=authority['current_generation'], crl_number=authority['current_crl_number'],
                                       retained_consumer_generation=self.config['retained_consumer_generation'],
                                       retained_consumer_crl_number=self.config['retained_consumer_crl_number'],
                                       historical_audit_rows=len(before['audit']), certificates=len(before['certificates']),
                                       revoked_certificates=sum(row['revoked'] is True for row in before['certificates']))
            report['inventory_sha256'] = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
            report['after_inventory_sha256'] = hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()
            require(all(checks.values()))
            report['partial_checks_passed'] = True
        except Exception:
            report.update(partial_checks_passed=False, error_code='recovery_check_failed')
        report['cleanup_confirmed'] = self.cleanup_confirmed
        raw = b'\n'.join(self.diagnostics)
        report['diagnostics_sha256'] = hashlib.sha256(raw).hexdigest()
        report['diagnostics_redacted'] = diagnostics_redacted(raw, self.shares, self.expected)
        report['seconds'] = round(time.monotonic() - started, 3)
        report['partial_checks_passed'] = report.get('partial_checks_passed', False) and report['diagnostics_redacted'] and self.cleanup_confirmed
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--shares-file', required=True)
    parser.add_argument('--expected-file', required=True)
    parser.add_argument('--output', required=True, help='new private JSON report path')
    args = parser.parse_args()
    try:
        config_path, shares_path, expected_path = map(private_file, (args.config, args.shares_file, args.expected_file))
        require(len({config_path, shares_path, expected_path}) == 3)
        checkout = Path(__file__).resolve().parents[2]
        checkout = next((parent.parent for parent in checkout.parents if parent.name == '.trees'), checkout)
        require(all(not path.is_relative_to(checkout) for path in (config_path, shares_path, expected_path)))
        config = validate_config(json.loads(config_path.read_text()), checkout)
        shares, expected = json.loads(shares_path.read_text()), json.loads(expected_path.read_text())
        require(isinstance(shares, list) and len(shares) > 0 and all(isinstance(item, str) and item for item in shares))
        require(isinstance(expected, dict) and set(expected) == {'secret_path', 'secret_data'})
        require(isinstance(expected['secret_path'], str) and expected['secret_path'] and isinstance(expected['secret_data'], dict))
        require(bool(sensitive_strings(expected['secret_data'])))
        output = Path(args.output).absolute()
        require(output.parent.resolve() == config_path.parent and not output.exists() and not output.is_symlink())
        report = RecoveryHarness(config, shares, expected).run()
        private_json(output, report)
        print('G16: partial; G17: partial; complete: false; partial checks: ' + ('passed' if report['partial_checks_passed'] else 'failed'))
        return 0 if report['partial_checks_passed'] else 1
    except Exception:
        print('recovery harness failed; private diagnostic detail withheld')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
