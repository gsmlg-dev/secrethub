#!/usr/bin/env python3
"""Partial G17 evidence from an old restored DB and retained PKI history."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import time
import uuid

from acceptance import CheckFailed, private_json, require
from pki_acceptance import PKIHarness
from recovery_acceptance import EVAL, RecoveryHarness, private_file, validate_config


# Reuse the reviewed immediate-worker-stop, UID, isolation and sealed-load boot.
SEALED_EXPORT = EVAL.partition('  input = Jason.decode!')[0] + r'''
  {:ok, bundle} = SecretHub.Core.PKI.ClientAuth.current_bundle()
  true = absent.() and isolated.() and SecretHub.Core.Vault.SealState.sealed?()
  IO.puts("HISTORY_PRIVATE=" <> Jason.encode!(bundle))
rescue
  _ -> IO.puts("HISTORY_PRIVATE=false")
catch
  _, _ -> IO.puts("HISTORY_PRIVATE=false")
end'''

INSPECT = r'''try do
  Application.ensure_all_started(:crypto)
  Application.ensure_all_started(:x509)
  input = Jason.decode!(IO.read(:stdio, :eof))
  base = "/state/bundle"
  {:ok, retained} = SecretHub.Agent.PKI.BundleValidator.validate_disk_bundle(base)
  wm_raw = File.read!(base <> "/watermark.json")
  {:ok, current} = File.read_link(base <> "/current")
  bundle = File.read!(base <> "/current/manifest.json") |> Jason.decode!()
    |> Map.put("ca_bundle_pem", retained.ca_bundle_pem)
    |> Map.put("crl_pem", retained.crl_pem)
  {:ok, old} = SecretHub.Agent.PKI.BundleValidator.validate(input["old_bundle"],
    pinned_ca_fingerprint: retained.ca_fingerprint)
  client = X509.Certificate.from_pem!(input["client_certificate"])
  control = X509.Certificate.from_pem!(input["control_certificate"])
  serials = fn crl -> X509.CRL.list(crl) |> Enum.map(&X509.CRL.Entry.serial/1) end
  current_serials = serials.(retained.parsed_crl)
  old_serials = serials.(old.parsed_crl)
  digest = fn value -> Base.encode16(:crypto.hash(:sha256, value), case: :lower) end
  watermarks = for kind <- ~w(tls http), into: %{} do
    raw = File.read!("/state/" <> kind <> "-watermark.json")
    {kind, %{metadata: Jason.decode!(raw), sha256: digest.(raw)}}
  end
  IO.puts("HISTORY_PRIVATE=" <> Jason.encode!(%{
    bundle: bundle, manager_watermark: Jason.decode!(wm_raw),
    manager_watermark_sha256: digest.(wm_raw), current_sha256: digest.(current),
    consumer_watermarks: watermarks,
    checks: %{old_signed_crl_valid_now: true, retained_signed_crl_valid_now: true,
      same_original_ca: old.ca_fingerprint == retained.ca_fingerprint,
      client_revoked_in_retained_crl: X509.Certificate.serial(client) in current_serials,
      client_not_revoked_in_old_crl: X509.Certificate.serial(client) not in old_serials,
      control_not_revoked: X509.Certificate.serial(control) not in current_serials}}))
rescue
  _ -> IO.puts("HISTORY_PRIVATE=false")
catch
  _, _ -> IO.puts("HISTORY_PRIVATE=false")
end'''


def private_result(raw):
    marker = 'HISTORY_PRIVATE='
    lines = [line[len(marker):] for line in raw.decode().splitlines() if line.startswith(marker)]
    require(len(lines) == 1)
    value = json.loads(lines[0])
    require(isinstance(value, dict))
    return value


def counters(watermark):
    result = {key: watermark[key] for key in ('highest_seen_generation', 'highest_seen_crl_number')}
    require(all(type(value) is int and value > 0 for value in result.values()))
    for key in ('pinned_ca_fingerprint', 'last_bundle_sha256'):
        require(re.fullmatch(r'[0-9a-f]{64}', watermark[key]) is not None)
        result[key] = watermark[key]
    return result


def replay_preserved(before, positive, rejected):
    return (positive.get('ok') is True and rejected.get('ok') is False and
            rejected.get('error') == 'generation_downgrade_rejected' and
            positive.get('watermark_sha256') == rejected.get('watermark_sha256') == before['manager_watermark_sha256'] and
            positive.get('current') == rejected.get('current') and
            hashlib.sha256(positive['current'].encode()).hexdigest() == before['current_sha256'])


class HistoryCore(RecoveryHarness):
    def export(self):
        self.name = self.config['fixture_prefix'] + '-history-core-' + uuid.uuid4().hex[:12]
        require(not self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + self.name + '$', '--format', '{{.Names}}']).stdout.strip())
        args = ['docker', 'run', '--rm', '--name', self.name, '--label', 'secrethub.prelaunch.owner=' + self.name,
                '--network', 'none', '--user', '1001:1001', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--no-healthcheck',
                '--tmpfs', '/app/tmp:rw,noexec,nosuid,uid=1001,gid=1001,mode=700',
                '--env-file', self.config['core_env_file'], '-e', 'RELEASE_DISTRIBUTION=none',
                '-e', 'ERL_CRASH_DUMP=/dev/null', '-e', 'SECRETHUB_ROLE=core', '-e', 'PHX_SERVER=',
                '-e', 'SECRET_HUB_AGENT_ENDPOINT_SERVER=false', '-e', 'SECRET_HUB_MACHINE_ENDPOINT_SERVER=false',
                '-e', 'SECRET_HUB_ADMIN_ENDPOINT_SERVER=false']
        for source, target in ((self.config['fixture_socket_dir'], '/socket'),
                               (self.config['core_input_dir'], self.config['core_input_mount'])):
            args += ['--mount', 'type=bind,src=' + source + ',dst=' + target + ',readonly']
        args += ['--entrypoint', '/app/bin/secrethub_core', self.config['core_image_id'], 'eval', SEALED_EXPORT]
        self.cleanup_confirmed = False
        try:
            return private_result(self.command(args, timeout=45).stdout)
        finally:
            remaining = self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + self.name + '$', '--format', '{{.Names}}'])
            if remaining.stdout.strip():
                self.cleanup()
            else:
                self.cleanup_confirmed, self.name = True, None


class HistoryHarness(PKIHarness):
    def __init__(self, recovery_config, pki_config, output):
        # Skip PKIHarness constructor/execute: both perform unrelated API operations.
        self.config = pki_config
        require(pki_config.get('isolated_fixture') is True)
        require(pki_config.get('provisional', False) == recovery_config.get('provisional', False))
        for key in ('core_image_id', 'agent_image_id', 'source_sha', 'platform'):
            require(pki_config[key] == recovery_config[key])
        self.output = Path(output).absolute()
        require(not self.output.exists() and not self.output.is_symlink())
        self.output.mkdir(mode=0o700, parents=True)
        self.volume = pki_config['history_retained_volume']
        require(re.fullmatch(r'secrethub-prelaunch-pki-[0-9a-f]{12}', self.volume) is not None)
        self.identifier = self.volume.rsplit('-', 1)[1]
        self.consumer = self.volume + '-history-' + uuid.uuid4().hex[:8]
        self.active_containers, self.diagnostics = set(), []
        self.live_bundle_dir = None  # Never bind the live Agent's bundle directory.
        source_fixture = Path(pki_config['history_consumer_fixture_dir'])
        require(source_fixture.is_absolute() and not source_fixture.is_symlink())
        self.source_fixture = source_fixture.resolve(strict=True)
        require(self.source_fixture.name == 'consumer.private')
        require(self.source_fixture.parent.stat().st_uid == os.getuid() and self.source_fixture.parent.stat().st_mode & 0o077 == 0)
        prior = json.loads((self.source_fixture.parent / 'report.json').read_text())
        require(prior['retained_monotonic_fixture_volume'] == self.volume)
        require(prior['source_sha'] == pki_config['source_sha'])
        for key in ('core_image_id', 'agent_image_id'):
            require(prior['artifacts'][key] == pki_config[key])
        self.caddy = Path(pki_config['pki_caddy_binary']).resolve(strict=True)
        self.carrier = pki_config['pki_caddy_carrier_image_id']
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', self.carrier) is not None)
        require(hashlib.sha256(self.caddy.read_bytes()).hexdigest() == prior['artifacts']['caddy_sha256'])
        require(self.carrier == prior['artifacts']['caddy_carrier_image_id'])
        self.runtime_paths = pki_config.get('pki_caddy_runtime_paths', [])
        require(all(re.fullmatch(r'/nix/store/[a-z0-9]{32}-[A-Za-z0-9.+_-]+', path) and Path(path).is_dir() for path in self.runtime_paths))
        self.port = pki_config['pki_consumer_port']
        require(type(self.port) is int and 1024 <= self.port <= 65535)
        self.fixture = self.output / 'consumer.private'
        self.fixture.mkdir(mode=0o755)
        for name in ('server.crt', 'server.key'):
            path = self.source_fixture / name
            require(path.is_file() and not path.is_symlink())
            (self.fixture / name).write_bytes(path.read_bytes())
            (self.fixture / name).chmod(0o644)
        self.core = HistoryCore(recovery_config, [], {})

    def context(self, kind):
        context = ssl.create_default_context(cafile=str(self.source_fixture / 'server.crt'))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.source_fixture / (kind + '.crt')), str(self.source_fixture / (kind + '.key')))
        return context

    def inspect_history(self, old):
        name = self.volume + '-history-inspect-' + uuid.uuid4().hex[:8]
        self.active_containers.add(name)
        payload = {'old_bundle': old, 'client_certificate': (self.source_fixture / 'client.crt').read_text(),
                   'control_certificate': (self.source_fixture / 'control.crt').read_text()}
        try:
            raw = self.run_command(['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none', '-i',
                '-e', 'SECRET_HUB_AGENT_CORE_URL=' + self.config['management_origin'],
                '-e', 'SECRET_HUB_AGENT_HOST_KEY_PATH=/state/unused-host-key',
                '-e', 'SECRET_HUB_AGENT_STATE_DIR=/state/agent', '-e', 'SECRET_HUB_AGENT_SOCKET_PATH=/state/unused.sock',
                '-e', 'SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR=/state/bundle', '-v', self.volume + ':/state:ro',
                self.config['agent_image_id'], 'eval', INSPECT], json.dumps(payload).encode())
        finally:
            self.remove_container(name)
        return private_result(raw)

    def execute_history(self):
        self.core.artifacts()
        self.run_command(['docker', 'volume', 'inspect', self.volume])  # Never implicitly create a missing trust volume.
        carrier = json.loads(self.run_command(['docker', 'image', 'inspect', self.carrier]))[0]
        require(carrier['Os'] + '/' + carrier['Architecture'] == self.config['platform'])
        before_db = self.core.snapshot()
        try:
            old = self.core.export()
        finally:
            require(before_db == self.core.snapshot())
        for kind in ('client', 'control', 'server'):
            cert = self.source_fixture / (kind + '.crt')
            require(cert.is_file() and not cert.is_symlink())
            self.run_command(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '180'])
        before = self.inspect_history(old)
        require(set(before['checks']) == {'old_signed_crl_valid_now', 'retained_signed_crl_valid_now',
            'same_original_ca', 'client_revoked_in_retained_crl', 'client_not_revoked_in_old_crl', 'control_not_revoked'})
        require(all(type(value) is bool and value for value in before['checks'].values()))
        retained = before['bundle']
        manager = counters(before['manager_watermark'])
        require(manager['highest_seen_generation'] == retained['generation'] > old['generation'])
        require(manager['highest_seen_crl_number'] == retained['crl_number'] > old['crl_number'])
        require(manager['pinned_ca_fingerprint'] == retained['ca_fingerprint'] == old['ca_fingerprint'])
        require(manager['last_bundle_sha256'] == retained['bundle_sha256'])
        consumer_before = {kind: counters(value['metadata']) for kind, value in before['consumer_watermarks'].items()}
        require(set(consumer_before) == {'tls', 'http'})
        for watermark in consumer_before.values():
            require(watermark['pinned_ca_fingerprint'] == retained['ca_fingerprint'])
            require(old['generation'] < watermark['highest_seen_generation'] <= retained['generation'] and
                    old['crl_number'] < watermark['highest_seen_crl_number'] <= retained['crl_number'])
        (self.fixture / 'ca.crt').write_text(retained['ca_bundle_pem'])
        self.run_command(['openssl', 'verify', '-CAfile', str(self.fixture / 'ca.crt'), '-purpose', 'sslclient',
                          str(self.source_fixture / 'client.crt'), str(self.source_fixture / 'control.crt')])
        positive = self.agent(retained)
        rejected = self.agent(old)
        require(replay_preserved(before, positive, rejected))
        self.valid_context = self.context('control')  # Consumer startup must use the unrevoked control.
        self.start_consumer(retained)
        require(self.request(self.context('client'))[0] != 200)
        require(self.request(self.valid_context)[0] == 200)
        for kind in ('client', 'control', 'server'):
            self.run_command(['openssl', 'x509', '-in', str(self.source_fixture / (kind + '.crt')),
                              '-noout', '-checkend', '0'])
        after = self.inspect_history(old)
        require(after['manager_watermark_sha256'] == before['manager_watermark_sha256'] and after['current_sha256'] == before['current_sha256'])
        consumer_after = {kind: counters(value['metadata']) for kind, value in after['consumer_watermarks'].items()}
        require(set(consumer_after) == {'tls', 'http'})
        for kind, watermark in consumer_after.items():
            require(watermark['highest_seen_generation'] == retained['generation'] >= consumer_before[kind]['highest_seen_generation'])
            require(watermark['highest_seen_crl_number'] == retained['crl_number'] >= consumer_before[kind]['highest_seen_crl_number'])
            require(watermark['last_bundle_sha256'] == retained['bundle_sha256'] and watermark['pinned_ca_fingerprint'] == retained['ca_fingerprint'])
        require(before_db == self.core.snapshot())
        return {'restored_generation': old['generation'], 'restored_crl_number': old['crl_number'],
                'retained_manager': manager, 'consumer_before': consumer_before, 'consumer_after': consumer_after,
                'old_bundle_sha256': old['bundle_sha256'], 'retained_bundle_sha256': retained['bundle_sha256'],
                'old_bundle_rejected': True, 'manager_watermark_and_current_preserved': True,
                'restored_vault_pki_audit_unchanged': True, 'revoked_denied': True, 'unrevoked_control_allowed': True,
                'leaf_expiry_and_signed_crl_membership_checked': True}

    def run(self):
        report = {key: self.config[key] for key in ('core_image_id', 'agent_image_id', 'source_sha', 'platform')}
        report.update(complete=False, recovery_hold=True, created_at=datetime.now(timezone.utc).isoformat(),
            provisional=self.config.get('provisional') is True, selected_checks_passed=False,
            caddy_sha256=hashlib.sha256(self.caddy.read_bytes()).hexdigest(), caddy_carrier_image_id=self.carrier,
            retained_volume=self.volume, counter_provenance='artifact process reads of retained manager and independent TLS/HTTP consumer files',
            gates={'G17': {'status': 'partial', 'authoritative_reconciliation': 'unexecuted', 'full_service_reopen': 'unexecuted'}},
            commands=['isolated sealed Core current_bundle export; read-only DB inventory',
                      'artifact manager same/old-bundle processing with retained trust state',
                      'retained-volume Caddy TLS requests using prior revoked and control leaves'])
        started = time.monotonic()
        try:
            report['observations'] = self.execute_history()
            report['selected_checks_passed'] = True
        except Exception:
            report['error_code'] = 'history_check_failed'
        finally:
            for name in list(self.active_containers):
                try:
                    self.remove_container(name)
                except Exception:
                    report['selected_checks_passed'] = False
            report['cleanup_confirmed'] = not self.active_containers and self.core.cleanup_confirmed
        raw = b'\n'.join(self.diagnostics + self.core.diagnostics)
        report['diagnostics_sha256'] = hashlib.sha256(raw).hexdigest()
        report['diagnostics_redacted'] = not any(marker in raw for marker in
            (b'-----BEGIN PRIVATE KEY', b'-----BEGIN EC PRIVATE KEY', b'-----BEGIN RSA PRIVATE KEY', b'-----BEGIN OPENSSH PRIVATE KEY'))
        report['selected_checks_passed'] &= report['diagnostics_redacted'] and report['cleanup_confirmed']
        report['seconds'] = round(time.monotonic() - started, 3)
        private_json(self.output / 'report.json', report)
        print('G17: partial; complete: false; selected checks: ' + ('passed' if report['selected_checks_passed'] else 'failed'))
        return 0 if report['selected_checks_passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recovery-config', required=True)
    parser.add_argument('--pki-config', required=True)
    parser.add_argument('--output', required=True, help='new private result directory')
    args = parser.parse_args()
    try:
        checkout = Path(__file__).resolve().parents[2]
        checkout = next((parent.parent for parent in checkout.parents if parent.name == '.trees'), checkout)
        recovery_path, pki_path = map(private_file, (args.recovery_config, args.pki_config))
        require(not recovery_path.is_relative_to(checkout) and not pki_path.is_relative_to(checkout))
        recovery = validate_config(json.loads(recovery_path.read_text()), checkout)
        pki = json.loads(pki_path.read_text())
        output = Path(args.output).absolute()
        require(not output.resolve().is_relative_to(checkout) and output.parent.resolve() == pki_path.parent)
        return HistoryHarness(recovery, pki, output).run()
    except Exception:
        print('history harness failed; private diagnostic detail withheld')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
