#!/usr/bin/env python3
"""Partial G15: copy-only disk damage, real Caddy enforcement, gated recovery."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid

from acceptance import CheckFailed, private_json, require
from history_acceptance import HistoryHarness, counters
from recovery_acceptance import private_file


MARKER = 'CORRUPTION_PRIVATE='
CORRUPT_CRL_ERROR = 'calculated transcript hash does not match bundle_sha256'
# Constant programs; no shell interpolation of inputs or private values.
INSPECT = r'''try do
  Application.ensure_all_started(:crypto)
  Application.ensure_all_started(:x509)
  input = Jason.decode!(IO.read(:stdio, :eof))
  base = "/state/bundle"
  {:ok, retained} = SecretHub.Agent.PKI.BundleValidator.validate_disk_bundle(base,
    pinned_ca_fingerprint: input["pin"])
  bundle = File.read!(base <> "/current/manifest.json") |> Jason.decode!()
    |> Map.put("ca_bundle_pem", retained.ca_bundle_pem) |> Map.put("crl_pem", retained.crl_pem)
  serials = X509.CRL.list(retained.parsed_crl) |> Enum.map(&X509.CRL.Entry.serial/1)
  client = X509.Certificate.from_pem!(input["client"])
  control = X509.Certificate.from_pem!(input["control"])
  true = X509.Certificate.serial(client) in serials
  true = X509.Certificate.serial(control) not in serials
  digest = fn raw -> Base.encode16(:crypto.hash(:sha256, raw), case: :lower) end
  watermark = fn path ->
    raw = File.read!(path)
    %{metadata: Jason.decode!(raw), sha256: digest.(raw)}
  end
  files = fn files, dir ->
    File.ls!(dir) |> Enum.sort() |> Enum.flat_map(fn name ->
      path = Path.join(dir, name)
      case File.lstat!(path).type do
        :directory -> files.(files, path)
        :regular -> [[path, digest.(File.read!(path))]]
        :symlink -> [[path, "link:" <> File.read_link!(path)]]
      end
    end)
  end
  IO.puts("CORRUPTION_PRIVATE=" <> Jason.encode!(%{
    bundle: bundle, manager: watermark.(base <> "/watermark.json"),
    current: File.read_link!(base <> "/current"),
    consumers: Map.new(~w(tls http), &{&1, watermark.("/state/" <> &1 <> "-watermark.json")}),
    inventory_sha256: digest.(Jason.encode!(files.(files, "/state")))}))
rescue
  _ -> IO.puts("CORRUPTION_PRIVATE=false")
catch
  _, _ -> IO.puts("CORRUPTION_PRIVATE=false")
end'''

TRUST_STATE = r'''try do
  Application.ensure_all_started(:crypto)
  digest = fn raw -> Base.encode16(:crypto.hash(:sha256, raw), case: :lower) end
  identity = for name <- ~w(agent-cert.pem agent-key.pem ca-chain.pem connect-info.json identity.json),
    File.exists?("/state/agent/" <> name), do: [name, digest.(File.read!("/state/agent/" <> name))]
  IO.puts("CORRUPTION_PRIVATE=" <> Jason.encode!(%{
    manager_sha256: digest.(File.read!("/state/bundle/watermark.json")),
    current: File.read_link!("/state/bundle/current"),
    consumers: Map.new(~w(tls http), &{&1, digest.(File.read!("/state/" <> &1 <> "-watermark.json"))}),
    identity_sha256: digest.(Jason.encode!(identity))}))
rescue
  _ -> IO.puts("CORRUPTION_PRIVATE=false")
catch
  _, _ -> IO.puts("CORRUPTION_PRIVATE=false")
end'''

DAMAGE = r'''try do
  input = Jason.decode!(IO.read(:stdio, :eof))
  base = "/state/bundle"
  {:ok, target} = File.read_link(base <> "/current")
  true = Regex.match?(~r/^generations\/[1-9][0-9]*$/, target)
  paths = case input["mode"] do
    "consumer" -> [Path.join([base, target, "crl.pem"])]
    "manager" ->
      names = File.ls!(base <> "/generations")
      true = Enum.all?(names, &Regex.match?(~r/^[1-9][0-9]*$/, &1))
      for name <- names, do: Path.join([base, "generations", name, "crl.pem"])
  end
  true = paths != []
  Enum.each(paths, fn path ->
    true = File.lstat!(Path.dirname(path)).type == :directory
    true = File.lstat!(path).type == :regular
    :ok = File.write(path, "prelaunch intentionally damaged CRL\n")
  end)
  if input["mode"] == "manager" do
    true = File.lstat!(base <> "/watermark.json").type == :regular
    :ok = File.write(base <> "/watermark.json", "[]")
  end
  IO.puts("CORRUPTION_PRIVATE=" <> Jason.encode!(%{damaged_files: length(paths), no_files_removed: true}))
rescue
  _ -> IO.puts("CORRUPTION_PRIVATE=false")
catch
  _, _ -> IO.puts("CORRUPTION_PRIVATE=false")
end'''

MANAGER = r'''try do
  Application.ensure_all_started(:crypto)
  Application.ensure_all_started(:x509)
  input = Jason.decode!(IO.read(:stdio, :eof))
  bundle = input["bundle"]
  {:ok, _} = SecretHub.Agent.PKI.BundleValidator.validate(bundle,
    pinned_ca_fingerprint: input["pin"])
  {:ok, manager} = SecretHub.Agent.PKI.TrustBundleManager.start_link(
    state_dir: "/state/agent", bundle_dir: "/state/bundle",
    agent_id: input["fixture_id"], name: :corruption_fixture_manager)
  status = fn -> Map.take(SecretHub.Agent.PKI.TrustBundleManager.status(manager),
    [:status, :recovery_mode, :trust_recovery_restriction, :last_error_code,
     :needs_repair, :lkg_generation, :lkg_crl_number]) end
  normalize = fn
    {:ok, _} -> %{ok: true, error: nil}
    {:error, code, _} -> %{ok: false, error: to_string(code)}
  end
  initial = status.()
  wm_before = File.read!("/state/bundle/watermark.json")
  current_before = File.read_link!("/state/bundle/current")
  rejected = for _ <- 1..2 do
    normalize.(SecretHub.Agent.PKI.TrustBundleManager.process_bundle(manager, bundle))
  end
  restricted = status.()
  unchanged = wm_before == File.read!("/state/bundle/watermark.json") and
    current_before == File.read_link!("/state/bundle/current")
  recovery = if input["authorized"] do
    normalize.(SecretHub.Agent.PKI.TrustBundleManager.process_bundle(manager, bundle,
      force: true, pinned_ca_fingerprint: input["pin"]))
  else
    nil
  end
  IO.puts("CORRUPTION_PRIVATE=" <> Jason.encode!(%{initial: initial, rejected: rejected,
    restricted: restricted, rejected_trust_unchanged: unchanged,
    operator_recovery: recovery, final: status.()}))
  GenServer.stop(manager)
rescue
  _ -> IO.puts("CORRUPTION_PRIVATE=false")
catch
  _, _ -> IO.puts("CORRUPTION_PRIVATE=false")
end'''


def private_result(raw):
    lines = [line[len(MARKER):] for line in raw.decode().splitlines() if line.startswith(MARKER)]
    require(len(lines) == 1)
    value = json.loads(lines[0])
    require(isinstance(value, dict))
    return value


def same_trust(before, after):
    return (counters(before['manager']['metadata']) == counters(after['manager']['metadata']) and
            before['current'] == after['current'] and before['consumers'] == after['consumers'])


def quarantine_checked(result):
    return (all(result[key]['status'] == 'recovery_required' and
                result[key]['recovery_mode'] == 'quarantined' and
                result[key]['trust_recovery_restriction'] == 'damaged_state_recovery_required'
                for key in ('initial', 'restricted')) and
            result['rejected_trust_unchanged'] is True and len(result['rejected']) == 2 and
            all(item == {'ok': False, 'error': 'damaged_state_recovery_required'} for item in result['rejected']))


def disk_failure_checked(logs, startup=False):
    marker = b'failed to load initial trust bundle' if startup else b'Failed to reload trust bundle from disk'
    return marker in logs and CORRUPT_CRL_ERROR.encode() in logs


class CorruptionHarness(HistoryHarness):
    def __init__(self, config, output, attempt_recovery=False):
        # Reuse offline provenance/private-fixture setup only. No Core/API method runs.
        super().__init__(config, config, output)
        self.source_volume = self.volume
        self.volume = self.source_volume + '-corruption-' + uuid.uuid4().hex[:12]
        self.consumer = self.volume + '-consumer'
        self.retained_copies = []
        self.attempt_recovery = attempt_recovery
        self.stage = 'preflight'
        self.results = {}
        self.pin = config['existing_authority_ca_fingerprint']
        require(re.fullmatch(r'[0-9a-f]{64}', self.pin) is not None)
        require(config.get('corruption_source_quiesced') is True)
        if attempt_recovery:
            require(config.get('corruption_operator_recovery_authorized') is True)
            require(re.fullmatch(r'[0-9a-f]{64}', config['corruption_approved_bundle_sha256']) is not None)
        fresh = config.get('corruption_consumer_fixture_dir')
        if fresh:
            directory = Path(fresh)
            require(directory.is_absolute() and not directory.is_symlink())
            directory = directory.resolve(strict=True)
            require(directory.is_dir() and directory.stat().st_uid == os.getuid() and directory.stat().st_mode & 0o077 == 0)
            self.source_fixture = directory
            for name in ('server.crt', 'server.key'):
                file = directory / name
                require(file.is_file() and not file.is_symlink())
                (self.fixture / name).write_bytes(file.read_bytes())
        for kind in ('client', 'control', 'server'):
            for suffix in ('.crt', '.key'):
                file = self.source_fixture / (kind + suffix)
                require(file.is_file() and not file.is_symlink() and file.stat().st_uid == os.getuid())
            require((self.source_fixture / (kind + '.key')).stat().st_mode & 0o077 == 0 or kind == 'server')

    def run_command(self, args, payload=None, timeout=45, combine_output=False):
        try:
            result = subprocess.run(args, input=payload, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.diagnostics.append((error.stdout or b'') + (error.stderr or b''))
            raise CheckFailed() from None
        self.diagnostics.append(result.stdout + result.stderr)
        require(result.returncode == 0)
        return result.stdout + result.stderr if combine_output else result.stdout

    def consumer_logs(self):
        require(self.consumer in self.active_containers)
        return self.run_command(['docker', 'logs', self.consumer], timeout=20, combine_output=True)

    def remove_container(self, name):
        require(name in self.active_containers and name.startswith(self.volume + '-'))
        # Inspect existence separately: an unavailable Docker daemon is not cleanup.
        present = self.run_command(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
        if present.strip():
            self.run_command(['docker', 'rm', '-f', name], timeout=20)
        require(not self.run_command(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).strip())
        self.active_containers.remove(name)

    def eval(self, volume, program, payload, writable=False):
        require(volume == self.source_volume or volume == self.volume)
        require(not writable or volume in self.retained_copies)
        name = self.volume + '-eval-' + uuid.uuid4().hex[:8]
        self.active_containers.add(name)
        try:
            return private_result(self.run_command(['docker', 'run', '--rm', '--pull', 'never', '--name', name,
                '--network', 'none', '--user', '1002:1002', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '-i', '-e', 'ERL_CRASH_DUMP=/dev/null', '-e', 'SECRET_HUB_AGENT_CORE_URL=' + self.config['management_origin'],
                '-e', 'SECRET_HUB_AGENT_HOST_KEY_PATH=/state/unused-host-key', '-e', 'SECRET_HUB_AGENT_STATE_DIR=/state/agent',
                '-e', 'SECRET_HUB_AGENT_SOCKET_PATH=/state/unused.sock', '-e', 'SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR=/state/bundle',
                '--mount', 'type=volume,src=' + volume + ',dst=/state' + ('' if writable else ',readonly'),
                self.config['agent_image_id'], 'eval', program], json.dumps(payload).encode()))
        finally:
            self.remove_container(name)

    def inspect(self, volume):
        return self.eval(volume, INSPECT, {'pin': self.pin,
            'client': (self.source_fixture / 'client.crt').read_text(),
            'control': (self.source_fixture / 'control.crt').read_text()})

    def trust_state(self):
        return self.eval(self.volume, TRUST_STATE, {})

    def start_consumer(self, bundle):
        require(self.volume in self.retained_copies and self.live_bundle_dir is None)
        require(not self.run_command(['docker', 'ps', '-a', '--filter', 'name=^/' + self.consumer + '$', '--format', '{{.Names}}']).strip())
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('127.0.0.1', self.port))
        return super().start_consumer(bundle)

    def copy_source(self):
        require(not self.run_command(['docker', 'volume', 'ls', '--filter', 'name=^' + self.volume + '$', '--format', '{{.Name}}']).strip())
        self.run_command(['docker', 'volume', 'create', '--label', 'secrethub.prelaunch.owner=' + self.volume, self.volume])
        self.retained_copies.append(self.volume)
        name = self.volume + '-copy'
        self.active_containers.add(name)
        try:
            self.run_command(['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none',
                '--user', '0', '--entrypoint', '/bin/sh', '--mount', 'type=volume,src=' + self.source_volume + ',dst=/source,readonly',
                '--mount', 'type=volume,src=' + self.volume + ',dst=/state', self.config['agent_image_id'],
                '-c', 'cp -a /source/. /state/ && chown 1002:1002 /state && chmod 700 /state'])
        finally:
            self.remove_container(name)

    def valid_certs(self, seconds):
        for kind in ('client', 'control', 'server'):
            self.run_command(['openssl', 'x509', '-in', str(self.source_fixture / (kind + '.crt')),
                              '-noout', '-checkend', str(seconds)])

    def denial_pair(self):
        require(self.request(self.context('client'))[0] != 200)
        require(self.request(self.valid_context)[0] == 200)
        self.valid_certs(0)

    def execute_corruption(self):
        for key in ('core_image_id', 'agent_image_id', 'pki_caddy_carrier_image_id'):
            info = json.loads(self.run_command(['docker', 'image', 'inspect', self.config[key]]))[0]
            require(info['Id'] == self.config[key] and info['Os'] + '/' + info['Architecture'] == self.config['platform'])
            if key == 'agent_image_id':
                require(info['Config']['User'] in ('1002', '1002:1002', 'secrethub'))
            if key != 'pki_caddy_carrier_image_id' and not self.config.get('provisional', False):
                require((info['Config'].get('Labels') or {}).get('org.opencontainers.image.revision') == self.config['source_sha'])
        self.run_command(['docker', 'volume', 'inspect', self.source_volume])
        self.valid_certs(180)
        before = self.inspect(self.source_volume)
        self.before = before
        bundle = before['bundle']
        wm = counters(before['manager']['metadata'])
        require(wm['pinned_ca_fingerprint'] == self.pin == bundle['ca_fingerprint'])
        require(wm['highest_seen_generation'] == bundle['generation'] and wm['highest_seen_crl_number'] == bundle['crl_number'])
        require(wm['last_bundle_sha256'] == bundle['bundle_sha256'])
        for value in before['consumers'].values():
            require(counters(value['metadata']) == wm)
        require(re.fullmatch(r'generations/[1-9][0-9]*', before['current']) is not None)
        if self.attempt_recovery:
            require(self.config['corruption_approved_bundle_sha256'] == bundle['bundle_sha256'])
        (self.fixture / 'ca.crt').write_text(bundle['ca_bundle_pem'])
        self.run_command(['openssl', 'verify', '-CAfile', str(self.fixture / 'ca.crt'), '-purpose', 'sslclient',
                          str(self.source_fixture / 'client.crt'), str(self.source_fixture / 'control.crt')])
        self.valid_context = self.context('control')
        self.stage = 'copy_history'
        self.copy_source()
        copied = self.inspect(self.volume)
        require(before == copied)
        self.stage = 'consumer_baseline'
        self.start_consumer(bundle)
        self.denial_pair()
        trust_before = self.trust_state()
        self.stage = 'consumer_disk_corruption'
        self.results['damage'] = self.eval(self.volume, DAMAGE, {'mode': 'consumer'}, writable=True)
        time.sleep(1)  # Five configured 200ms reload polls; no enforcement timing claim.
        logs = self.consumer_logs()
        require(disk_failure_checked(logs))
        self.denial_pair()
        require(trust_before == self.trust_state())
        self.results['live_consumer'] = {'status': 'passed', 'policy': 'last-known-good retained after failed reload',
            'revoked': 'denied', 'control': 'allowed', 'reload_failure_observed': True,
            'exact_error': CORRUPT_CRL_ERROR, 'trust_watermarks_and_identity_preserved': True}
        self.remove_container(self.consumer)
        self.stage = 'consumer_damaged_restart'
        # start_consumer writes configuration but cannot report ready on damaged disk.
        try:
            self.start_consumer(bundle)
            raise CheckFailed()
        except CheckFailed:
            require(self.request(self.valid_context)[0] != 200)
            info = json.loads(self.run_command(['docker', 'inspect', self.consumer]))[0]
            require(info['State']['Running'] is False and info['State']['ExitCode'] != 0)
            logs = self.consumer_logs()
            require(disk_failure_checked(logs, startup=True))
        self.remove_container(self.consumer)
        require(trust_before == self.trust_state())
        self.results['damaged_restart'] = {'status': 'passed', 'policy': 'startup fails closed',
                                          'control': 'denied', 'exact_error': CORRUPT_CRL_ERROR}
        self.stage = 'manager_damaged_state'
        self.results['manager_damage'] = self.eval(self.volume, DAMAGE, {'mode': 'manager'}, writable=True)
        damaged = self.trust_state()
        require(all(damaged[key] == trust_before[key] for key in ('consumers', 'identity_sha256', 'current')))
        result = self.eval(self.volume, MANAGER, {'bundle': bundle, 'pin': self.pin,
            'fixture_id': '00000000-0000-4000-8000-' + self.identifier,
            'authorized': self.attempt_recovery}, writable=True)
        self.results['manager'] = result
        require(quarantine_checked(result))
        if self.attempt_recovery:
            if result['operator_recovery'] == {'ok': False, 'error': 'corrupted_existing_generation'}:
                require(damaged == self.trust_state())
                require(result['final']['recovery_mode'] == 'quarantined' and
                        result['final']['trust_recovery_restriction'] == 'damaged_state_recovery_required')
                self.results['operator_recovery'] = {'status': 'unsupported', 'error': 'corrupted_existing_generation',
                    'decision': 'existing operator API cannot repair retained damaged same-generation directory'}
                return 'SELECTED_CHECKS_PASSED'
            require(result['operator_recovery'] == {'ok': True, 'error': None})
            after = self.inspect(self.volume)
            require(same_trust(before, after))
            self.start_consumer(bundle)
            self.denial_pair()
            self.results['operator_recovery'] = {'status': 'passed', 'same_high_water_bundle': True}
        else:
            require(damaged == self.trust_state())
            self.results['operator_recovery'] = {'status': 'unexecuted', 'reason': 'explicit recovery authorization absent'}
        return 'SELECTED_CHECKS_PASSED'

    def run(self):
        status = 'FAILED'
        report = {'complete': False, 'provisional': self.config.get('provisional', False),
            'source_sha': self.config['source_sha'], 'platform': self.config['platform'],
            'artifacts': {key: self.config[key] for key in ('core_image_id', 'agent_image_id')},
            'source_retained_volume': self.source_volume, 'retained_copied_volumes': self.retained_copies,
            'operator_recovery_authorized': self.attempt_recovery, 'results': self.results,
            'recovery_hold': True,
            'gates': {'G15': {'status': 'partial'}}, 'observed_at': datetime.now(timezone.utc).isoformat()}
        report['artifacts'].update(caddy_sha256=hashlib.sha256(self.caddy.read_bytes()).hexdigest(),
            caddy_carrier_image_id=self.carrier, caddy_runtime_store_paths=self.runtime_paths)
        started = time.monotonic()
        try:
            status = self.execute_corruption()
        except Exception as error:
            report['failure'] = {'stage': self.stage, 'error_type': type(error).__name__}
        finally:
            for name in list(self.active_containers):
                try:
                    self.remove_container(name)
                except Exception:
                    status = 'FAILED'
            # Original evidence always rechecked, even after a blocked recovery.
            try:
                report['source_inventory_unchanged'] = self.before == self.inspect(self.source_volume)
                require(report['source_inventory_unchanged'])
            except Exception:
                report['source_inventory_unchanged'] = False
                status = 'FAILED'
            report['cleanup_confirmed'] = not self.active_containers
            if not report['cleanup_confirmed']:
                status = 'FAILED'
        report['status'] = status
        if hasattr(self, 'before'):
            report['verified_high_water'] = counters(self.before['manager']['metadata'])
        report['seconds'] = round(time.monotonic() - started, 3)
        report['diagnostics_sha256'] = hashlib.sha256(b'\n'.join(self.diagnostics)).hexdigest()
        report['private_material'] = 'excluded; retain private fixture, copied volume, and source history'
        private_json(self.output / 'report.json', report)
        print(json.dumps({'complete': False, 'G15': 'partial', 'status': status,
                          'report': str(self.output / 'report.json')}))
        return 0 if status == 'SELECTED_CHECKS_PASSED' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='private PKI config with owned retained fixture provenance')
    parser.add_argument('--output', required=True, help='new owner-only result beside config')
    parser.add_argument('--attempt-operator-recovery', action='store_true', help='also requires private config authorization and exact approved bundle hash')
    args = parser.parse_args()
    try:
        checkout = Path(__file__).resolve().parents[2]
        checkout = next((parent.parent for parent in checkout.parents if parent.name == '.trees'), checkout)
        path = private_file(args.config)
        require(not path.is_relative_to(checkout))
        output = Path(args.output).absolute()
        require(not output.resolve().is_relative_to(checkout) and output.parent.resolve() == path.parent)
        config = json.loads(path.read_text())
        require(re.fullmatch(r'[0-9a-f]{40}', config['source_sha']) is not None)
        require(config['platform'] == 'linux/amd64' and type(config.get('provisional', False)) is bool)
        return CorruptionHarness(config, output, args.attempt_operator_recovery).run()
    except Exception as error:
        print(json.dumps({'complete': False, 'G15': 'partial', 'setup': 'failed', 'error_type': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
