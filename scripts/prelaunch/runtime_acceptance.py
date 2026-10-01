#!/usr/bin/env python3
"""Real-image Agent lifecycle checks against explicitly owned fixture processes.

Reports metadata only. Existing Agent identity and monotonic state are preserved;
damaged-state rejection uses a separate copy, never the live state directory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

from acceptance import Harness, CheckFailed, command, private_json, require


class RuntimeHarness:
    def __init__(self, config, output, shares_file):
        self.core = Harness(config, output, shares_file=shares_file)
        self.config = config
        self.output = Path(output)
        require(config.get('isolated_fixture') is True)
        self.agent = config['agent_container']
        require(self.agent.startswith('secrethub-prelaunch-'))
        self.agent_info = json.loads(command(['docker', 'inspect', self.agent]))[0]
        require(self.agent_info['Image'] == config['agent_image_id'])
        require(self.agent_info['Config']['User'] in ('secrethub', '1002', '1002:1002'))
        artifact = json.loads(command(['docker', 'image', 'inspect', config['agent_image_id']]))[0]
        require(artifact['Os'] + '/' + artifact['Architecture'] == config['platform'])
        if not self.core.provisional:
            require(config['source_sha'] == (self.agent_info['Config'].get('Labels') or {}).get(
                'org.opencontainers.image.revision'))
        require(command(['docker', 'exec', self.agent, 'id', '-u']).strip() == '1002')
        self.environment = dict(value.split('=', 1) for value in self.agent_info['Config']['Env'])
        self.state_dir = self.environment['SECRET_HUB_AGENT_STATE_DIR']
        self.hostname = config['agent_hostname']
        require(self.hostname == self.agent_info['Config']['Hostname'])
        self.diagnostics = []

    def agent_value(self, expression):
        code = ('try do Application.load(:secrethub_agent); '
                'IO.puts("PRELAUNCH_RESULT=" <> Jason.encode!(' + expression + ')) '
                'rescue _ -> IO.puts("PRELAUNCH_RESULT=false") end')
        result = subprocess.run(['docker', 'exec', self.agent, '/app/bin/secrethub_agent',
                                 'eval', code], capture_output=True, timeout=60)
        self.diagnostics.append(result.stdout + result.stderr)
        require(result.returncode == 0)
        values = [line[17:] for line in result.stdout.decode().splitlines()
                  if line.startswith('PRELAUNCH_RESULT=')]
        require(len(values) == 1)
        return json.loads(values[0])

    def snapshot(self):
        return self.agent_value(
            'case SecretHub.Agent.IdentityStore.load(' + json.dumps(self.state_dir) + ') do '
            '{:ok, m} -> %{agent_id: m.agent_id, '
            'certificate_sha256: Base.encode16(:crypto.hash(:sha256, m.certificate_pem), case: :lower), '
            'key_sha256: Base.encode16(:crypto.hash(:sha256, m.private_key_pem), case: :lower), '
            'ca_sha256: Base.encode16(:crypto.hash(:sha256, m.ca_chain_pem), case: :lower), '
            'minimum_uds_auth_version: Map.get(m.identity, "minimum_uds_auth_version", 1)}; '
            '_ -> false end')

    def database_status(self):
        return self.core.evaluate(
            'SecretHub.Core.Repo.all(Ecto.Query.from(e in SecretHub.Shared.Schemas.AgentEnrollment, '
            'where: e.hostname == ' + json.dumps(self.hostname) + ', '
            'join: a in SecretHub.Shared.Schemas.Agent, on: a.agent_id == e.agent_id, '
            'select: %{enrollment_id: e.id, status: e.status, agent_id: a.agent_id, '
            'heartbeat: a.last_heartbeat_at, certificate_id: a.certificate_id}))')

    def enrollment_ids(self):
        return self.core.evaluate(
            'SecretHub.Core.Repo.all(Ecto.Query.from(e in SecretHub.Shared.Schemas.AgentEnrollment, '
            'where: e.hostname == ' + json.dumps(self.hostname) + ', order_by: e.id, select: e.id))')

    def wait_connected(self, previous_heartbeat=None, not_before=None):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = self.database_status()
            if isinstance(rows, list) and len(rows) == 1 and rows[0]['status'] == 'finalized':
                heartbeat = rows[0]['heartbeat']
                if heartbeat is not None and heartbeat != previous_heartbeat:
                    observed = datetime.fromisoformat(heartbeat.replace('Z', '+00:00'))
                    if not_before is None or observed > not_before:
                        return rows[0]
            time.sleep(1)
        raise CheckFailed()

    def damaged_copy(self):
        volume = 'secrethub-prelaunch-damaged-' + uuid.uuid4().hex[:12]
        command(['docker', 'volume', 'create', volume])
        source = next(m for m in self.agent_info['Mounts']
                      if self.state_dir.startswith(m['Destination'] + '/') and m['Type'] == 'bind')
        relative = self.state_dir[len(source['Destination']):]
        require(re.fullmatch(r'/[A-Za-z0-9_./-]+', relative) is not None and '..' not in relative)
        command(['docker', 'run', '--rm', '--network', 'none', '--user', '0',
                 '--entrypoint', 'sh', '--mount', 'type=bind,src=' + source['Source'] + ',dst=/source,readonly',
                 '--mount', 'type=volume,src=' + volume + ',dst=/damaged',
                 self.config['agent_image_id'], '-c',
                 'cp -a /source' + relative + '/. /damaged/; '
                 'printf malformed > /damaged/identity.json; '
                 'chown -R 1002:1002 /damaged; chmod 700 /damaged'])
        environment = dict(self.environment)
        environment.update(SECRET_HUB_AGENT_STATE_DIR='/damaged',
                           SECRET_HUB_AGENT_SOCKET_PATH='/app/tmp/damaged.sock',
                           SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR='/app/tmp')
        name = 'secrethub-prelaunch-damage-check-' + uuid.uuid4().hex[:12]
        args = ['docker', 'run', '--rm', '--name', name, '--network', 'host']
        for mount in self.agent_info['Mounts']:
            require(mount['Type'] == 'bind')
            args += ['--mount', 'type=bind,src=' + mount['Source'] + ',dst=' + mount['Destination'] + ',readonly']
        args += ['--mount', 'type=volume,src=' + volume + ',dst=/damaged']
        for key, value in environment.items():
            args += ['-e', key + '=' + value]
        args += [self.config['agent_image_id']]
        try:
            preflight = subprocess.run(args + ['eval',
                'Application.load(:secrethub_agent); IO.puts("PRELAUNCH_RESULT=" <> '
                'Jason.encode!(SecretHub.Agent.Preflight.checks()))'], capture_output=True, timeout=45)
            self.diagnostics.append(preflight.stdout + preflight.stderr)
            values = [line[17:] for line in preflight.stdout.decode().splitlines()
                      if line.startswith('PRELAUNCH_RESULT=')]
            require(preflight.returncode == 0 and len(values) == 1)
            checks = json.loads(values[0])
            require(set(checks) >= {'role', 'host_key', 'enrollment_trust', 'state_directory',
                                    'socket_directory', 'bundle_directory', 'identity'})
            require(checks.get('identity') is False)
            require(all(value is True for key, value in checks.items() if key != 'identity'))
            result = subprocess.run(args + ['start'], capture_output=True, timeout=45)
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=20)
            raise CheckFailed()
        self.diagnostics.append(result.stdout + result.stderr)
        require(result.returncode != 0 and b'agent_preflight_failed' in result.stdout + result.stderr)
        return volume

    def run(self):
        started = time.monotonic()
        result = {'status': 'failed'}
        try:
            first = self.wait_connected()
            identity = self.snapshot()
            require(isinstance(identity, dict) and identity['agent_id'] == first['agent_id'])
            require(self.agent_value('not File.exists?(Path.join(' + json.dumps(self.state_dir) +
                                     ', "pending.json"))') is True)
            enrollments_before = self.enrollment_ids()
            command(['docker', 'restart', self.agent])
            agent_restart_completed = datetime.now(timezone.utc)
            after_agent_restart = self.wait_connected(first['heartbeat'], agent_restart_completed)
            require(self.snapshot() == identity)
            require(self.enrollment_ids() == enrollments_before)
            command(['docker', 'restart', self.config['core_container']])
            core_restart_completed = datetime.now(timezone.utc)
            deadline = time.monotonic() + 60
            while True:
                try:
                    self.core.client.session()
                    require(self.core.client.json('/v1/sys/seal-status')[2]['sealed'] is True)
                    break
                except Exception:
                    require(time.monotonic() < deadline)
                    time.sleep(0.5)
            for share in self.core.shares[:3]:
                require(self.core.client.json('/v1/sys/unseal', 'POST', {'share': share})[0] == 200)
            after_core_restart = self.wait_connected(after_agent_restart['heartbeat'], core_restart_completed)
            require(self.snapshot() == identity)
            require(self.enrollment_ids() == enrollments_before)
            retained_volume = self.damaged_copy()
            require(self.snapshot() == identity)
            require(self.enrollment_ids() == enrollments_before)
            require(after_core_restart['certificate_id'] == first['certificate_id'])
            result = {'status': 'passed', 'observations': {
                'runtime': 'real Core-issued certificate over mTLS WebSocket; finalized enrollment and fresh heartbeats',
                'agent_restart': 'certificate, private-key digest, authority and floor preserved',
                'core_restart': 'sealed until manual unseal; reconnect without new enrollment',
                'damaged_copy': 'startup rejected before enrollment; original identity unchanged',
                'retained_damaged_fixture_volume': retained_volume}}
        except Exception as error:
            result['error_class'] = type(error).__name__
        result['seconds'] = round(time.monotonic() - started, 3)
        report = {key: self.config[key] for key in ('source_sha', 'core_image_id', 'agent_image_id', 'platform')}
        report.update(created_at=datetime.now(timezone.utc).isoformat(), provisional=self.core.provisional,
                      complete=False, gates={'G11': result},
                      diagnostics_sha256=hashlib.sha256(b'\n'.join(self.diagnostics)).hexdigest())
        private_json(self.output / 'runtime-report.json', report)
        print('G11: ' + result['status'], flush=True)
        return 0 if result['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--shares-file', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        return RuntimeHarness(json.loads(Path(args.config).read_text()), args.output, args.shares_file).run()
    except Exception as error:
        print('runtime fixture rejected: ' + type(error).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
