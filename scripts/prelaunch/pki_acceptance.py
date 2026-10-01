#!/usr/bin/env python3
"""Isolated PKI artifact/consumer evidence; transport and restore gates stay partial.

Uses the existing protected management ingress. Never initializes operator Caddy,
prints response bodies or removes a persistent trust watermark. Fixture volumes
are retained so their monotonic state survives this process.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import uuid

from acceptance import CheckFailed, Client, command, private_json, require


class PKIHarness:
    def __init__(self, config, output, resume_output=None):
        self.config = config
        self.output = Path(output).resolve()
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.identifier = uuid.uuid4().hex[:12]
        self.volume = 'secrethub-prelaunch-pki-' + self.identifier
        self.consumer = self.volume + '-consumer'
        self.active_containers = set()
        self.results = {}
        self.stage = 'setup'
        self.diagnostics = []
        self.artifacts = {}
        self.port = config.get('pki_consumer_port', 15767)
        require(isinstance(self.port, int) and 1024 <= self.port <= 65535)
        self.bound = config['pki_enforcement_bound_seconds']
        self.delay = config.get('pki_distribution_delay_seconds', 1)
        require(0 < self.delay <= 30 and self.bound > self.delay)
        self.provisional = config.get('provisional') is True
        for kind in ('core', 'agent'):
            image_id = config[kind + '_image_id']
            require(re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) is not None)
            info = json.loads(command(['docker', 'image', 'inspect', image_id]))[0]
            require(info['Os'] + '/' + info['Architecture'] == config['platform'])
            require(info['Config']['User'] in ('secrethub', str(1001 if kind == 'core' else 1002)))
            if not self.provisional:
                require((info['Config'].get('Labels') or {}).get('org.opencontainers.image.revision') == config['source_sha'])
            self.artifacts[kind + '_image_id'] = image_id
        require(config['core_container'].startswith('secrethub-prelaunch-'))
        core = json.loads(command(['docker', 'inspect', config['core_container']]))[0]
        require(core['Image'] == config['core_image_id'])
        caddy = Path(config['pki_caddy_binary']).resolve()
        require(caddy.is_file())
        self.caddy = caddy
        self.artifacts['caddy_sha256'] = hashlib.sha256(caddy.read_bytes()).hexdigest()
        self.carrier = config['pki_caddy_carrier_image_id']
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', self.carrier) is not None)
        carrier = json.loads(command(['docker', 'image', 'inspect', self.carrier]))[0]
        require(carrier['Os'] + '/' + carrier['Architecture'] == config['platform'])
        self.artifacts['caddy_carrier_image_id'] = self.carrier
        self.runtime_paths = config.get('pki_caddy_runtime_paths', [])
        require(all(re.fullmatch(r'/nix/store/[a-z0-9]{32}-[A-Za-z0-9.+_-]+', item)
                    and Path(item).is_dir() for item in self.runtime_paths))
        self.artifacts['caddy_runtime_store_paths'] = self.runtime_paths
        self.live_bundle_dir = config.get('agent_bundle_dir')
        if self.live_bundle_dir:
            # The host operator need not traverse Agent-owned mode700 parents.
            # Validate the bind mapping here; read the actual manifest using the
            # Agent UID before starting the consumer.
            require(Path(self.live_bundle_dir).is_absolute())
            self.live_bundle_dir = os.path.abspath(self.live_bundle_dir)
            require(config['agent_container'].startswith('secrethub-prelaunch-'))
            agent = json.loads(command(['docker', 'inspect', config['agent_container']]))[0]
            require(agent['Image'] == config['agent_image_id'] and agent['State']['Running'])
            env = dict(item.split('=', 1) for item in agent['Config']['Env'])
            bundle_path = Path(env['SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR'])
            matching = [mount for mount in agent['Mounts'] if mount['Type'] == 'bind'
                        and (bundle_path == Path(mount['Destination']) or Path(mount['Destination']) in bundle_path.parents)]
            require(bool(matching))
            mount = max(matching, key=lambda item: len(item['Destination']))
            require(os.path.abspath(Path(mount['Source']) / bundle_path.relative_to(mount['Destination'])) == self.live_bundle_dir)
        context = ssl.create_default_context(cafile=config['management_ca'])
        context.load_cert_chain(config['operator_cert'], config['operator_key'])
        self.client = Client(config['management_origin'], context).session()
        self.fixture = self.output / 'consumer.private'
        # The outer directory is owner-only; these files are visible only via
        # explicitly selected read-only binds to the nonroot fixture containers.
        self.fixture.mkdir(mode=0o755)
        self.resume = resume_output is not None
        if self.resume:
            previous = Path(resume_output).resolve()
            prior = json.loads((previous / 'report.json').read_text())
            require(all(prior['artifacts'].get(key) == value for key, value in self.artifacts.items()))
            require(prior['source_sha'] == config['source_sha'])
            require(re.fullmatch(r'secrethub-prelaunch-pki-[0-9a-f]{12}', prior['retained_monotonic_fixture_volume']) is not None)
            self.volume = prior['retained_monotonic_fixture_volume']
            self.identifier = self.volume.rsplit('-', 1)[1]
            self.consumer = self.volume + '-consumer'
            self.fixture = previous / 'consumer.private'
            require(self.fixture.is_dir())

    def run_command(self, args, payload=None, timeout=60):
        result = subprocess.run(args, input=payload, capture_output=True, timeout=timeout)
        self.diagnostics.append(result.stdout + result.stderr)
        require(result.returncode == 0)
        return result.stdout

    def api(self, path, body=None, status=200):
        code, _, value = self.client.json('/v1/pki/client-auth' + path,
                                          'POST' if body is not None else 'GET', body)
        require(code == status and isinstance(value, dict) and 'data' in value)
        return value['data']

    def agent(self, bundle):
        name = self.volume + '-apply-' + uuid.uuid4().hex[:6]
        code = '''
        Application.ensure_all_started(:crypto)
        Application.ensure_all_started(:x509)
        bundle = Jason.decode!(IO.read(:stdio, :eof))
        {:ok, manager} = SecretHub.Agent.PKI.TrustBundleManager.start_link(
          state_dir: "/state/agent", bundle_dir: "/state/bundle",
          agent_id: "ARTIFACT_FIXTURE_ID", name: :artifact_pki_acceptance)
        result = SecretHub.Agent.PKI.TrustBundleManager.process_bundle(manager, bundle)
        state = SecretHub.Agent.PKI.TrustBundleManager.status(manager)
        {ok, error} = case result do
          {:ok, _} -> {true, nil}
          {:error, code, _} -> {false, to_string(code)}
        end
        {:ok, watermark} = File.read("/state/bundle/watermark.json")
        {:ok, current} = File.read_link("/state/bundle/current")
        IO.puts("PKI_RESULT=" <> Jason.encode!(%{ok: ok, error: error,
          watermark_sha256: Base.encode16(:crypto.hash(:sha256, watermark), case: :lower),
          current: current, state: Map.take(state, [:lkg_generation, :lkg_crl_number, :status])}))
        GenServer.stop(manager)
        '''
        code = code.replace('ARTIFACT_FIXTURE_ID', '00000000-0000-4000-8000-' + self.identifier)
        self.active_containers.add(name)
        try:
            raw = self.run_command(['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none', '-i',
                                    '-e', 'SECRET_HUB_AGENT_CORE_URL=' + self.config['management_origin'],
                                    '-e', 'SECRET_HUB_AGENT_HOST_KEY_PATH=/state/unused-host-key',
                                    '-e', 'SECRET_HUB_AGENT_STATE_DIR=/state/agent',
                                    '-e', 'SECRET_HUB_AGENT_SOCKET_PATH=/state/unused-agent.sock',
                                    '-e', 'SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR=/state/bundle',
                                    '-v', self.volume + ':/state', self.config['agent_image_id'], 'eval', code],
                                   json.dumps(bundle).encode())
        finally:
            self.remove_container(name)
        lines = [line[11:] for line in raw.decode().splitlines() if line.startswith('PKI_RESULT=')]
        require(len(lines) == 1)
        return json.loads(lines[0])

    def remove_container(self, name):
        # Only invocation-owned names; never stop existing integration fixtures.
        result = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=20)
        if result.returncode:
            check = subprocess.run(['docker', 'inspect', name], capture_output=True, timeout=20)
            require(check.returncode != 0)
        self.active_containers.discard(name)

    def generate_material(self):
        for kind in ('server', 'untrusted'):
            self.run_command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                              '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                              '-keyout', str(self.fixture / (kind + '.key')),
                              '-out', str(self.fixture / (kind + '.crt'))])
        self.run_command(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:secp384r1',
                          '-nodes', '-subj', '/CN=disposable-pki-consumer',
                          '-keyout', str(self.fixture / 'client.key'), '-out', str(self.fixture / 'client.csr')])
        # The serving container needs only its test server key; client keys stay
        # owner-only and are never mounted into that container.
        (self.fixture / 'server.key').chmod(0o644)
        for filename in ('client.key', 'untrusted.key'):
            (self.fixture / filename).chmod(0o600)

    def start_consumer(self, bundle):
        (self.fixture / 'ca.crt').write_text(bundle['ca_bundle_pem'])
        verifier = {'bundle_dir': '/state/bundle', 'expected_ca_fingerprint': bundle['ca_fingerprint'],
                    'poll_interval': 200_000_000}
        config = {'admin': {'disabled': True}, 'apps': {
            'tls': {'certificates': {'load_files': [{'certificate': '/fixture/server.crt', 'key': '/fixture/server.key'}]}},
            'http': {'servers': {'consumer': {'listen': ['127.0.0.1:' + str(self.port)],
                'automatic_https': {'disable': True},
                'tls_connection_policies': [{'protocol_min': 'tls1.2', 'protocol_max': 'tls1.2', 'client_authentication': {
                    'mode': 'require_and_verify', 'ca': {'provider': 'file', 'pem_files': ['/fixture/ca.crt']},
                    'verifiers': [{'verifier': 'secrethub_client_auth', **verifier, 'watermark_file': '/state/tls-watermark.json'}]}}],
                'routes': [{'handle': [
                    {'handler': 'secrethub_client_auth', **verifier, 'watermark_file': '/state/http-watermark.json'},
                    {'handler': 'static_response', 'body': 'ok', 'status_code': 200}]}]}}}}}
        path = self.fixture / 'caddy.json'
        path.write_text(json.dumps(config))
        self.active_containers.add(self.consumer)
        args = ['docker', 'run', '-d', '--pull', 'never', '--name', self.consumer, '--network', 'host',
                          '--user', '1002:1002',
                          '-e', 'XDG_DATA_HOME=/state/caddy-data', '-e', 'XDG_CONFIG_HOME=/state/caddy-config',
                          '--entrypoint', '/prelaunch-caddy', '-v', str(self.caddy) + ':/prelaunch-caddy:ro',
                          '-v', self.volume + ':/state', '-v', str(self.fixture) + ':/fixture:ro']
        if self.live_bundle_dir:
            args += ['-v', self.live_bundle_dir + ':/state/bundle:ro']
        for runtime in self.runtime_paths:
            args += ['-v', runtime + ':' + runtime + ':ro']
        args += [self.carrier, 'run', '--config', '/fixture/caddy.json']
        self.run_command(args)
        deadline = time.monotonic() + 15
        while True:
            try:
                if self.request(self.valid_context)[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            require(time.monotonic() < deadline)
            time.sleep(0.2)

    def wait_live_bundle(self, bundle):
        if not self.live_bundle_dir:
            return
        deadline = time.monotonic() + self.bound
        while True:
            name = self.volume + '-watch-' + uuid.uuid4().hex[:6]
            self.active_containers.add(name)
            try:
                result = subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none',
                    '--entrypoint', '/bin/cat', '-v', self.live_bundle_dir + ':/bundle:ro',
                    self.config['agent_image_id'], '/bundle/current/manifest.json'], capture_output=True, timeout=15)
            finally:
                self.remove_container(name)
            if result.returncode == 0:
                manifest = json.loads(result.stdout)
                if manifest.get('generation') == bundle['generation'] and manifest.get('bundle_sha256') == bundle['bundle_sha256']:
                    return
            require(time.monotonic() < deadline)
            time.sleep(0.2)

    def context(self, kind):
        ctx = ssl.create_default_context(cafile=str(self.fixture / 'server.crt'))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        if kind:
            ctx.load_cert_chain(str(self.fixture / (kind + '.crt')), str(self.fixture / (kind + '.key')))
        return ctx

    def connect(self, context, session=None):
        plain = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        try:
            return context.wrap_socket(plain, server_hostname='localhost', session=session)
        except Exception:
            plain.close()
            raise

    def exchange(self, connection):
        connection.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read()
        status = response.status
        response.close()
        if status == 200:
            require(body == b'ok')
        return status

    def request(self, context, session=None):
        connection = None
        try:
            connection = self.connect(context, session)
            return self.exchange(connection), connection.session_reused
        except (OSError, http.client.HTTPException):
            return 'tls_or_transport_rejected', False
        finally:
            if connection:
                connection.close()

    def execute(self):
        self.stage = 'authority_initialization'
        # Never silently reuse an authority; this run expects its dedicated DB.
        if not self.resume:
            code, _, _ = self.client.json('/v1/pki/client-auth/authority/status')
            require(code == 404)
            self.api('/authority/init', {'name': 'Disposable artifact acceptance CA', 'key_algorithm': 'ecdsa_p384'}, 201)
        first = self.api('/bundle')
        self.artifacts['trust_bundle_schema_version'] = first['schema_version']
        if self.resume:
            # Resume only an unrevoked baseline owned by this previous run.
            # A later checkpoint must use a new fixture, never rewind trust.
            require(first['generation'] == 1 and first['crl_number'] == 1)
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.fixture / 'client.crt').read_text())).hexdigest()
            certificates = self.api('/certificates')
            matches = [item for item in certificates if item.get('canonical_fingerprint', '').lower().replace(':', '') == fingerprint]
            require(len(matches) == 1 and matches[0]['revoked'] is False)
            identities = self.api('/identities')
            require(any(item['name'] == 'disposable-consumer-' + self.identifier
                        and item['id'] == matches[0]['client_auth_identity_id'] for item in identities))
            issued = {'cert_id': matches[0]['id']}
            self.run_command(['docker', 'volume', 'inspect', self.volume])
        else:
            self.generate_material()
            identity = self.api('/identities', {'name': 'disposable-consumer-' + self.identifier}, 201)
            issued = self.api('/issue', {'identity_id': identity['id'], 'request_id': str(uuid.uuid4()),
                                         'csr_pem': (self.fixture / 'client.csr').read_text(), 'ttl_seconds': 3600}, 201)
            (self.fixture / 'client.crt').write_text(issued['certificate_pem'])
            control_identity = self.api('/identities', {'name': 'disposable-control-' + self.identifier}, 201)
            control = self.api('/issue', {'identity_id': control_identity['id'], 'request_id': str(uuid.uuid4()),
                                          'csr_pem': (self.fixture / 'client.csr').read_text(), 'ttl_seconds': 3600}, 201)
            (self.fixture / 'control.crt').write_text(control['certificate_pem'])
            descriptor = os.open(self.fixture / 'control.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as target:
                target.write((self.fixture / 'client.key').read_bytes())
            self.run_command(['docker', 'volume', 'create', self.volume])
        self.stage = 'agent_initial_application'
        permissions = self.volume + '-permissions'
        self.active_containers.add(permissions)
        try:
            self.run_command(['docker', 'run', '--rm', '--pull', 'never', '--name', permissions, '--network', 'none',
                              '--user', '0', '--entrypoint', '/bin/sh',
                              '-v', self.volume + ':/state', self.config['agent_image_id'], '-c',
                              'chown 1002:1002 /state && chmod 700 /state'])
        finally:
            self.remove_container(permissions)
        initial = self.agent(first)
        require(initial['ok'])
        self.wait_live_bundle(first)
        self.valid_context = self.context('client')
        self.control_context = self.context('control')
        self.stage = 'consumer_start'
        self.start_consumer(first)
        require(self.request(self.valid_context)[0] == 200)
        require(self.request(self.context('untrusted'))[0] != 200)
        require(self.request(self.context(None))[0] != 200)
        self.results['issuance_trust'] = {'status': 'passed', 'valid': 'allowed', 'untrusted': 'rejected', 'missing': 'rejected'}

        existing = self.connect(self.valid_context)
        try:
            self.stage = 'revocation_sessions'
            require(self.exchange(existing) == 200)
            session = existing.session
            before = self.request(self.valid_context, session)
            require(before[0] == 200)
            require(before[1] == session.has_ticket)
            self.results['tls_session_behavior'] = {
                'status': 'passed', 'baseline_has_ticket': session.has_ticket,
                'baseline_attempt_status': before[0], 'baseline_session_reused': before[1],
                'policy': 'resumption enabled' if before[1] else 'resumption disabled by exact consumer policy',
                'successfully_resumed_session_revocation': 'measured below' if before[1] else 'unexecuted; consumer issues no session tickets'}
            start = time.monotonic()
            self.api('/certificates/' + issued['cert_id'] + '/revoke', {'reason': 'keyCompromise'})
            publication = self.api('/bundle')
            require(publication['generation'] > first['generation'] and publication['crl_number'] > first['crl_number'])
            if self.live_bundle_dir:
                self.wait_live_bundle(publication)
                self.results['delayed_distribution'] = {'status': 'unexecuted', 'reason': 'owned runtime Agent is not paused by this helper'}
            else:
                time.sleep(self.delay)
                require(self.request(self.valid_context)[0] == 200)
                self.results['delayed_distribution'] = {'status': 'passed', 'withheld_seconds': self.delay,
                                                         'pre_delivery': 'still_allowed', 'transport': 'explicit_harness_delivery'}
            applied = self.agent(publication)
            require(applied['ok'])
            while self.request(self.valid_context)[0] == 200:
                require(time.monotonic() - start < self.bound)
                time.sleep(0.1)
            elapsed = time.monotonic() - start
            require(elapsed <= self.bound)
            resumed = self.request(self.valid_context, session)
            while resumed[0] == 200:
                require(time.monotonic() - start < self.bound)
                time.sleep(0.1)
                resumed = self.request(self.valid_context, session)
            resumed_elapsed = time.monotonic() - start
            open_status = self.exchange(existing)
            while open_status == 200:
                require(time.monotonic() - start < self.bound)
                time.sleep(0.1)
                open_status = self.exchange(existing)
            open_elapsed = time.monotonic() - start
            require(resumed[0] != 200 and open_status != 200)
            require(self.request(self.control_context)[0] == 200)
            self.results['revocation'] = {'status': 'passed', 'publication_to_new_handshake_rejection_upper_bound_seconds': round(elapsed, 3),
                'acceptable_bound_seconds': self.bound, 'new_handshake': 'rejected',
                'resumption_before_revocation_verified': before[1], 'resumed_after_revocation': resumed[1],
                'attempted_session_reuse_request': resumed[0], 'existing_connection_request': open_status,
                'publication_to_session_reuse_attempt_rejection_upper_bound_seconds': round(resumed_elapsed, 3),
                'publication_to_existing_request_rejection_upper_bound_seconds': round(open_elapsed, 3),
                'timing_origin': 'before revocation request; includes Core transaction and transport latency',
                'unrevoked_control_request': 'allowed',
                'existing_connection_termination': 'unexecuted; per-request middleware enforcement measured'}
        finally:
            existing.close()

        self.stage = 'crl_refresh'
        self.api('/crl/refresh', {})
        latest = self.api('/bundle')
        require(latest['generation'] > publication['generation'] and latest['crl_number'] > publication['crl_number'])
        high = self.agent(latest)
        require(high['ok'])
        self.wait_live_bundle(latest)
        require(self.request(self.valid_context)[0] != 200)
        require(self.request(self.control_context)[0] == 200)
        self.results['crl_refresh'] = {'status': 'passed', 'generation': latest['generation'], 'crl_number': latest['crl_number']}
        self.stage = 'old_corrupt_bundle'
        old = self.agent(first)
        require(not old['ok'] and old['error'] == 'generation_downgrade_rejected')
        require(old['watermark_sha256'] == high['watermark_sha256'] and old['current'] == high['current'])
        corrupt = dict(latest, bundle_sha256='0' * 64)
        bad = self.agent(corrupt)
        require(not bad['ok'] and bad['watermark_sha256'] == high['watermark_sha256'] and bad['current'] == high['current'])
        require(self.request(self.valid_context)[0] != 200)
        require(self.request(self.control_context)[0] == 200)
        self.results['old_corrupt_bundle'] = {'status': 'passed', 'old_error': old['error'], 'corrupt_error': bad['error'],
                                              'watermark_preserved': True, 'applied_generation_preserved': True}
        self.results['agent_process_restart'] = {'status': 'passed', 'probe': 'artifact release manager recreated for every apply; persisted watermark retained'}

    def run(self):
        failed = False
        try:
            self.execute()
        except Exception as error:
            # Exception type only: messages, subprocess and HTTP bodies can
            # contain private fixture credentials.
            failed = True
            self.results['execution'] = {'status': 'failed', 'stage': self.stage, 'error_type': type(error).__name__}
        finally:
            for name in list(self.active_containers):
                try:
                    self.remove_container(name)
                except Exception:
                    failed = True
                    self.results['shutdown'] = {'status': 'failed', 'container': name}
        report = {'source_sha': self.config['source_sha'], 'platform': self.config['platform'],
            'artifacts': self.artifacts, 'provisional': self.provisional, 'complete': False,
            'normal_delivery': 'runtime Agent WebSocket; observed installed bundle' if self.live_bundle_dir else 'explicit harness delivery to artifact release manager',
            'negative_replay_delivery': 'isolated artifact release manager; existing live Agent trust state never mutated',
            'headless_manager_identity': 'explicit fixture identity; runtime authentication unexecuted',
            'observed_at': datetime.now(timezone.utc).isoformat(), 'results': self.results,
            'retained_monotonic_fixture_volume': self.volume,
            'gates': {'G14': {'status': 'failed' if failed else 'partial', 'unexecuted': (['disconnection/reconnect delivery', 'delayed runtime distribution'] if self.live_bundle_dir else ['enrolled Agent WebSocket distribution', 'disconnection/reconnect delivery'])},
                      'G15': {'status': 'partial' if 'old_corrupt_bundle' in self.results else 'unexecuted', 'unexecuted': ['consumer on-disk corruption', 'operator-gated damaged-state recovery']},
                      'G17': {'status': 'unexecuted', 'unexecuted': ['actual older DB restore against newer Agent/consumer watermarks']}},
            'shutdown': 'failed' if self.active_containers else 'all invocation-owned containers stopped',
            'private_material': 'fixture keys and certificates excluded from redacted report; do not export consumer.private',
            'commands': ['management mTLS Client Auth API', 'exact Agent image release eval process_bundle via stdin',
                         'exact Caddy executable TLS verifier and HTTP middleware', 'TLS1.2 new/resumed/keepalive HTTP requests']}
        private_json(self.output / 'report.json', report)
        print(json.dumps({'complete': False, 'provisional': self.provisional,
                          'selected_checks': 'failed' if failed else 'passed', 'report': str(self.output / 'report.json')}))
        return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='private isolated-fixture JSON, including exact Core/Agent IDs')
    parser.add_argument('--output', required=True, help='new private output directory; never export consumer.private')
    parser.add_argument('--resume-output', help='owned earlier private fixture; only unrevoked generation1 baseline can resume')
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text())
        require(config.get('isolated_fixture') is True)
        return PKIHarness(config, args.output, args.resume_output).run()
    except Exception as error:
        print(json.dumps({'complete': False, 'setup': 'failed', 'error_type': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
