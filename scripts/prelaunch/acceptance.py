#!/usr/bin/env python3
"""Production-artifact checks against explicitly named, disposable fixtures.

Never emits HTTP bodies, RPC diagnostics, cookies, shares or secret values.
The private recovery file is separate from the redacted report.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import time
import uuid
from urllib.parse import urlencode, urlsplit


class CheckFailed(Exception):
    pass


def require(condition):
    if not condition:
        raise CheckFailed()


def command(args, payload=None):
    result = subprocess.run(args, input=payload, capture_output=True, timeout=120)
    require(result.returncode == 0)
    return result.stdout.decode()


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as target:
        json.dump(value, target, indent=2)
        target.write('\n')


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf = None
        self.root = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'meta' and attrs.get('name') == 'csrf-token':
            self.csrf = attrs.get('content')
        if attrs.get('data-phx-session'):
            self.root = attrs


class Client:
    def __init__(self, origin, context):
        self.origin = origin
        self.uri = urlsplit(origin)
        require(self.uri.hostname in ('localhost', '127.0.0.1'))
        self.context = context
        self.cookie = ''
        self.csrf = None

    def request(self, path, method='GET', body=None, headers=None):
        conn = http.client.HTTPSConnection(self.uri.hostname, self.uri.port, context=self.context, timeout=10)
        request_headers = {'accept': 'application/json'}
        if self.cookie:
            request_headers['cookie'] = self.cookie
        if body is not None:
            body = json.dumps(body).encode()
            request_headers.update({'content-type': 'application/json', 'x-csrf-token': self.csrf or '', 'origin': self.origin})
        request_headers.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=request_headers)
            response = conn.getresponse()
            data = response.read(2_000_000)
            require(len(data) < 2_000_000)
            cookie = response.getheader('set-cookie')
            if cookie:
                self.cookie = cookie.split(';', 1)[0]
            return response.status, {name.lower(): value for name, value in response.getheaders()}, data
        finally:
            conn.close()

    def json(self, path, method='GET', body=None, headers=None):
        status, response_headers, data = self.request(path, method, body, headers)
        try:
            value = json.loads(data)
        except ValueError:
            value = None
        return status, response_headers, value

    def session(self):
        status, _, value = self.json('/v1/sys/csrf-token')
        require(status == 200 and isinstance(value.get('csrf_token'), str))
        self.csrf = value['csrf_token']
        return self

    def websocket(self, origin, mount=False):
        page = Page()
        if mount:
            status, _, body = self.request('/vault/init', headers={'accept': 'text/html'})
            require(status == 200)
            page.feed(body.decode())
            require(page.root is not None and page.csrf is not None)
        params = {'vsn': '2.0.0', '_csrf_token': page.csrf or self.csrf or ''}
        connection = socket.create_connection((self.uri.hostname, self.uri.port), timeout=10)
        connection = self.context.wrap_socket(connection, server_hostname=self.uri.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (f'GET /live/websocket?{urlencode(params)} HTTP/1.1\r\nHost: {self.uri.netloc}\r\n'
                   f'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
                   f'Sec-WebSocket-Version: 13\r\nOrigin: {origin}\r\nCookie: {self.cookie}\r\n\r\n')
        try:
            connection.sendall(request.encode())
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                byte = connection.recv(1)
                require(bool(byte))
                header.extend(byte)
                require(len(header) < 65536)
            status = int(header.split(b' ', 2)[1])
            if not mount:
                return status
            require(status == 101)
            payload = ['1', '1', 'lv:' + page.root['id'], 'phx_join', {
                'url': self.origin + '/vault/init', 'params': {'_csrf_token': page.csrf, '_mounts': 0},
                'session': page.root['data-phx-session'], 'static': page.root.get('data-phx-static', '')}]
            data = json.dumps(payload).encode()
            mask = os.urandom(4)
            length = bytes([0x80 | len(data)]) if len(data) < 126 else b'\xfe' + struct.pack('!H', len(data))
            connection.sendall(b'\x81' + length + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(data)))
            for _ in range(8):
                frame = read_exact(connection, 2)
                size = frame[1] & 127
                if size == 126:
                    size = struct.unpack('!H', read_exact(connection, 2))[0]
                if size == 127:
                    size = struct.unpack('!Q', read_exact(connection, 8))[0]
                require(size < 2_000_000)
                reply = json.loads(read_exact(connection, size))
                if reply[3] == 'phx_reply':
                    require(reply[4]['status'] == 'ok')
                    return status
            raise CheckFailed()
        finally:
            connection.close()


def read_exact(connection, size):
    output = bytearray()
    while len(output) < size:
        data = connection.recv(size - len(output))
        require(bool(data))
        output.extend(data)
    return bytes(output)


class Harness:
    def __init__(self, config, output, selected=None, shares_file=None):
        self.config = config
        self.output = Path(output)
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        require(config['core_container'].startswith('secrethub-prelaunch-'))
        info = json.loads(command(['docker', 'inspect', config['core_container']]))[0]
        self.container_info = info
        require(info['Image'] == config['core_image_id'])
        artifact = json.loads(command(['docker', 'image', 'inspect', config['core_image_id']]))[0]
        require(artifact['Os'] + '/' + artifact['Architecture'] == config['platform'])
        require(info['Config']['User'] in ('secrethub', '1001', '1001:1001'))
        self.provisional = config.get('provisional') is True
        if not self.provisional:
            require(config['source_sha'] == (info['Config'].get('Labels') or {}).get('org.opencontainers.image.revision'))
        context = ssl.create_default_context(cafile=config['management_ca'])
        context.load_cert_chain(config['operator_cert'], config['operator_key'])
        self.context = context
        self.client = Client(config['management_origin'], context)
        deadline = time.monotonic() + 60
        while True:
            try:
                self.client.session()
                break
            except Exception:
                require(time.monotonic() < deadline)
                time.sleep(0.5)
        self.results = {f'G{i:02}': {'status': 'unexecuted'} for i in range(1, 21)}
        self.selected = selected or ['G01', 'G02', 'G03', 'G04', 'G05', 'G06', 'G07', 'G08', 'G09', 'G10', 'G18', 'G19', 'G20']
        self.shares = json.loads(Path(shares_file).read_text()) if shares_file else None
        if self.shares is not None:
            require(isinstance(self.shares, list) and len(self.shares) >= 3)
            require(all(isinstance(share, str) for share in self.shares))
        self.fixture_logs = []
        self.fixture_databases = []

    def fixture(self, code, overrides=None, inputs=None, serving=False):
        """Run the same image with normal runtime inputs in an owned container.

        Captured diagnostics stay in memory for the redaction check. Secrets are
        mounted files; they never appear in command arguments or the report.
        """
        name = 'secrethub-prelaunch-check-' + uuid.uuid4().hex[:12]
        environment = dict(item.split('=', 1) for item in self.container_info['Config']['Env'])
        environment.update(overrides or {})
        args = ['docker', 'run', '--rm', '--name', name, '--network', 'host', '-i']
        for mount in self.container_info['Mounts']:
            require(mount['Type'] == 'bind')
            args += ['--mount', 'type=bind,src=' + mount['Source'] + ',dst=' + mount['Destination'] + ',readonly']
        if inputs:
            directory = self.output / name
            directory.mkdir(mode=0o700)
            for key, value in inputs.items():
                environment.pop(key, None)
                environment.pop(key + '_FILE', None)
                if value is not None:
                    target = directory / key
                    target.write_text(value)
                    # The containing host output directory stays owner-only;
                    # the nonroot container can read only this mounted folder.
                    target.chmod(0o644)
                    environment[key + '_FILE'] = '/prelaunch-input/' + key
            directory.chmod(0o755)
            args += ['--mount', 'type=bind,src=' + str(directory.resolve()) + ',dst=/prelaunch-input,readonly']
        for key, value in environment.items():
            args += ['-e', key + '=' + value]
        args += [self.config['core_image_id']]
        args += ['start'] if serving else ['eval', code]
        try:
            result = subprocess.run(args, capture_output=True, timeout=90)
        except subprocess.TimeoutExpired:
            # This name belongs exclusively to this invocation.
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=20)
            raise CheckFailed()
        self.fixture_logs.append(result.stdout + result.stderr)
        return result

    def fixture_value(self, expression, overrides=None, inputs=None, boot=None):
        if boot is None:
            boot = 'Application.ensure_all_started(:secrethub_core); Process.sleep(400); '
        code = 'require Ecto.Query; try do ' + boot + 'IO.puts("PRELAUNCH_RESULT=" <> Jason.encode!(' + expression + ')) rescue _ -> IO.puts("PRELAUNCH_RESULT=false") catch _, _ -> IO.puts("PRELAUNCH_RESULT=false") end'
        result = self.fixture(code, overrides, inputs)
        require(result.returncode == 0)
        values = [line[17:] for line in result.stdout.decode().splitlines() if line.startswith('PRELAUNCH_RESULT=')]
        require(len(values) == 1)
        return json.loads(values[0])

    def database(self, copy=False):
        postgres = self.config['fixture_postgres_container']
        require(postgres.startswith('secrethub-prelaunch-'))
        name = 'secrethub_prelaunch_check_' + uuid.uuid4().hex[:12]
        require(re.fullmatch(r'[a-z0-9_]+', name) is not None)
        pg_socket = self.config.get('fixture_postgres_socket', '/socket')
        command(['docker', 'exec', postgres, 'createdb', '-h', pg_socket, '-U', 'secrethub', name])
        self.fixture_databases.append(name)
        source = self.config.get('fixture_database')
        if copy:
            require(isinstance(source, str) and re.fullmatch(r'[a-z0-9_]+', source) is not None)
            dump = command(['docker', 'exec', postgres, 'pg_dump', '-h', pg_socket, '-U', 'secrethub', '--no-owner', '--no-acl', source])
            command(['docker', 'exec', '-i', postgres, 'psql', '-h', pg_socket, '-U', 'secrethub', '-v', 'ON_ERROR_STOP=1', '-d', name], dump.encode())
        return name, {'DATABASE_URL': 'postgres://secrethub@localhost/' + name + '?socket_dir=/socket'}

    def evaluate(self, expression, unseal=False):
        # Distribution is intentionally disabled. Start only Core in a separate
        # release eval process; private fixture shares travel on stdin, never argv.
        boot = 'Application.ensure_all_started(:secrethub_core); '
        if unseal:
            boot += 'for encoded <- Jason.decode!(IO.read(:stdio, :eof)) |> Enum.take(3), do: (with {:ok, share} <- SecretHub.Shared.Crypto.Shamir.decode_share(encoded), do: SecretHub.Core.Vault.SealState.unseal(share)); '
        boot += 'Process.sleep(100); '
        if unseal:
            # Vault loading is asynchronous. Wait before submitting shares.
            boot = boot.replace('for encoded', 'Process.sleep(300); for encoded', 1)
        code = 'require Ecto.Query; try do ' + boot + 'result = (' + expression + '); IO.puts("PRELAUNCH_RESULT=" <> Jason.encode!(result)) rescue _ -> IO.puts("PRELAUNCH_RESULT=false") catch _, _ -> IO.puts("PRELAUNCH_RESULT=false") end'
        payload = json.dumps(self.shares).encode() if unseal else None
        result = subprocess.run(['docker', 'exec', '-i', self.config['core_container'], '/app/bin/secrethub_core', 'eval', code],
                                input=payload, capture_output=True, timeout=120)
        self.fixture_logs.append(result.stdout + result.stderr)
        require(result.returncode == 0)
        output = result.stdout.decode()
        values = [line[17:] for line in output.splitlines() if line.startswith('PRELAUNCH_RESULT=')]
        require(len(values) == 1)
        return json.loads(values[0])

    def check(self, gate, details, operation):
        started = time.monotonic()
        try:
            evidence = operation()
            result = {'status': 'partial' if isinstance(evidence, dict) and evidence.get('partial') else 'passed', 'evidence': details}
            if isinstance(evidence, dict):
                result['observations'] = evidence
        except Exception as error:
            result = {'status': 'failed', 'error_class': type(error).__name__}
        result['seconds'] = round(time.monotonic() - started, 3)
        self.results[gate] = result
        print(gate + ': ' + result['status'], flush=True)
        self.report()
        return result['status'] == 'passed'

    def report(self):
        report = {key: self.config[key] for key in ('source_sha', 'core_image_id', 'platform')}
        executed = {gate for gate, result in self.results.items() if result['status'] != 'unexecuted'}
        report['commands'] = ['python3 -B scripts/prelaunch/acceptance.py --config <private fixture config> --output <private result directory> --gates <selected gates>']
        if executed & {'G02', 'G04', 'G06', 'G10'}:
            report['commands'].append('docker exec <isolated Core> /app/bin/secrethub_core eval <bounded fixture checks>')
        if executed & {'G02', 'G04', 'G05', 'G06', 'G07', 'G08', 'G09', 'G10'}:
            report['commands'].append('protected HTTP/WebSocket through fixture Caddy mTLS; direct/machine denial probes when selected')
        if 'G06' in executed:
            report['commands'].append('docker restart <isolated Core>')
        if executed & {'G01', 'G03', 'G18', 'G20'}:
            report['commands'].append('docker run --rm <same exact Core image> eval/start <bounded runtime fixture probes>')
        if executed & {'G01', 'G03', 'G18'}:
            report['commands'].append('docker exec <explicit isolated PostgreSQL> createdb/psql/pg_dump <owned disposable databases>')
        report.update(created_at=datetime.now(timezone.utc).isoformat(), gates=self.results,
                      selected_gates=self.selected, disposable_databases=self.fixture_databases,
                      candidate_status='provisional' if self.provisional else 'pending_acceptance',
                      complete=not self.provisional and all(gate['status'] == 'passed' for gate in self.results.values()))
        target = self.output / 'report.json'
        temporary = self.output / '.report.json.tmp'
        with open(temporary, 'w') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
        os.chmod(temporary, 0o600)
        temporary.replace(target)

    def init(self):
        require(self.client.json('/v1/sys/seal-status')[2]['state'] == 'not_initialized')
        def initialize(_):
            return Client(self.config['management_origin'], self.context).session().json('/v1/sys/init', 'POST', {'secret_shares': 5, 'secret_threshold': 3})
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(initialize, range(2)))
        require(sorted(result[0] for result in results) == [200, 400])
        success = next(result for result in results if result[0] == 200)
        self.shares = success[2]['shares']
        require(len(self.shares) == 5)
        private_json(self.output / 'recovery-shares.private.json', self.shares)
        require('no-store' in success[1].get('cache-control', ''))
        require(self.evaluate('SecretHub.Core.Repo.aggregate(SecretHub.Shared.Schemas.VaultConfig, :count) == 1'))

    def repeated_init(self):
        fingerprint = 'SecretHub.Core.Repo.one(SecretHub.Shared.Schemas.VaultConfig) |> :erlang.term_to_binary() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16()'
        original = self.evaluate(fingerprint)
        require(self.client.json('/v1/sys/init', 'POST', {'secret_shares': 5, 'secret_threshold': 3})[0] == 400)
        require(self.evaluate('SecretHub.Core.Repo.aggregate(SecretHub.Shared.Schemas.VaultConfig, :count) == 1'))
        require(self.evaluate(fingerprint) == original)

    def malformed(self):
        prefix = 'secrethub-share-'
        encoded = self.shares[0][len(prefix):]
        raw = bytearray(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        raw[6] ^= 1
        foreign = prefix + base64.urlsafe_b64encode(raw).decode().rstrip('=')
        for value in ('invalid', self.shares[0][:-8], 'x' * 9000, foreign):
            require(self.client.json('/v1/sys/unseal', 'POST', {'share': value})[0] == 400)
        require(self.client.json('/v1/sys/unseal', 'POST', {'share': self.shares[0]})[0] == 200)
        require(self.client.json('/v1/sys/unseal', 'POST', {'share': self.shares[0]})[0] == 400)
        # Duplicate rejection clears partial progress; begin a new attempt.
        require(self.client.json('/v1/sys/unseal', 'POST', {'share': self.shares[0]})[0] == 200)
        # Complete a wrong reconstruction using original metadata, then prove reset.
        for index, share in enumerate(self.shares[1:3]):
            raw = bytearray(base64.urlsafe_b64decode(share[len(prefix):] + '=' * (-len(share[len(prefix):]) % 4)))
            if index == 0:
                raw[-1] ^= 1
            wrong = prefix + base64.urlsafe_b64encode(raw).decode().rstrip('=')
            status = self.client.json('/v1/sys/unseal', 'POST', {'share': wrong})[0]
        require(status == 400)
        require(self.client.json('/v1/sys/seal-status')[2]['sealed'] is True)
        require(self.client.json('/v1/sys/health/live')[0] == 200)

    def sealed(self):
        require(self.client.json('/v1/sys/health/live')[0] == 200)
        require(self.client.json('/v1/sys/health/ready')[0] == 503)
        require(self.client.json('/v1/sys/health/management')[0] == 200)
        require(self.evaluate('match?({:error, :sealed}, SecretHub.Core.Vault.SealState.get_master_key())'))
        require(self.evaluate('match?({:error, _}, SecretHub.Core.PKI.ClientAuth.get_active_ca_and_key())'))
        require(self.client.request('/vault/unseal', headers={'accept': 'text/html'})[0] == 200)

    def protected_admin(self):
        require(self.client.request('/vault/init', headers={'accept': 'text/html'})[0] == 200)
        require(self.client.websocket(self.config['management_origin'], mount=True) == 101)

    def boundary(self):
        untrusted = Client(self.config['management_origin'], ssl.create_default_context(cafile=self.config['management_ca']))
        try:
            untrusted.request('/vault/init')
        except (ssl.SSLError, OSError, http.client.HTTPException):
            pass
        else:
            raise CheckFailed()
        machine = urlsplit(self.config['machine_backend'])
        require(machine.hostname in ('127.0.0.1', 'localhost'))
        connection = http.client.HTTPConnection(machine.hostname, machine.port, timeout=10)
        try:
            connection.request('GET', '/vault/init', headers={'x-forwarded-client-cert': 'operator', 'x-secrethub-client-id': 'operator'})
            require(connection.getresponse().status == 404)
        finally:
            connection.close()
        # A caller from another network namespace must not reach private backend.
        result = subprocess.run(['docker', 'run', '--rm', '--network', 'bridge', '--entrypoint', 'curl', self.config['core_image_id'], '--connect-timeout', '3', '-fsS', self.config['external_backend'] + '/vault/init'], capture_output=True, timeout=15)
        require(result.returncode != 0)
        if not self.config.get('rejected_operator_cert') or not self.config.get('rejected_operator_key'):
            return {'partial': True, 'no_client_certificate_machine_routes_and_external_backend': 'denied',
                    'wrong_ingress_certificate': 'unexecuted_requires_rejected_operator_cert_and_key'}
        context = ssl.create_default_context(cafile=self.config['management_ca'])
        context.load_cert_chain(self.config['rejected_operator_cert'], self.config['rejected_operator_key'])
        try:
            Client(self.config['management_origin'], context).request('/vault/init')
        except (ssl.SSLError, OSError, http.client.HTTPException):
            pass
        else:
            raise CheckFailed()

    def browser_negatives(self):
        status = self.client.json('/v1/sys/init', 'POST', {'secret_shares': 5, 'secret_threshold': 3}, {'origin': 'https://untrusted.invalid'})[0]
        require(status == 403)
        status = self.client.json('/v1/sys/init', 'POST', {'secret_shares': 5, 'secret_threshold': 3}, {'x-csrf-token': ''})[0]
        require(status == 403)
        require(self.client.websocket('https://untrusted.invalid') == 403)

    def unseal(self):
        for share in self.shares[:3]:
            require(self.client.json('/v1/sys/unseal', 'POST', {'share': share})[0] == 200)
        require(self.client.json('/v1/sys/seal-status')[2]['sealed'] is False)

    def restart(self):
        self.unseal()
        require(self.evaluate('match?({:ok, _}, SecretHub.Core.Secrets.create_secret(%{name: "Artifact fixture", secret_path: "prelaunch.static", secret_data: %{"value" => "disposable-prelaunch-v1"}}))', unseal=True))
        identity = self.evaluate('SecretHub.Core.Repo.one(Ecto.Query.from(v in SecretHub.Shared.Schemas.VaultConfig, select: v.id))')
        command(['docker', 'restart', self.config['core_container']])
        deadline = time.monotonic() + 60
        while True:
            try:
                if self.client.json('/v1/sys/seal-status')[2]['state'] == 'sealed':
                    break
            except Exception:
                pass
            require(time.monotonic() < deadline)
            time.sleep(0.5)
        self.unseal()
        require(self.evaluate('case SecretHub.Core.Secrets.read_decrypted("prelaunch.static") do {:ok, data, _} -> data == %{"value" => "disposable-prelaunch-v1"}; _ -> false end', unseal=True))
        require(self.evaluate('SecretHub.Core.Repo.one(Ecto.Query.from(v in SecretHub.Shared.Schemas.VaultConfig, select: v.id))') == identity)
        require(self.client.json('/v1/sys/seal', 'POST', {})[2]['sealed'] is False)

    def runtime_keys(self):
        _, inputs = self.database()
        keys = [base64.b64encode(os.urandom(32)).decode() for _ in range(2)]
        overrides = {'AUDIT_HMAC_KEY_ID': 'fixture-runtime-key'}
        first_inputs = dict(inputs, AUDIT_HMAC_KEY=keys[0])
        require(self.fixture_value('(SecretHub.Core.Release.migrate(); true)', overrides, first_inputs,
                                   boot='') is True)
        event = '%{event_type: "vault_initialized", actor_type: "system", actor_id: "prelaunch-fixture", resource_type: "vault", resource_id: "fixture-runtime-key", event_data: %{fixture: true}}'
        require(self.fixture_value('(match?({:ok, _}, SecretHub.Core.Audit.log_event(' + event + ')) and SecretHub.Core.Audit.verify_chain() == {:ok, :valid})', overrides, first_inputs) is True)
        # Verify the very same row under each runtime key. Different event IDs
        # or timestamps cannot account for this result.
        verify = 'SecretHub.Core.Audit.verify_chain() == {:ok, :valid}'
        require(self.fixture_value(verify, overrides, dict(inputs, AUDIT_HMAC_KEY=keys[1])) is False)
        require(self.fixture_value(verify, overrides, first_inputs) is True)
        for value in (None, base64.b64encode(b'dev-audit-secret').decode(), base64.b64encode(b'change-me-in-production').decode()):
            result = self.fixture('', overrides, dict(inputs, AUDIT_HMAC_KEY=value), serving=True)
            require(result.returncode != 0)
            require(b'AUDIT_HMAC_KEY' in result.stdout + result.stderr)
        return {'same_image_runtime_key_reverification': True, 'missing_and_known_development_keys_block_start': True}

    def unavailable(self):
        _, inputs = self.database()
        boot = ('Application.ensure_all_started(:ecto_sql); Application.ensure_all_started(:postgrex); '
                '{:ok, _} = SecretHub.Core.Repo.start_link(); '
                '{:ok, _} = SecretHub.Core.Vault.SealState.start_link(); Process.sleep(2500); ')
        check = ('(status = SecretHub.Core.Vault.SealState.status(); '
                 'status.state == :unavailable and status.sealed and '
                 'match?({:error, _}, SecretHub.Core.Vault.SealState.initialize(5, 3)))')
        require(self.fixture_value(check, inputs=inputs, boot=boot) is True)
        unavailable = {'DATABASE_URL': 'postgres://secrethub@127.0.0.1:1/prelaunch_unavailable'}
        require(self.fixture_value(check, inputs=unavailable, boot=boot) is True)
        # No table/row was created by the rejected initialization.
        name = self.fixture_databases[-1]
        sql = ['docker', 'exec', self.config['fixture_postgres_container'], 'psql', '-h', self.config.get('fixture_postgres_socket', '/socket'), '-U', 'secrethub', '-At', '-d', name]
        value = command(sql + [
                         '-c', "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"])
        require(value.strip() == '0')
        command(sql + ['-v', 'ON_ERROR_STOP=1', '-c', 'CREATE TABLE vault_config(id bigint)'])
        require(self.fixture_value(check, inputs=inputs, boot=boot) is True)
        require(command(sql + ['-c', 'SELECT count(*) FROM vault_config']).strip() == '0')
        return {'unmigrated_and_corrupt_schema_and_unreachable_database': 'unavailable_not_empty', 'destructive_initialization': False,
                'probe': 'production release eval starts runtime Repo and Vault; serving fixture untouched'}

    def compatibility(self):
        _, inputs = self.database(copy=True)
        require(self.fixture_value('(SecretHub.Core.Release.migrate(); true)', inputs=inputs,
                                   boot='Application.load(:secrethub_core); ') is True)
        expression = ('(before = SecretHub.Core.Repo.query!("SELECT version FROM schema_migrations ORDER BY version").rows; '
                      'vault = SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.VaultConfig); '
                      'audit = SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.AuditLog); '
                      'ciphertext = SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.Secret); '
                      'versions = SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.SecretVersion); '
                      'blocked = try do SecretHub.Core.Release.rollback(SecretHub.Core.Repo, 20261001000001); false rescue _ -> true end; '
                      'blocked and before == SecretHub.Core.Repo.query!("SELECT version FROM schema_migrations ORDER BY version").rows '
                      'and vault == SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.VaultConfig) '
                      'and audit == SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.AuditLog) '
                      'and ciphertext == SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.Secret) '
                      'and versions == SecretHub.Core.Repo.all(SecretHub.Shared.Schemas.SecretVersion))')
        require(self.fixture_value(expression, inputs=inputs) is True)
        return {'partial': True, 'current_migrations': 'idempotent_on_isolated_database_copy',
                'incompatible_downgrade': 'refused_data_and_schema_preserved',
                'older_binary_upgrade_and_compatible_binary_rollback': 'unexecuted_requires_selected_older_artifact'}

    def redaction(self):
        result = subprocess.run(['docker', 'logs', self.config['core_container']], capture_output=True, timeout=20)
        require(result.returncode == 0)
        logs = result.stdout + result.stderr
        content = b'\n'.join([logs] + self.fixture_logs)
        for path in self.config.get('additional_private_logs', []):
            content += b'\n' + Path(path).read_bytes()
        needles = [b'disposable-prelaunch-v1']
        if self.shares:
            needles.extend(share.encode() for share in self.shares)
        # Inspect only runtime-input mounts, never emit contents or matches.
        for mount in self.container_info['Mounts']:
            if mount['Destination'] == '/fixture':
                for path in Path(mount['Source']).iterdir():
                    if path.is_file():
                        value = path.read_bytes().strip()
                        if len(value) >= 16:
                            needles.append(value)
        for directory in self.output.glob('secrethub-prelaunch-check-*'):
            for path in directory.iterdir():
                value = path.read_bytes().strip()
                if len(value) >= 16:
                    needles.append(value)
        # Runtime Base64 input and the decoded key's common diagnostic forms
        # must all stay out of output; checking only the encoded file is weaker.
        for needle in list(needles):
            try:
                decoded = base64.b64decode(needle, validate=True)
            except ValueError:
                continue
            if len(decoded) >= 16:
                needles += [decoded, decoded.hex().encode(), decoded.hex().upper().encode()]
        report_path = self.output / 'report.json'
        if report_path.exists():
            content += b'\n' + report_path.read_bytes()
        require(not any(needle in content for needle in needles))
        require(re.search(rb'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----', content) is None)
        require(re.search(rb'(?:postgres(?:ql)?|ecto|https?)://[^\s/]*:[^\s/@]+@', content) is None)
        # This run does not deliberately create a VM crash dump. Say so rather
        # than transferring source redaction tests to crash-artifact acceptance.
        return {'partial': True, 'captured_core_and_fixture_logs': 'no_known_fixture_secret_or_private_key_marker',
                'additional_private_logs_scanned': len(self.config.get('additional_private_logs', [])),
                'crash_dump_fault_injection': 'unexecuted', 'private_inputs_and_shares': 'excluded_from_export'}

    def worker(self):
        expression = ('(alias SecretHub.Core.Workers.ClientAuthCRLRefresher; '
                      'before = SecretHub.Core.Health.check_background_jobs(); '
                      ':ok = Supervisor.terminate_child(SecretHub.Core.Supervisor, ClientAuthCRLRefresher); '
                      'stopped = SecretHub.Core.Health.check_background_jobs(); '
                      'health = SecretHub.Core.Health.readiness(); '
                      'before == {:ok, %{required: true, retry_attempt: 0}} '
                      'and stopped == {:error, %{reason: "crl_worker_unavailable"}} '
                      'and match?({:error, %{checks: %{background_jobs: %{status: "failing"}}}}, health))')
        require(self.fixture_value(expression) is True)
        return {'healthy_worker_observed_before_stop': True, 'stopped_required_worker': 'readiness_background_jobs_failing',
                'probe': 'separate production release eval; serving Core not stopped'}

    def run(self):
        checks = [
            ('G07', 'Caddy mTLS HTTP and connected LiveView; no second login', self.protected_admin),
            ('G08', 'missing ingress certificate, separate machine route and external network namespace denied', self.boundary),
            ('G09', 'cross-origin mutation, absent CSRF and cross-origin WebSocket denied', self.browser_negatives),
            ('G02', 'concurrent protected initialization; one committed configuration; private shares', self.init),
            ('G04', 'concurrent loser and repeated initialize reject without replacing configuration', self.repeated_init),
            ('G05', 'malformed/mixed/duplicate/wrong shares rejected; state process remains responsive', self.malformed),
            ('G10', 'sealed process live, readiness false, management/unseal available, key/signing denied', self.sealed),
            ('G06', 'restart sealed; correct shares recover old static ciphertext under same Vault ID; manual seal no-op', self.restart),
            ('G01', 'same production image runtime audit keys; missing/development keys block startup', self.runtime_keys),
            ('G03', 'unreachable database and unmigrated schema refuse initialization', self.unavailable),
            ('G18', 'current migration and guarded incompatible downgrade on disposable database copy', self.compatibility),
            ('G20', 'production health detects stopped required worker', self.worker),
            ('G19', 'scan captured diagnostics for private fixture inputs and plaintext markers', self.redaction)]
        for gate, details, operation in checks:
            if gate in self.selected:
                if gate in ('G05', 'G06') and self.shares is None:
                    self.results[gate] = {'status': 'unexecuted', 'reason': 'requires_successful_initialization_or_private_resume_shares'}
                    continue
                self.check(gate, details, operation)
        self.report()
        return 0 if all(self.results[gate]['status'] == 'passed' for gate in self.selected) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--gates', help='comma-separated selected gates; omitted gates remain unexecuted')
    parser.add_argument('--shares-file', help='private existing fixture shares; never reinitializes a database')
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text())
        selected = args.gates.split(',') if args.gates else None
        if selected:
            require(len(set(selected)) == len(selected) and all(re.fullmatch(r'G(?:0[1-9]|1[0-9]|20)', gate) for gate in selected))
        return Harness(config, args.output, selected, args.shares_file).run()
    except Exception as error:
        print('Artifact harness failed: ' + type(error).__name__ + ' (details suppressed)')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
