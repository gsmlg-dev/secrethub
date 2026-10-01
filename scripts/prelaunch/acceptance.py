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
import socket
import ssl
import struct
import subprocess
import time
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
    def __init__(self, config, output):
        self.config = config
        self.output = Path(output)
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        require(config['core_container'].startswith('secrethub-prelaunch-'))
        info = json.loads(command(['docker', 'inspect', config['core_container']]))[0]
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
        self.shares = None

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
        output = command(['docker', 'exec', '-i', self.config['core_container'], '/app/bin/secrethub_core', 'eval', code], payload)
        values = [line[17:] for line in output.splitlines() if line.startswith('PRELAUNCH_RESULT=')]
        require(len(values) == 1)
        return json.loads(values[0])

    def check(self, gate, details, operation):
        started = time.monotonic()
        try:
            operation()
            result = {'status': 'passed', 'evidence': details}
        except Exception as error:
            result = {'status': 'failed', 'error_class': type(error).__name__}
        result['seconds'] = round(time.monotonic() - started, 3)
        self.results[gate] = result
        print(gate + ': ' + result['status'], flush=True)
        self.report()
        return result['status'] == 'passed'

    def report(self):
        report = {key: self.config[key] for key in ('source_sha', 'core_image_id', 'platform')}
        report['commands'] = [
            'python3 -B scripts/prelaunch/acceptance.py --config <private fixture config> --output <private result directory>',
            'docker exec <isolated Core> /app/bin/secrethub_core eval <bounded fixture checks>',
            'protected HTTP and connected LiveView through fixture Caddy mTLS',
            'docker restart <isolated Core>']
        report.update(created_at=datetime.now(timezone.utc).isoformat(), gates=self.results,
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
        require(self.client.json('/v1/sys/init', 'POST', {'secret_shares': 5, 'secret_threshold': 3})[0] == 400)
        require(self.evaluate('SecretHub.Core.Repo.aggregate(SecretHub.Shared.Schemas.VaultConfig, :count) == 1'))

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

    def run(self):
        self.check('G07', 'Caddy mTLS HTTP and connected LiveView; no second login', self.protected_admin)
        self.check('G08', 'missing ingress certificate, separate machine route and external network namespace denied', self.boundary)
        self.check('G09', 'cross-origin mutation, absent CSRF and cross-origin WebSocket denied', self.browser_negatives)
        if self.check('G02', 'concurrent protected initialization; one committed configuration; private shares', self.init):
            self.check('G04', 'concurrent loser and repeated initialize reject without replacing configuration', self.repeated_init)
            self.check('G05', 'malformed/mixed/duplicate/wrong shares rejected; state process remains responsive', self.malformed)
            self.check('G10', 'sealed process live, readiness false, management/unseal available, key/signing denied', self.sealed)
            self.check('G06', 'restart sealed; correct shares recover old static ciphertext under same Vault ID; manual seal no-op', self.restart)
        self.report()
        return 0 if all(self.results[gate]['status'] == 'passed' for gate in ('G02', 'G04', 'G05', 'G06', 'G07', 'G08', 'G09', 'G10')) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text())
        return Harness(config, args.output).run()
    except Exception as error:
        print('Artifact harness failed: ' + type(error).__name__ + ' (details suppressed)')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
