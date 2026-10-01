#!/usr/bin/env python3
"""Disposable static consumer: real UDS auth-v2, atomic private file and readback.

Requires an issued application certificate and matching private key. A failed
request never replaces application-owned configuration. Prints metadata only.
"""
import argparse
import base64
import json
import hashlib
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import uuid


class ConsumerError(Exception):
    pass


def exchange(stream, action, params):
    request_id = str(uuid.uuid4())
    stream.write((json.dumps({'request_id': request_id, 'action': action, 'params': params}) + '\n').encode())
    stream.flush()
    line = stream.readline(65537)
    if not line.endswith(b'\n') or len(line) > 65536:
        raise ConsumerError('INVALID_RESPONSE')
    response = json.loads(line)
    if response.get('request_id') != request_id:
        raise ConsumerError('INVALID_RESPONSE')
    if response.get('status') != 'ok':
        code = response.get('error', {}).get('code')
        permitted = {'FORBIDDEN', 'PERMISSION_DENIED', 'CORE_UNAVAILABLE', 'NOT_FOUND', 'SEALED', 'PROOF_FAILED', 'INCOMPATIBLE_VERSION', 'INVALID_CERTIFICATE', 'UNAUTHORIZED'}
        raise ConsumerError(code if code in permitted else 'REQUEST_DENIED')
    return response['data']


def authenticate(stream, certificate, key):
    challenge = exchange(stream, 'authenticate', {'auth_version': 2, 'certificate': base64.b64encode(certificate.read_bytes()).decode()})
    algorithm = challenge['signature_algorithm']
    if algorithm not in ('rsa-pss-sha256', 'ecdsa-sha256') or challenge['auth_version'] != 2:
        raise ConsumerError('INVALID_CHALLENGE')
    expiry = datetime.fromisoformat(challenge['expires_at'].replace('Z', '+00:00'))
    if not 0 < (expiry - datetime.now(timezone.utc)).total_seconds() <= 30:
        raise ConsumerError('INVALID_CHALLENGE')
    der = subprocess.run(['openssl', 'x509', '-in', str(certificate), '-outform', 'DER'], capture_output=True, timeout=10)
    if der.returncode or hashlib.sha256(der.stdout).hexdigest() != challenge['certificate_fingerprint']:
        raise ConsumerError('INVALID_CHALLENGE')
    nonce = base64.b64decode(challenge['challenge'], validate=True)
    fingerprint = bytes.fromhex(challenge['certificate_fingerprint'])
    if len(nonce) != 32 or len(fingerprint) != 32:
        raise ConsumerError('INVALID_CHALLENGE')
    fields = [b'secrethub-uds-auth', b'\x02', algorithm.encode(), challenge['agent_id'].encode(), challenge['connection_id'].encode(), challenge['challenge_id'].encode(), nonce, fingerprint, b'authenticate']
    transcript = b''.join(struct.pack('!I', len(field)) + field for field in fields)
    args = ['openssl', 'dgst', '-sha256', '-sign', str(key)]
    if algorithm == 'rsa-pss-sha256':
        args += ['-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', '-sigopt', 'rsa_mgf1_md:sha256']
    signature = subprocess.run(args, input=transcript, capture_output=True, timeout=10)
    if signature.returncode:
        raise ConsumerError('PROOF_FAILED')
    result = exchange(stream, 'authenticate_proof', {'auth_version': 2, 'connection_id': challenge['connection_id'], 'challenge_id': challenge['challenge_id'], 'signature_algorithm': algorithm, 'signature': base64.b64encode(signature.stdout).decode()})
    if result.get('authenticated') is not True or result.get('auth_version') != 2:
        raise ConsumerError('PROOF_FAILED')


def apply_private(path, data):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.consumer-', delete=False) as target:
            temporary = Path(target.name)
            os.fchmod(target.fileno(), 0o600)
            target.write(json.dumps(data).encode() + b'\n')
            target.flush()
            os.fsync(target.fileno())
        temporary.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    if json.loads(path.read_bytes()) != data or path.stat().st_mode & 0o077:
        raise ConsumerError('READBACK_FAILED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('socket', 'cert', 'key', 'path', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--expect', help='Private fixture JSON value to require before applying')
    args = parser.parse_args()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect(args.socket)
            with connection.makefile('rwb') as stream:
                authenticate(stream, Path(args.cert), Path(args.key))
                data = exchange(stream, 'get_secret', {'path': args.path})
        if args.expect and data['value'] != json.loads(Path(args.expect).read_bytes()):
            raise ConsumerError('UNEXPECTED_VALUE')
        apply_private(args.output, data['value'])
        print(json.dumps({'applied': True, 'readback': True, 'version': data['version'], 'revision': data['revision']}))
        return 0
    except ConsumerError as error:
        print(json.dumps({'applied': False, 'error': str(error)}))
    except Exception:
        print(json.dumps({'applied': False, 'error': 'CONSUMER_UNAVAILABLE'}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
