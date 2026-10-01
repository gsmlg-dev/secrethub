#!/usr/bin/env python3
"""Partial G12/G13 evidence from the real auth-v2 UDS static consumer."""
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
import uuid

from acceptance import CheckFailed, private_json, require
from recovery_acceptance import private_file
from runtime_acceptance import RuntimeHarness


UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
MARKER = 'STATIC_PRIVATE='
POLICY_FIELDS = ('name', 'description', 'policy_document', 'entity_bindings', 'max_ttl_seconds', 'deny_policy')

# Inspect through the consumer UID, never through the host operator after chown.
FILE_STATE = r'''import hashlib,json,os,pathlib,stat
root=pathlib.Path('/consumer-fixture')
assert os.getuid()==1002 and root.stat().st_uid==1002 and root.stat().st_mode & 0o077==0
for name in ('app.crt','app.key','expected1.json','expected2.json'):
    file=root/name
    assert not file.is_symlink() and stat.S_ISREG(file.stat().st_mode)
    assert file.stat().st_uid==1002 and file.stat().st_mode & 0o077==0
output=root/'output.json'
result={'uid':1002,'temporary_files_absent':not any(root.glob('.consumer-*')),'exists':output.exists()}
if output.exists():
    assert not output.is_symlink() and stat.S_ISREG(output.stat().st_mode)
    info=output.stat()
    assert info.st_uid==1002 and info.st_mode & 0o077==0
    raw=output.read_bytes()
    result.update(inode=info.st_ino,device=info.st_dev,mode=stat.S_IMODE(info.st_mode),
        sha256=hashlib.sha256(raw).hexdigest(),matches1=json.loads(raw)==json.loads((root/'expected1.json').read_bytes()),
        matches2=json.loads(raw)==json.loads((root/'expected2.json').read_bytes()))
print(json.dumps(result))'''

READ_EXPECT = r'''import pathlib,sys
root=pathlib.Path('/consumer-fixture')
assert sys.argv[1] in ('expected1.json','expected2.json')
file=root/sys.argv[1]
assert not file.is_symlink() and file.stat().st_size<=65536
sys.stdout.buffer.write(file.read_bytes())'''

# Private values and shares are stdin-only; only fixed metadata leaves this VM.
CORE_EVAL = r'''require Ecto.Query
try do
  {:ok, _} = Application.ensure_all_started(:secrethub_core)
  :ok = Supervisor.terminate_child(SecretHub.Core.Supervisor, SecretHub.Core.Workers.ClientAuthCRLRefresher)
  true = Enum.all?([:secrethub_web, :secrethub_agent], fn app ->
    app not in Enum.map(Application.started_applications(), &elem(&1, 0))
  end)
  input = Jason.decode!(IO.read(:stdio, :eof))
  alias SecretHub.Core.{Repo, Policies, Secrets}
  alias SecretHub.Shared.Schemas.{Secret, SecretPathRevision, Application, Agent, AgentEnrollment, ClusterNode}
  serving_node_id = SecretHub.Shared.RuntimeSecrets.read!("SECRET_HUB_PRELAUNCH_SERVING_NODE_ID")
  eval_node_id = System.fetch_env!("SECRET_HUB_CLUSTER_NODE_ID")
  true = eval_node_id != serving_node_id
  true = Elixir.Application.get_env(:secrethub_core, :cluster_node_id) == eval_node_id
  Repo.get_by!(ClusterNode, node_id: eval_node_id)
  serving_snapshot = fn ->
    node = Repo.get_by!(ClusterNode, node_id: serving_node_id)
    Map.take(node, [:node_id, :incarnation_id, :started_at, :hostname, :status, :version])
      |> Map.put(:capabilities, node.metadata["capabilities"])
  end
  serving_before = serving_snapshot.()
  fields = ~w(name description policy_document entity_bindings max_ttl_seconds deny_policy)a
  metadata = fn ->
    secret = Repo.get!(Secret, input["secret_id"])
    true = secret.secret_type == :static and secret.secret_path == input["path"]
    revision = Repo.one!(Ecto.Query.from(r in SecretPathRevision, where: r.secret_path == ^secret.secret_path))
    %{version: secret.version, revision: revision.revision}
  end
  result = case input["operation"] do
    "database_status" ->
      rows = Repo.all(Ecto.Query.from(e in AgentEnrollment,
        where: e.hostname == ^input["hostname"], join: a in Agent, on: a.agent_id == e.agent_id,
        select: %{enrollment_id: e.id, status: e.status, agent_id: a.agent_id,
          heartbeat: a.last_heartbeat_at, certificate_id: a.certificate_id}))
      %{rows: rows}
    "enrollment_ids" ->
      %{ids: Repo.all(Ecto.Query.from(e in AgentEnrollment,
        where: e.hostname == ^input["hostname"], order_by: e.id, select: e.id))}
    "preflight" ->
      Repo.get!(Application, input["app_id"])
      agent = Repo.get!(Agent, input["agent_uuid"])
      policies = for id <- input["policy_ids"] do
        {:ok, policy} = Policies.get_policy(id)
        true = policy.entity_bindings == ["application:" <> input["app_id"]] and not policy.deny_policy
        %{id: id, attrs: Map.take(policy, fields)}
      end
      %{secret: metadata.(), policies: policies, agent_runtime_id: agent.agent_id}
    "update" ->
      wait = fn wait, deadline ->
        state = SecretHub.Core.Vault.SealState.status()
        if state.state == :sealed and state.initialized do
          state
        else
          true = System.monotonic_time(:millisecond) < deadline
          Process.sleep(100)
          wait.(wait, deadline)
        end
      end
      status = wait.(wait, System.monotonic_time(:millisecond) + 15000)
      true = length(input["shares"]) >= status.threshold
      for encoded <- Enum.take(input["shares"], status.threshold) do
        {:ok, share} = SecretHub.Shared.Crypto.Shamir.decode_share(encoded)
        {:ok, _} = SecretHub.Core.Vault.SealState.unseal(share)
      end
      {:ok, existing, _} = Secrets.read_decrypted(input["path"])
      existing_value = case existing do %{"value" => value} -> value; value -> value end
      true = existing_value == input["expected1"]
      metadata.()
      {:ok, _} = Secrets.update_secret(input["secret_id"], %{secret_data: %{"value" => input["expected2"]}})
      metadata.()
    "revoke" ->
      {:ok, policy} = Policies.get_policy(input["policy_id"])
      true = Map.take(policy, fields) == Map.new(input["attrs"], fn {key, value} -> {String.to_existing_atom(key), value} end)
      true = policy.entity_bindings == ["application:" <> input["app_id"]] and not policy.deny_policy
      {:ok, _} = Policies.delete_policy(policy.id)
      %{deleted: true}
    "restore" ->
      attrs = input["attrs"]
      true = attrs["entity_bindings"] == ["application:" <> input["app_id"]] and attrs["deny_policy"] == false
      case Policies.get_policy_by_name(attrs["name"]) do
        {:ok, policy} ->
          true = Map.take(policy, fields) == Map.new(attrs, fn {key, value} -> {String.to_existing_atom(key), value} end)
          %{id: policy.id, original_binding_restored: true}
        {:error, "Policy not found"} ->
          {:ok, policy} = Policies.create_policy(attrs)
          %{id: policy.id, original_binding_restored: true}
      end
  end
  IO.puts("STATIC_PRIVATE=" <> Jason.encode!(%{result: result, eval_node_id: eval_node_id,
    serving_before: serving_before, serving_after: serving_snapshot.()}))
rescue
  _ -> IO.puts("STATIC_PRIVATE=false")
catch
  _, _ -> IO.puts("STATIC_PRIVATE=false")
end'''


def private_result(raw):
    values = [line[len(MARKER):] for line in raw.decode().splitlines() if line.startswith(MARKER)]
    require(len(values) == 1)
    result = json.loads(values[0])
    require(isinstance(result, dict))
    return result


def consumer_result(raw, returncode):
    result = json.loads(raw)
    require(isinstance(result, dict))
    if returncode == 0:
        require(set(result) == {'applied', 'readback', 'version', 'revision'})
        require(result['applied'] is True and result['readback'] is True)
        require(all(type(result[key]) is int and result[key] > 0 for key in ('version', 'revision')))
    else:
        require(set(result) == {'applied', 'error'} and result['applied'] is False)
        require(result['error'] in {'FORBIDDEN', 'PERMISSION_DENIED', 'CORE_UNAVAILABLE', 'REQUEST_DENIED'})
    return result


def file_preserved(before, after):
    return before.get('exists') is True and before == after and after.get('temporary_files_absent') is True


def serving_identity(observation):
    return {key: observation[key] for key in
            ('node_id', 'incarnation_id', 'started_at', 'hostname', 'version', 'capabilities')}


def validate_config(config):
    require(config.get('isolated_fixture') is True)
    require(type(config.get('provisional', False)) is bool and config['platform'] == 'linux/amd64')
    require(re.fullmatch(r'[0-9a-f]{40}', config['source_sha']) is not None)
    for key in ('core_image_id', 'agent_image_id', 'consumer_image_id'):
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', config[key]) is not None)
    fixture = config['static_fixture']
    for key in ('secret_id', 'app_id', 'agent_uuid'):
        require(re.fullmatch(UUID, fixture[key]) is not None)
    require(isinstance(fixture['policy_ids'], list) and fixture['policy_ids'])
    require(len(set(fixture['policy_ids'])) == len(fixture['policy_ids']))
    require(all(re.fullmatch(UUID, value) is not None for value in fixture['policy_ids']))
    require(fixture.get('cache_ttl_seconds') == 300 and type(fixture['cache_ttl_seconds']) is int)
    require(fixture.get('expected_versions') == [1, 2])
    require(all(type(value) is int for value in fixture['expected_versions']))
    for key in ('path', 'denied_path'):
        require(re.fullmatch(r'prelaunch\.[a-zA-Z0-9_.-]+', fixture[key]) is not None)
    require(fixture['path'] != fixture['denied_path'])
    directory = Path(fixture['directory'])
    require(directory.is_absolute() and not directory.is_symlink() and ',' not in str(directory))
    directory = directory.resolve(strict=True)
    require(directory.is_dir() and directory.stat().st_uid == 1002 and directory.stat().st_mode & 0o077 == 0)
    fixture['directory'] = str(directory)
    return config


class StaticHarness(RuntimeHarness):
    def __init__(self, config, output, shares_file):
        super().__init__(config, output, shares_file)
        self.fixture = config['static_fixture']
        self.stage = 'preflight'
        self.owner = 'secrethub-prelaunch-static-' + uuid.uuid4().hex[:12]
        self.active_containers = set()
        self.paused = False
        self.core_needs_unseal = False
        self.pending_policies = {}
        self.regranted_ids = {}
        self.results = {}
        self.cluster_phase = 'before_core_restart'
        self.cluster_observations = []
        self.core_eval_node_ids = []
        self.eval_environment_files = {
            'core': self.write_environment(self.core.container_info['Config']['Env'], 'core'),
            'agent': self.write_environment(self.agent_info['Config']['Env'], 'agent')}
        image = json.loads(self.command(['docker', 'image', 'inspect', config['consumer_image_id']]).stdout)[0]
        require(image['Id'] == config['consumer_image_id'] and image['Os'] + '/' + image['Architecture'] == config['platform'])
        require(image['Config']['User'] == '1002:1002')
        socket_path = Path(self.environment['SECRET_HUB_AGENT_SOCKET_PATH'])
        mounts = [mount for mount in self.agent_info['Mounts'] if mount['Type'] == 'bind' and
                  Path(mount['Destination']) in socket_path.parents]
        require(mounts)
        mount = max(mounts, key=lambda item: len(item['Destination']))
        require(socket_path.relative_to(mount['Destination']) == Path('run/agent.sock'))
        self.agent_directory = Path(mount['Source']).resolve(strict=True)
        require(self.agent_directory.is_dir() and ',' not in str(self.agent_directory))
        self.file_state()
        program_hash = self.consumer_python('import hashlib; print(hashlib.sha256(open("/consumer/static-consumer.py","rb").read()).hexdigest())').stdout.decode().strip()
        require(program_hash == hashlib.sha256((Path(__file__).parent / 'static-consumer.py').read_bytes()).hexdigest())
        self.program_hash = program_hash

    def command(self, args, payload=None, timeout=45, check=True, private_stdout=False):
        try:
            result = subprocess.run(args, input=payload, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.diagnostics.append((b'' if private_stdout else error.stdout or b'') + (error.stderr or b''))
            raise CheckFailed() from None
        self.diagnostics.append((b'' if private_stdout else result.stdout) + result.stderr)
        if check:
            require(result.returncode == 0)
        return result

    def write_environment(self, entries, role):
        environment = dict(entry.split('=', 1) for entry in entries)
        require(all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key) and
                    '\n' not in value and '\r' not in value and '\x00' not in value
                    for key, value in environment.items()))
        environment.update(RELEASE_DISTRIBUTION='none', ERL_CRASH_DUMP='/dev/null')
        if role == 'core':
            original_id = environment.pop('SECRET_HUB_CLUSTER_NODE_ID', None)
            original_file = environment.pop('SECRET_HUB_CLUSTER_NODE_ID_FILE', None)
            require((original_id is None) != (original_file is None))
            self.serving_node_id = original_id
            environment.pop('SECRET_HUB_PRELAUNCH_SERVING_NODE_ID', None)
            environment.pop('SECRET_HUB_PRELAUNCH_SERVING_NODE_ID_FILE', None)
            if original_id is not None:
                require(original_id)
                environment['SECRET_HUB_PRELAUNCH_SERVING_NODE_ID'] = original_id
            else:
                require(original_file)
                environment['SECRET_HUB_PRELAUNCH_SERVING_NODE_ID_FILE'] = original_file
            environment.update(SECRETHUB_ROLE='core', PHX_SERVER='',
                SECRET_HUB_AGENT_ENDPOINT_SERVER='false', SECRET_HUB_MACHINE_ENDPOINT_SERVER='false',
                SECRET_HUB_ADMIN_ENDPOINT_SERVER='false')
        path = self.output / (role + '-eval.private.env')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as target:
            target.write(''.join(key + '=' + value + '\n' for key, value in environment.items()))
        return path

    def eval_args(self, name, role, program):
        require(role in ('core', 'agent') and name.startswith(self.owner + '-' + role + '-eval-'))
        uid = '1001' if role == 'core' else '1002'
        info = self.core.container_info if role == 'core' else self.agent_info
        require(info['Image'] == self.config[role + '_image_id'])
        args = ['docker', 'run', '--rm', '--pull', 'never', '--name', name,
            '--label', 'secrethub.prelaunch.owner=' + self.owner, '--network', 'none',
            '--user', uid + ':' + uid, '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--no-healthcheck', '-i',
            '--tmpfs', '/app/tmp:rw,noexec,nosuid,uid=' + uid + ',gid=' + uid + ',mode=700',
            '--env-file', str(self.eval_environment_files[role])]
        if role == 'core':
            require(name != self.serving_node_id)
            # Set after the environment file; no inherited *_FILE source remains.
            args += ['-e', 'SECRET_HUB_CLUSTER_NODE_ID=' + name]
        for mount in info['Mounts']:
            require(mount['Type'] in ('bind', 'tmpfs'))
            if mount['Type'] == 'bind':
                source, destination = mount['Source'], mount['Destination']
                require(Path(source).is_absolute() and Path(destination).is_absolute() and
                        ',' not in source and ',' not in destination)
                args += ['--mount', 'type=bind,src=' + source + ',dst=' + destination + ',readonly']
        args += ['--entrypoint', '/app/bin/secrethub_' + role,
                 self.config[role + '_image_id'], 'eval', program]
        return args

    def owned_eval(self, role, program, payload=None):
        # A previous unconfirmed VM must never overlap a subsequent operation.
        require(not any('-core-eval-' in name or '-agent-eval-' in name for name in self.active_containers))
        name = self.owner + '-' + role + '-eval-' + uuid.uuid4().hex[:12]
        args = self.eval_args(name, role, program)
        require(not self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).stdout.strip())
        self.active_containers.add(name)
        if role == 'core':
            self.core_eval_node_ids.append(name)
        try:
            result = self.command(args, payload=payload, timeout=75)
        finally:
            # This confirms daemon-side VM absence even when the local CLI timed out.
            self.remove_container(name)
        return result

    def database_status(self):
        return self.core_private('database_status')['rows']

    def enrollment_ids(self):
        return self.core_private('enrollment_ids')['ids']

    def agent_value(self, expression):
        code = ('try do Application.load(:secrethub_agent); IO.puts("STATIC_PRIVATE=" <> Jason.encode!(' +
                expression + ')) rescue _ -> IO.puts("STATIC_PRIVATE=false") end')
        return private_result(self.owned_eval('agent', code).stdout)

    def remove_container(self, name):
        require(name in self.active_containers and name.startswith(self.owner + '-'))
        names = self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).stdout
        if names.strip():
            self.command(['docker', 'rm', '-f', name], timeout=20)
        require(not self.command(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).stdout.strip())
        self.active_containers.remove(name)

    def consumer(self, arguments, python=False, writable=False, private_stdout=False):
        name = self.owner + '-consumer-' + uuid.uuid4().hex[:8]
        self.active_containers.add(name)
        args = ['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none',
            '--user', '1002:1002', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--mount', 'type=bind,src=' + self.fixture['directory'] + ',dst=/consumer-fixture' + ('' if writable else ',readonly')]
        if python:
            args += ['--entrypoint', 'python3']
        else:
            args += ['--mount', 'type=bind,src=' + str(self.agent_directory) + ',dst=/agent-fixture,readonly']
        args += [self.config['consumer_image_id']] + arguments
        try:
            return self.command(args, timeout=70, check=False, private_stdout=private_stdout)
        finally:
            self.remove_container(name)

    def consumer_python(self, code, arguments=None, private_stdout=False):
        result = self.consumer(['-B', '-c', code] + (arguments or []), python=True, private_stdout=private_stdout)
        require(result.returncode == 0)
        return result

    def file_state(self):
        result = json.loads(self.consumer_python(FILE_STATE).stdout)
        require(result['uid'] == 1002 and result['temporary_files_absent'] is True)
        return result

    def read_expect(self, number):
        return json.loads(self.consumer_python(READ_EXPECT, ['expected' + str(number) + '.json'], private_stdout=True).stdout)

    def core_private(self, operation, extra=None):
        payload = dict(self.fixture, operation=operation, hostname=self.hostname)
        payload.pop('directory')
        if extra:
            payload.update(extra)
        if operation == 'update':
            payload.update(shares=self.core.shares, expected1=self.read_expect(1), expected2=self.read_expect(2))
            require(payload['expected1'] != payload['expected2'])
        result = self.owned_eval('core', CORE_EVAL, json.dumps(payload).encode())
        observed = private_result(result.stdout)
        before, after = observed['serving_before'], observed['serving_after']
        require(observed['eval_node_id'].startswith(self.owner + '-core-eval-'))
        require(observed['eval_node_id'] != before['node_id'])
        entry = {'operation': operation, 'phase': self.cluster_phase, 'eval_node_id': observed['eval_node_id'],
                 'before': before, 'after': after}
        preserved = serving_identity(before) == serving_identity(after)
        if self.cluster_observations:
            previous = self.cluster_observations[-1]
            if previous['phase'] == self.cluster_phase:
                preserved &= serving_identity(previous['after']) == serving_identity(before)
        entry['identity_preserved'] = preserved
        self.cluster_observations.append(entry)
        require(preserved)
        require(isinstance(observed['result'], dict))
        return observed['result']

    def read(self, number=2, denied=False):
        before = self.file_state()
        args = ['--socket', '/agent-fixture/run/agent.sock', '--cert', '/consumer-fixture/app.crt',
                '--key', '/consumer-fixture/app.key', '--path', self.fixture['denied_path'] if denied else self.fixture['path'],
                '--output', '/consumer-fixture/output.json', '--expect', '/consumer-fixture/expected' + str(number) + '.json']
        raw = self.consumer(args, writable=True)
        result = consumer_result(raw.stdout, raw.returncode)
        after = self.file_state()
        if result['applied']:
            require(not denied and result['version'] == self.fixture['expected_versions'][number - 1])
            require(after['matches' + str(number)] is True and after['mode'] == 0o600)
            if before['exists']:
                require(after['device'] == before['device'] and after['inode'] != before['inode'])
        else:
            require(file_preserved(before, after))
        return result

    def allowed(self, number=2, revision=None):
        result = self.read(number)
        require(result['applied'] is True)
        if revision is not None:
            require(result['revision'] == revision)
        return result

    def restore_policies(self):
        # Do not race a timed-out deletion or update whose VM is still unconfirmed.
        require(not any('-core-eval-' in name or '-agent-eval-' in name for name in self.active_containers))
        for policy_id, attrs in list(self.pending_policies.items()):
            result = self.core_private('restore', {'attrs': attrs})
            require(result['original_binding_restored'] is True and re.fullmatch(UUID, result['id']) is not None)
            self.regranted_ids[policy_id] = result['id']
            del self.pending_policies[policy_id]

    def unpause(self):
        info = json.loads(self.command(['docker', 'inspect', self.config['core_container']]).stdout)[0]
        require(info['Image'] == self.config['core_image_id'])
        if info['State']['Paused']:
            self.command(['docker', 'unpause', self.config['core_container']], timeout=20)
        require(not json.loads(self.command(['docker', 'inspect', self.config['core_container']]).stdout)[0]['State']['Paused'])
        self.paused = False

    def manual_unseal(self):
        deadline = time.monotonic() + 60
        while True:
            try:
                self.core.client.session()
                status = self.core.client.json('/v1/sys/seal-status')[2]
                require(status['initialized'] is True and status['sealed'] is True)
                break
            except Exception:
                require(time.monotonic() < deadline)
                time.sleep(0.5)
        require(type(status['threshold']) is int and 0 < status['threshold'] <= len(self.core.shares))
        for share in self.core.shares[:status['threshold']]:
            require(self.core.client.json('/v1/sys/unseal', 'POST', {'share': share})[0] == 200)
        require(self.core.client.json('/v1/sys/seal-status')[2]['sealed'] is False)
        self.core_needs_unseal = False
        self.cluster_phase = 'after_core_restart'

    def execute(self):
        first = self.wait_connected()
        identity = self.snapshot()
        require(identity['agent_id'] == first['agent_id'] and identity['minimum_uds_auth_version'] in (1, 2))
        enrollments = self.enrollment_ids()
        baseline = self.core_private('preflight')
        require(baseline['agent_runtime_id'] == first['agent_id'] and baseline['secret']['version'] == 1)
        initial = self.allowed(1, baseline['secret']['revision'])
        self.results['initial_readback'] = initial
        self.results['uds_authentication'] = {'status': 'passed', 'consumer_auth_version': 2,
                                             'preserved_minimum_auth_version': identity['minimum_uds_auth_version']}
        require(self.read(1, denied=True)['error'] in ('FORBIDDEN', 'PERMISSION_DENIED'))
        self.results['denied_path'] = {'status': 'passed', 'file_preserved': True}
        self.stage = 'secret_update'
        updated = self.core_private('update')
        require(updated['version'] == 2 and updated['revision'] > initial['revision'])
        self.results['updated_readback'] = self.allowed(2, updated['revision'])
        self.allowed(2, updated['revision'])  # Successful warm-up before revocation.
        self.stage = 'application_policy_revocation'
        try:
            for policy in baseline['policies']:
                self.pending_policies[policy['id']] = policy['attrs']
                require(self.core_private('revoke', {'policy_id': policy['id'], 'attrs': policy['attrs']}) == {'deleted': True})
            require(self.read()['error'] in ('FORBIDDEN', 'PERMISSION_DENIED'))
            self.results['policy_revocation'] = {'status': 'passed', 'post_warm_read': 'denied', 'file_preserved': True}
        finally:
            self.restore_policies()
        self.allowed(2, updated['revision'])
        self.results['policy_regrant'] = {'status': 'passed', 'original_binding_restored': True}
        self.stage = 'agent_restart'
        self.command(['docker', 'restart', self.agent], timeout=30)
        after_agent = self.wait_connected(first['heartbeat'], datetime.now(timezone.utc))
        require(self.snapshot() == identity and self.enrollment_ids() == enrollments)
        self.allowed(2, updated['revision'])
        self.results['agent_restart'] = {'status': 'passed', 'identity_preserved': True, 'fresh_heartbeat': True, 'readback': True}
        self.stage = 'core_restart'
        self.core_needs_unseal = True
        self.command(['docker', 'restart', self.config['core_container']], timeout=30)
        restarted = datetime.now(timezone.utc)
        self.manual_unseal()
        after_core = self.wait_connected(after_agent['heartbeat'], restarted)
        require(after_core['certificate_id'] == first['certificate_id'] and self.snapshot() == identity and self.enrollment_ids() == enrollments)
        self.allowed(2, updated['revision'])
        self.results['core_restart'] = {'status': 'passed', 'sealed_until_manual_unseal': True,
                                       'identity_preserved': True, 'fresh_heartbeat': True, 'readback': True}
        self.stage = 'core_outage'
        self.allowed(2, updated['revision'])
        paused_at = time.monotonic()
        self.paused = True
        try:
            self.command(['docker', 'pause', self.config['core_container']], timeout=20)
            require(json.loads(self.command(['docker', 'inspect', self.config['core_container']]).stdout)[0]['State']['Paused'] is True)
            denied = self.read()
            require(denied['error'] in ('CORE_UNAVAILABLE', 'REQUEST_DENIED'))
            require(time.monotonic() - paused_at < 90)
            self.results['core_outage'] = {'status': 'passed', 'post_warm_read': 'denied', 'file_preserved': True,
                'consumer_error': denied['error'], 'paused_seconds': round(time.monotonic() - paused_at, 3)}
        finally:
            self.unpause()
        deadline = time.monotonic() + 45
        while True:
            result = self.read()
            if result['applied']:
                require(result['revision'] == updated['revision'])
                break
            require(result['error'] in ('CORE_UNAVAILABLE', 'REQUEST_DENIED') and time.monotonic() < deadline)
            time.sleep(0.5)
        require(self.snapshot() == identity and self.enrollment_ids() == enrollments)
        self.results['outage_recovery'] = {'status': 'passed', 'readback': True, 'identity_preserved': True}

    def run(self):
        started = time.monotonic()
        passed = False
        try:
            self.execute()
            passed = True
        except Exception as error:
            self.results['failure'] = {'stage': self.stage, 'error_type': type(error).__name__}
        finally:
            # Stop residual evaluators before any policy restoration is attempted.
            for name in list(self.active_containers):
                try:
                    self.remove_container(name)
                except Exception:
                    passed = False
            try:
                if self.paused:
                    self.unpause()
                if self.core_needs_unseal:
                    self.manual_unseal()
                self.restore_policies()
            except Exception:
                passed = False
                self.results['fixture_recovery'] = {'status': 'failed'}
            for name in list(self.active_containers):
                try:
                    self.remove_container(name)
                except Exception:
                    passed = False
        report = {key: self.config[key] for key in ('source_sha', 'platform', 'core_image_id', 'agent_image_id', 'consumer_image_id')}
        report.update(complete=False, provisional=self.core.provisional, recovery_hold=True,
            observed_at=datetime.now(timezone.utc).isoformat(), selected_checks='passed' if passed else 'failed',
            gates={'G12': {'status': 'passed' if passed else 'failed'},
                   'G13': {'status': 'partial', 'unexecuted': ['live cache TTL expiry', 'direct cache-hit provenance']}},
            results=self.results, regranted_policy_ids=self.regranted_ids, consumer_program_sha256=self.program_hash,
            serving_cluster_observations=self.cluster_observations,
            core_eval_node_ids=self.core_eval_node_ids,
            incidental_cluster_rows='retained if evaluator startup registered; no row deletion or backfill',
            cleanup_confirmed=not self.active_containers and not self.paused and not self.pending_policies and not self.core_needs_unseal,
            configured_cache_ttl_seconds=300, seconds=round(time.monotonic() - started, 3),
            diagnostics_sha256=hashlib.sha256(b'\n'.join(self.diagnostics + self.core.fixture_logs)).hexdigest(),
            private_material='excluded; preserve fixture certificate/key, expected values, applied file and held shares')
        if not report['cleanup_confirmed']:
            report['selected_checks'] = 'failed'
            report['gates']['G12']['status'] = 'failed'
            passed = False
        private_json(self.output / 'static-report.json', report)
        print(json.dumps({'G12': report['gates']['G12']['status'], 'G13': 'partial', 'complete': False,
                          'selected_checks': report['selected_checks']}))
        return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--shares-file', required=True)
    parser.add_argument('--output', required=True, help='new private result directory beside config')
    args = parser.parse_args()
    try:
        checkout = Path(__file__).resolve().parents[2]
        checkout = next((parent.parent for parent in checkout.parents if parent.name == '.trees'), checkout)
        config_path, shares = map(private_file, (args.config, args.shares_file))
        require(not config_path.is_relative_to(checkout) and not shares.is_relative_to(checkout))
        output = Path(args.output).absolute()
        require(output.parent.resolve() == config_path.parent and not output.resolve().is_relative_to(checkout))
        config = validate_config(json.loads(config_path.read_text()))
        require(not Path(config['static_fixture']['directory']).is_relative_to(checkout))
        return StaticHarness(config, output, shares).run()
    except Exception as error:
        print(json.dumps({'complete': False, 'setup': 'failed', 'error_type': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
