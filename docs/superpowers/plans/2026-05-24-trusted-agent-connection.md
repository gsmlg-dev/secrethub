# Trusted Agent Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## Agent skills

- [$subagent-driven-development](/home/gao/.agents/skills/subagent-driven-development/SKILL.md) -- use this plan as task-by-task implementation work with review checkpoints.
- [$test-driven-development](/home/gao/.agents/skills/test-driven-development/SKILL.md) -- drive behavior changes through failing tests before implementation.
- [$using-elixir-skills](/home/gao/.agents/skills/using-elixir-skills/SKILL.md) -- apply Elixir/Phoenix/Ecto/OTP repo conventions while editing `.ex` and `.exs` files.
- [$verification-before-completion](/home/gao/.agents/skills/verification-before-completion/SKILL.md) -- rerun focused and broad verification before calling the work complete.

**Goal:** Make the Agent-to-Core trusted runtime connection work end to end using Core-issued mTLS client certificates as the only runtime identity.

**Implementation Status:** Implemented through the trusted runtime integration slice on 2026-05-25. Final verification is tracked in Task 8 below.

**Architecture:** The Agent owns a state directory and a startup coordinator. The coordinator loads trusted material or runs enrollment, then starts the existing low-level Phoenix Socket client only after a valid certificate, private key, CA chain, and connect-info exist. Core verifies SSH-host-key proof before issuing a separate TLS client certificate and verifies the certificate fingerprint, state, EKU, SANs, and Agent status when accepting the trusted runtime socket.

**Tech Stack:** Elixir umbrella, Phoenix Channels, Bandit/Thousand Island TLS, Ecto/PostgreSQL, `:public_key`, `:ssh_file`, `x509`, `phoenix_socket_client`, `websocket_client`.

---

## Guardrails

- Before editing an existing function, module, or schema, run GitNexus impact analysis for that symbol if GitNexus tools are available. Report direct callers, affected processes, and risk.
- Follow TDD: write the failing test, run it, implement the smallest change, run it again.
- Run commands through `test-all` because devenv defaults `MIX_ENV=dev`.
- Keep runtime credential authorization off the normal API endpoint. Pending token remains enrollment-only.
- Keep `SecretHub.Agent.Connection` as the low-level WebSocket client.

## File Structure

- Create `apps/secrethub_shared/lib/secrethub_shared/crypto/agent_csr_proof.ex`
  - Canonical CSR proof payload and sign/verify helpers shared by Agent and Core.
- Test `apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs`
  - RSA and ECDSA proof verification with tamper checks.
- Modify `apps/secrethub_agent/lib/secrethub_agent/host_key.ex`
  - Add OpenSSH public key export and proof signing.
- Test `apps/secrethub_agent/test/secrethub_agent/host_key_test.exs`
  - Public key export fingerprint matches discovered key.
- Create `apps/secrethub_agent/lib/secrethub_agent/tls_identity.ex`
  - Generate separate TLS client keypair and CSR from Core-required fields.
- Test `apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs`
  - CSR uses TLS public key, not SSH host key, and contains requested SANs.
- Create migration in `apps/secrethub_core/priv/repo/migrations/`
  - Add `ssh_host_public_key` to `agent_enrollments` and `agents`.
- Modify `apps/secrethub_shared/lib/secrethub_shared/schemas/agent_enrollment.ex`
  - Cast and require `ssh_host_public_key` for pending enrollment.
- Modify `apps/secrethub_shared/lib/secrethub_shared/schemas/agent.ex`
  - Cast `ssh_host_public_key`.
- Modify `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`
  - Include host public key in pending payload, generate TLS keypair, submit CSR proof, and store TLS private key.
- Modify `apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex`
  - Generate CSR challenge on approval, verify proof on submit, set 30-day default TTL with 90-day max.
- Modify `apps/secrethub_web/lib/secret_hub/web/controllers/agent_enrollment_controller.ex`
  - Accept `ssh_proof` with CSR submission.
- Modify `apps/secrethub_core/lib/secrethub_core/pki/issuer.ex`
  - Issue client certificate from TLS CSR with explicit SAN metadata and EKU metadata.
- Modify `apps/secrethub_core/lib/secrethub_core/pki/verifier.ex`
  - Enforce `agent_client`, unrevoked, unexpired, `clientAuth`, expected URI SANs, and active Agent status.
- Create `apps/secrethub_agent/lib/secrethub_agent/identity_store.ex`
  - Load, validate, and persist state directory files with permissions.
- Test `apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs`
  - File writes, mode checks, load success, and missing-material behavior.
- Create `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
  - Own startup decision: load state, enroll, start trusted runtime, finalize after accepted join.
- Modify `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
  - Emit `on_runtime_accepted` callback after `agent:runtime` join succeeds.
- Modify `apps/secrethub_agent/lib/secrethub_agent/trusted_connection.ex`
  - Accept loaded identity material and callback options.
- Modify `apps/secrethub_agent/lib/secrethub_agent/application.ex`
  - Start `RuntimeBootstrapper` instead of static-path `ConnectionManager` as the top-level Agent runtime path.
- Modify `mix.exs`
  - Update `mix agent.run` to use the coordinator and state directory path.
- Update tests in:
  - `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs`
  - `apps/secrethub_web/test/secrethub_web_web/controllers/agent_registration_e2e_test.exs`
  - `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`

---

### Task 1: Shared CSR Proof Contract

**Files:**
- Create: `apps/secrethub_shared/lib/secrethub_shared/crypto/agent_csr_proof.ex`
- Create: `apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs`

- [ ] **Step 1: Write failing shared proof tests**

Create `apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs`:

```elixir
defmodule SecretHub.Shared.Crypto.AgentCSRProofTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.Crypto.AgentCSRProof

  test "signs and verifies an RSA host-key proof" do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    public_key = :ssh_file.extract_public_key(private_key)

    proof =
      AgentCSRProof.sign(private_key, %{
        enrollment_id: "enrollment-1",
        challenge: "challenge-1",
        csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
      })

    assert {:ok, %{algorithm: "rsa"}} =
             AgentCSRProof.verify(public_key, %{
               enrollment_id: "enrollment-1",
               challenge: "challenge-1",
               csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
               proof: proof
             })
  end

  test "rejects a proof when the CSR changes after signing" do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    public_key = :ssh_file.extract_public_key(private_key)

    proof =
      AgentCSRProof.sign(private_key, %{
        enrollment_id: "enrollment-1",
        challenge: "challenge-1",
        csr_pem: "csr-a"
      })

    assert {:error, :invalid_signature} =
             AgentCSRProof.verify(public_key, %{
               enrollment_id: "enrollment-1",
               challenge: "challenge-1",
               csr_pem: "csr-b",
               proof: proof
             })
  end
end
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
test-all apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs
```

Expected: fail because `SecretHub.Shared.Crypto.AgentCSRProof` is not defined.

- [ ] **Step 3: Implement proof payload, signing, and verification**

Create `apps/secrethub_shared/lib/secrethub_shared/crypto/agent_csr_proof.ex`:

```elixir
defmodule SecretHub.Shared.Crypto.AgentCSRProof do
  @moduledoc """
  Canonical proof that binds an Agent TLS CSR to the approved SSH host key.
  """

  @context "secrethub-agent-csr-v1"

  def sign(private_key, attrs) do
    signature =
      attrs
      |> payload()
      |> :public_key.sign(:sha256, private_key)
      |> Base.url_encode64(padding: false)

    %{
      "algorithm" => algorithm(private_key),
      "signature" => signature
    }
  end

  def verify(public_key, %{proof: proof} = attrs) when is_map(proof) do
    with {:ok, signature} <- decode_signature(proof),
         true <- :public_key.verify(payload(attrs), :sha256, signature, public_key) do
      {:ok, %{algorithm: Map.get(proof, "algorithm") || Map.get(proof, :algorithm)}}
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify(_public_key, _attrs), do: {:error, :missing_proof}

  def payload(attrs) do
    enrollment_id = fetch_string!(attrs, :enrollment_id)
    challenge = fetch_string!(attrs, :challenge)
    csr_pem = fetch_string!(attrs, :csr_pem)
    csr_hash = :crypto.hash(:sha256, csr_pem) |> Base.encode16(case: :lower)

    Enum.join([@context, enrollment_id, challenge, csr_hash], <<0>>)
  end

  defp decode_signature(proof) do
    proof
    |> fetch_string(:signature)
    |> case do
      nil -> {:error, :missing_signature}
      signature -> Base.url_decode64(signature, padding: false)
    end
  end

  defp fetch_string!(attrs, key) do
    case fetch_string(attrs, key) do
      value when is_binary(value) -> value
      nil -> raise ArgumentError, "missing #{key}"
    end
  end

  defp fetch_string(attrs, key) do
    Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))
  end

  defp algorithm({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}), do: "rsa"
  defp algorithm({:ECPrivateKey, _, _, _, _, _}), do: "ecdsa"
end
```

- [ ] **Step 4: Run shared proof tests**

Run:

```bash
test-all apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add apps/secrethub_shared/lib/secrethub_shared/crypto/agent_csr_proof.ex apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs
git commit -m "feat(shared): add agent CSR proof contract"
```

---

### Task 2: Persist SSH Host Public Key During Enrollment

**Files:**
- Modify: `apps/secrethub_agent/lib/secrethub_agent/host_key.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent_enrollment.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent.ex`
- Create: `apps/secrethub_core/priv/repo/migrations/<timestamp>_add_ssh_host_public_key_to_agents.exs`
- Modify tests: `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs`, `apps/secrethub_agent/test/secrethub_agent/host_key_test.exs`

- [ ] **Step 1: Generate the migration**

Run:

```bash
cd apps/secrethub_core && mix ecto.gen.migration add_ssh_host_public_key_to_agents
```

Expected: a migration file appears under `apps/secrethub_core/priv/repo/migrations/`.

- [ ] **Step 2: Write failing tests**

Add to `apps/secrethub_agent/test/secrethub_agent/host_key_test.exs`:

```elixir
@tag :tmp_dir
test "exports an OpenSSH public key for enrollment payload", %{tmp_dir: tmp_dir} do
  path = Path.join(tmp_dir, "ssh_host_rsa_key")

  {_, 0} =
    System.cmd("ssh-keygen", ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", path])

  assert {:ok, host_key} = SecretHub.Agent.HostKey.discover(paths: [rsa: path])
  assert public_key = SecretHub.Agent.HostKey.public_key_openssh(host_key)
  assert String.starts_with?(public_key, "ssh-rsa ")
end
```

Update `@pending_attrs` in `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs` to include:

```elixir
ssh_host_public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"
```

Add an assertion in `"stores a hashed pending token and returns the plaintext token once"`:

```elixir
assert enrollment.ssh_host_public_key == @pending_attrs.ssh_host_public_key
```

- [ ] **Step 3: Run tests and verify failure**

Run:

```bash
test-all apps/secrethub_agent/test/secrethub_agent/host_key_test.exs apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
```

Expected: fail because schemas and `HostKey.public_key_openssh/1` do not exist.

- [ ] **Step 4: Implement schema and payload changes**

Migration body:

```elixir
defmodule SecretHub.Core.Repo.Migrations.AddSshHostPublicKeyToAgents do
  use Ecto.Migration

  def change do
    alter table(:agent_enrollments) do
      add :ssh_host_public_key, :text
    end

    alter table(:agents) do
      add :ssh_host_public_key, :text
    end
  end
end
```

Update both schemas to cast `:ssh_host_public_key`. In `AgentEnrollment.pending_changeset/2`, add it to `validate_required/2`.

Add to `SecretHub.Agent.HostKey`:

```elixir
def public_key_openssh(%__MODULE__{public_key: public_key}) do
  public_key
  |> then(&:ssh_file.encode([{&1, []}], :openssh_key))
  |> IO.iodata_to_binary()
  |> String.trim()
end
```

Update `SecretHub.Agent.Enrollment.pending_payload/2`:

```elixir
def pending_payload(%HostKey{} = host_key, opts) do
  %{
    "hostname" => Keyword.get(opts, :hostname, hostname()),
    "fqdn" => Keyword.get(opts, :fqdn, fqdn()),
    "machine_id" => Keyword.get(opts, :machine_id, machine_id()),
    "os" => :os.type() |> Tuple.to_list() |> Enum.join("-"),
    "arch" => :erlang.system_info(:system_architecture) |> to_string(),
    "agent_version" => Keyword.get(opts, :agent_version, "0.1.0"),
    "ssh_host_key_algorithm" => host_key.algorithm,
    "ssh_host_key_fingerprint" => host_key.fingerprint,
    "ssh_host_public_key" => HostKey.public_key_openssh(host_key),
    "capabilities" => Keyword.get(opts, :capabilities, %{})
  }
end
```

Update `SecretHub.Core.Agents.Enrollment.create_or_reuse_agent/1` to persist `ssh_host_public_key` on new Agents.

- [ ] **Step 5: Run migration and tests**

Run:

```bash
db-migrate
test-all apps/secrethub_agent/test/secrethub_agent/host_key_test.exs apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_core/priv/repo/migrations apps/secrethub_shared/lib/secrethub_shared/schemas/agent.ex apps/secrethub_shared/lib/secrethub_shared/schemas/agent_enrollment.ex apps/secrethub_agent/lib/secrethub_agent/host_key.ex apps/secrethub_agent/lib/secrethub_agent/enrollment.ex apps/secrethub_agent/test/secrethub_agent/host_key_test.exs apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
git commit -m "feat(agent): persist SSH host public key for enrollment"
```

---

### Task 3: Generate Separate TLS Identity and CSR

**Files:**
- Create: `apps/secrethub_agent/lib/secrethub_agent/tls_identity.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`

- [ ] **Step 1: Write failing TLS identity test**

Create `apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs`:

```elixir
defmodule SecretHub.Agent.TLSIdentityTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.TLSIdentity

  test "generates a TLS keypair and CSR with required identity fields" do
    required_fields = %{
      "subject" => %{"O" => "SecretHub Agents", "CN" => "agent-123"},
      "san" => %{
        "uri" => [
          "urn:secrethub:agent:agent-123",
          "urn:secrethub:hostkey-sha256:abc"
        ],
        "dns" => ["agent-123.example.internal"]
      },
      "key_usage" => ["digitalSignature"],
      "extended_key_usage" => ["clientAuth"]
    }

    assert {:ok, identity} = TLSIdentity.generate(required_fields)
    assert is_binary(identity.private_key_pem)
    assert is_tuple(identity.private_key)
    assert is_binary(identity.csr_pem)
    assert {:ok, csr} = X509.CSR.from_pem(identity.csr_pem)
    assert X509.CSR.valid?(csr)
    assert X509.CSR.public_key(csr) == :ssh_file.extract_public_key(identity.private_key)
  end
end
```

- [ ] **Step 2: Run failing test**

```bash
test-all apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs
```

Expected: fail because `SecretHub.Agent.TLSIdentity` is not defined.

- [ ] **Step 3: Implement TLS identity module**

Create `apps/secrethub_agent/lib/secrethub_agent/tls_identity.ex`:

```elixir
defmodule SecretHub.Agent.TLSIdentity do
  @moduledoc """
  Generates runtime TLS client key material separate from the SSH host key.
  """

  defstruct [:private_key, :private_key_pem, :csr_pem]

  def generate(required_fields) when is_map(required_fields) do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    with {:ok, csr_pem} <- csr_pem(private_key, required_fields) do
      {:ok,
       %__MODULE__{
         private_key: private_key,
         private_key_pem: X509.PrivateKey.to_pem(private_key, wrap: true),
         csr_pem: csr_pem
       }}
    end
  end

  defp csr_pem(private_key, required_fields) do
    subject = Map.fetch!(required_fields, "subject")
    san = Map.get(required_fields, "san", %{})

    uri_sans =
      san
      |> Map.get("uri", [])
      |> List.wrap()
      |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})

    dns_sans =
      san
      |> Map.get("dns", [])
      |> List.wrap()
      |> Enum.map(&{:dNSName, to_charlist(&1)})

    csr =
      X509.CSR.new(
        private_key,
        "/O=#{escape_rdn(Map.fetch!(subject, "O"))}/CN=#{escape_rdn(Map.fetch!(subject, "CN"))}",
        extension_request: [
          X509.Certificate.Extension.subject_alt_name(uri_sans ++ dns_sans),
          X509.Certificate.Extension.key_usage([:digitalSignature]),
          X509.Certificate.Extension.ext_key_usage([:clientAuth])
        ]
      )

    {:ok, X509.CSR.to_pem(csr)}
  rescue
    e -> {:error, {:tls_csr_failed, Exception.message(e)}}
  end

  defp escape_rdn(value) when is_binary(value), do: String.replace(value, "/", "\\/")
end
```

- [ ] **Step 4: Update enrollment to use TLS identity**

In `SecretHub.Agent.Enrollment.enroll/1`, replace `HostKey.csr_pem/2` with:

```elixir
{:ok, tls_identity} <- SecretHub.Agent.TLSIdentity.generate(approved["required_csr_fields"]),
{:ok, issued} <- submit_csr(core_url, pending, approved, tls_identity, host_key),
```

Change `submit_csr/3` to `submit_csr/5`:

```elixir
def submit_csr(core_url, pending, approved, tls_identity, host_key) do
  proof =
    SecretHub.Shared.Crypto.AgentCSRProof.sign(host_key.private_key, %{
      enrollment_id: pending["enrollment_id"],
      challenge: approved["required_csr_fields"]["challenge"],
      csr_pem: tls_identity.csr_pem
    })

  core_url
  |> endpoint_url("/v1/agent/enrollments/#{pending["enrollment_id"]}/csr")
  |> post_json(
    %{
      "csr_pem" => tls_identity.csr_pem,
      "ssh_proof" => proof
    },
    bearer_headers(pending)
  )
end
```

Pass `tls_identity` to `store_material/5` and write `tls_identity.private_key_pem` to `agent-key.pem`.

- [ ] **Step 5: Run Agent tests**

```bash
test-all apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_agent/lib/secrethub_agent/tls_identity.ex apps/secrethub_agent/lib/secrethub_agent/enrollment.ex apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs
git commit -m "feat(agent): generate separate TLS identity during enrollment"
```

---

### Task 4: Verify SSH Proof Before Certificate Issuance

**Files:**
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/agent_enrollment_controller.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs`

- [ ] **Step 1: Write failing Core proof test**

Add a test under `describe "submit_csr/3"`:

```elixir
test "rejects CSR submissions without a valid SSH host-key proof" do
  private_key = :public_key.generate_key({:rsa, 2048, 65_537})
  public_key = :ssh_file.extract_public_key(private_key)
  fingerprint = SecretHub.Core.PKI.CSR.ssh_fingerprint(public_key)

  generate_active_ca!()

  attrs =
    @pending_attrs
    |> Map.put(:ssh_host_key_fingerprint, fingerprint)
    |> Map.put(:ssh_host_public_key, :ssh_file.encode(public_key, :openssh_key) |> IO.iodata_to_binary() |> String.trim())

  {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
    Enrollment.create_pending(attrs, "203.0.113.10")

  {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
  tls_key = :public_key.generate_key({:rsa, 2048, 65_537})
  csr = X509.CSR.new(tls_key, "/O=SecretHub Agents/CN=#{approved.agent_id}")

  assert {:error, :missing_proof} =
           Enrollment.submit_csr(approved.id, pending_token, %{
             "csr_pem" => X509.CSR.to_pem(csr)
           })
end
```

- [ ] **Step 2: Run failing test**

```bash
test-all apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
```

Expected: fail because `submit_csr/3` still accepts only raw CSR PEM.

- [ ] **Step 3: Update approval fields and submit contract**

In `required_csr_fields/2`, add a challenge:

```elixir
"challenge" => :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
```

Change `submit_csr/3` to accept either legacy binary only in tests removed by this task, or a map payload:

```elixir
def submit_csr(enrollment_id, pending_token, %{"csr_pem" => csr_pem, "ssh_proof" => proof}) do
  with {:ok, enrollment} <- authorize(enrollment_id, pending_token),
       :ok <- verify_not_expired(enrollment),
       :ok <- verify_status(enrollment, [:approved_waiting_for_csr, :csr_invalid]),
       {:ok, csr} <- PKI.CSR.parse(csr_pem),
       :ok <- verify_csr_proof(enrollment, csr_pem, proof),
       :ok <- verify_csr_identity(enrollment, csr) do
    issue_certificate(enrollment, csr_pem, csr)
  else
    {:error, reason}
    when reason in [
           :not_found,
           :expired,
           :invalid_pending_token,
           :invalid_status,
           :missing_proof,
           :invalid_signature,
           :host_public_key_mismatch
         ] ->
      {:error, reason}

    {:error, reason} ->
      mark_csr_invalid(enrollment_id, reason)
  end
end

def submit_csr(_enrollment_id, _pending_token, _payload), do: {:error, :missing_proof}
```

Add helper functions:

```elixir
defp verify_csr_proof(enrollment, csr_pem, proof) do
  with {:ok, public_key} <- decode_ssh_public_key(enrollment.ssh_host_public_key),
       :ok <- verify_public_key_fingerprint(public_key, enrollment.ssh_host_key_fingerprint),
       {:ok, _} <-
         SecretHub.Shared.Crypto.AgentCSRProof.verify(public_key, %{
           enrollment_id: enrollment.id,
           challenge: enrollment.required_csr_fields["challenge"],
           csr_pem: csr_pem,
           proof: proof
         }) do
    :ok
  end
end

defp decode_ssh_public_key(public_key_text) when is_binary(public_key_text) do
  case :ssh_file.decode(public_key_text, :public_key) do
    [{public_key, _attributes}] -> {:ok, public_key}
    [] -> {:error, :invalid_host_public_key}
  end
rescue
  _e -> {:error, :invalid_host_public_key}
end

defp decode_ssh_public_key(_), do: {:error, :missing_host_public_key}

defp verify_public_key_fingerprint(public_key, expected) do
  if PKI.CSR.ssh_fingerprint(public_key) == expected do
    :ok
  else
    {:error, :host_public_key_mismatch}
  end
end
```

Rename `verify_csr_fingerprint/2` to `verify_csr_identity/2` and make it validate that the CSR public key is not the SSH public key and that the CSR subject/SANs match `required_csr_fields`.

- [ ] **Step 4: Update controller**

Change `submit_csr/2`:

```elixir
def submit_csr(conn, %{"id" => id, "csr_pem" => _csr_pem} = params) do
  with {:ok, token} <- bearer_token(conn),
       {:ok, result} <- Enrollment.submit_csr(id, token, Map.take(params, ["csr_pem", "ssh_proof"])) do
    certificate = result.certificate

    json(conn, %{
      agent_id: result.enrollment.agent_id,
      certificate_pem: certificate.certificate_pem,
      ca_chain_pem: ca_chain_pem(),
      certificate_serial: certificate.serial_number,
      certificate_fingerprint: certificate.fingerprint,
      connect_info_url: "/v1/agent/enrollments/#{id}/connect-info"
    })
  else
    {:error, reason} -> enrollment_error(conn, reason)
  end
end
```

- [ ] **Step 5: Run Core and Web tests**

```bash
test-all apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs apps/secrethub_web/test/secrethub_web_web/controllers/agent_registration_e2e_test.exs
```

Expected: pass after updating existing CSR tests to include a valid proof.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex apps/secrethub_web/lib/secret_hub/web/controllers/agent_enrollment_controller.ex apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs apps/secrethub_web/test/secrethub_web_web/controllers/agent_registration_e2e_test.exs
git commit -m "feat(core): require SSH proof for agent CSR issuance"
```

---

### Task 5: Enforce Certificate Identity and TTL Policy

**Files:**
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/issuer.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/verifier.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex`
- Modify tests: `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs`

- [ ] **Step 1: Write failing verifier tests**

Add tests that create issued certificates and then mutate stored metadata:

```elixir
test "verifier rejects an agent certificate missing clientAuth metadata" do
  %{certificate: certificate} = issue_valid_agent_certificate!()

  certificate
  |> Ecto.Changeset.change(metadata: Map.delete(certificate.metadata, "extended_key_usage"))
  |> Repo.update!()

  [{:Certificate, cert_der, :not_encrypted}] = :public_key.pem_decode(certificate.certificate_pem)

  assert {:error, :missing_client_auth} = Verifier.verify_agent_certificate(cert_der)
end

test "verifier rejects a certificate whose host-key SAN is not bound to the agent" do
  %{certificate: certificate} = issue_valid_agent_certificate!()

  metadata =
    certificate.metadata
    |> Map.put("san_uri", ["urn:secrethub:agent:#{certificate.entity_id}"])

  certificate
  |> Ecto.Changeset.change(metadata: metadata)
  |> Repo.update!()

  [{:Certificate, cert_der, :not_encrypted}] = :public_key.pem_decode(certificate.certificate_pem)

  assert {:error, :missing_host_key_san} = Verifier.verify_agent_certificate(cert_der)
end
```

Use a local helper `issue_valid_agent_certificate!/0` in the test file that performs the existing create, approve, proof, and submit flow.

- [ ] **Step 2: Run failing verifier tests**

```bash
test-all apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
```

Expected: fail because verifier does not enforce EKU and host-key SAN yet.

- [ ] **Step 3: Set TTL defaults and max**

In `SecretHub.Core.Agents.Enrollment`, replace `certificate_ttl_seconds/0` with:

```elixir
defp certificate_ttl_seconds do
  configured =
    Application.get_env(:secrethub_core, :agent_certificate_ttl_seconds, 30 * 24 * 60 * 60)

  min(configured, max_certificate_ttl_seconds())
end

defp max_certificate_ttl_seconds do
  Application.get_env(:secrethub_core, :agent_certificate_max_ttl_seconds, 90 * 24 * 60 * 60)
end
```

Update `SecretHub.Core.PKI.Issuer.validity_days/0` to use the same 30-day default and 90-day cap.

- [ ] **Step 4: Store identity metadata during issuance**

In `issue_agent_certificate_from_csr/2`, set metadata:

```elixir
metadata: %{
  "san_uri" => get_in(enrollment.required_csr_fields, ["san", "uri"]) || [],
  "san_dns" => get_in(enrollment.required_csr_fields, ["san", "dns"]) || [],
  "extended_key_usage" => ["clientAuth"]
}
```

- [ ] **Step 5: Enforce verifier checks**

In `SecretHub.Core.PKI.Verifier.verify_agent_certificate/1`, add checks:

```elixir
:ok <- verify_cert_type(stored),
:ok <- verify_client_auth(stored),
:ok <- verify_agent_uri(stored, agent.agent_id),
:ok <- verify_host_key_uri(stored, agent.ssh_host_key_fingerprint),
```

Add helpers:

```elixir
defp verify_cert_type(%Certificate{cert_type: :agent_client}), do: :ok
defp verify_cert_type(_), do: {:error, :invalid_certificate_type}

defp verify_client_auth(certificate) do
  usages = get_in(certificate.metadata || %{}, ["extended_key_usage"]) || []
  if "clientAuth" in usages, do: :ok, else: {:error, :missing_client_auth}
end

defp verify_host_key_uri(certificate, "SHA256:" <> fingerprint) do
  san_uri = get_in(certificate.metadata || %{}, ["san_uri"]) || []

  if "urn:secrethub:hostkey-sha256:#{fingerprint}" in san_uri do
    :ok
  else
    {:error, :missing_host_key_san}
  end
end

defp verify_host_key_uri(_certificate, _fingerprint), do: {:error, :missing_host_key_san}
```

- [ ] **Step 6: Run verifier tests**

```bash
test-all apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add apps/secrethub_core/lib/secrethub_core/pki/issuer.ex apps/secrethub_core/lib/secrethub_core/pki/verifier.ex apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs
git commit -m "feat(core): enforce trusted agent certificate identity"
```

---

### Task 6: Agent State Directory and Identity Store

**Files:**
- Create: `apps/secrethub_agent/lib/secrethub_agent/identity_store.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`

- [ ] **Step 1: Write failing identity store tests**

Create `apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs`:

```elixir
defmodule SecretHub.Agent.IdentityStoreTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.IdentityStore

  @tag :tmp_dir
  test "stores and loads trusted material from the state directory", %{tmp_dir: tmp_dir} do
    material = %{
      agent_id: "agent-123",
      enrollment_id: "enrollment-123",
      certificate_pem: "cert-pem",
      private_key_pem: "key-pem",
      ca_chain_pem: "ca-pem",
      connect_info: %{
        "trusted_websocket_endpoint" => "wss://localhost:4665/agent/socket/websocket",
        "expected_core_server_name" => "localhost"
      },
      identity: %{
        "agent_id" => "agent-123",
        "enrollment_id" => "enrollment-123",
        "certificate_fingerprint" => "fingerprint",
        "certificate_serial" => "serial",
        "valid_until" => "2026-06-23T00:00:00Z",
        "ssh_host_key_fingerprint" => "SHA256:abc",
        "hostname" => "host",
        "fqdn" => "host.example.internal",
        "machine_id" => "machine"
      }
    }

    assert :ok = IdentityStore.write(tmp_dir, material)
    assert {:ok, loaded} = IdentityStore.load(tmp_dir)
    assert loaded.agent_id == "agent-123"
    assert loaded.connect_info["expected_core_server_name"] == "localhost"
    assert loaded.certificate_pem == "cert-pem"
    assert loaded.private_key_pem == "key-pem"
  end

  @tag :tmp_dir
  test "reports missing material when state directory is empty", %{tmp_dir: tmp_dir} do
    assert {:error, :missing_trusted_material} = IdentityStore.load(tmp_dir)
  end
end
```

- [ ] **Step 2: Run failing test**

```bash
test-all apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs
```

Expected: fail because `IdentityStore` is missing.

- [ ] **Step 3: Implement identity store**

Create `apps/secrethub_agent/lib/secrethub_agent/identity_store.ex`:

```elixir
defmodule SecretHub.Agent.IdentityStore do
  @moduledoc """
  Reads and writes trusted Agent runtime material from a state directory.
  """

  defstruct [
    :agent_id,
    :certificate_pem,
    :private_key_pem,
    :ca_chain_pem,
    :connect_info,
    :identity
  ]

  @files %{
    cert: "agent-cert.pem",
    key: "agent-key.pem",
    ca: "ca-chain.pem",
    connect_info: "connect-info.json",
    identity: "identity.json"
  }

  def load(state_dir) do
    with {:ok, certificate_pem} <- read_file(state_dir, :cert),
         {:ok, private_key_pem} <- read_file(state_dir, :key),
         {:ok, ca_chain_pem} <- read_file(state_dir, :ca),
         {:ok, connect_info} <- read_json(state_dir, :connect_info),
         {:ok, identity} <- read_json(state_dir, :identity),
         {:ok, agent_id} <- fetch_agent_id(identity) do
      {:ok,
       %__MODULE__{
         agent_id: agent_id,
         certificate_pem: certificate_pem,
         private_key_pem: private_key_pem,
         ca_chain_pem: ca_chain_pem,
         connect_info: connect_info,
         identity: identity
       }}
    else
      {:error, :enoent} -> {:error, :missing_trusted_material}
      {:error, reason} -> {:error, reason}
    end
  end

  def write(state_dir, material) do
    with :ok <- File.mkdir_p(state_dir),
         :ok <- File.chmod(state_dir, 0o700),
         :ok <- write_file(state_dir, :cert, material.certificate_pem, 0o644),
         :ok <- write_file(state_dir, :key, material.private_key_pem, 0o600),
         :ok <- write_file(state_dir, :ca, material.ca_chain_pem, 0o644),
         :ok <- write_json(state_dir, :connect_info, material.connect_info, 0o644),
         :ok <- write_json(state_dir, :identity, material.identity, 0o644) do
      :ok
    end
  end

  defp read_file(state_dir, key), do: File.read(path(state_dir, key))

  defp read_json(state_dir, key) do
    with {:ok, contents} <- read_file(state_dir, key) do
      Jason.decode(contents)
    end
  end

  defp write_file(state_dir, key, contents, mode) do
    file_path = path(state_dir, key)

    with :ok <- File.write(file_path, contents),
         :ok <- File.chmod(file_path, mode) do
      :ok
    end
  end

  defp write_json(state_dir, key, value, mode) do
    write_file(state_dir, key, Jason.encode!(value), mode)
  end

  defp path(state_dir, key), do: Path.join(state_dir, Map.fetch!(@files, key))

  defp fetch_agent_id(%{"agent_id" => agent_id}) when is_binary(agent_id), do: {:ok, agent_id}
  defp fetch_agent_id(_), do: {:error, :missing_agent_id}
end
```

- [ ] **Step 4: Route enrollment storage through IdentityStore**

Update `SecretHub.Agent.Enrollment.store_material/5` to assemble the material map and call `IdentityStore.write/2`. Preserve `pending.json` writing separately with mode `0600`.

- [ ] **Step 5: Run Agent storage tests**

```bash
test-all apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add apps/secrethub_agent/lib/secrethub_agent/identity_store.ex apps/secrethub_agent/lib/secrethub_agent/enrollment.ex apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs
git commit -m "feat(agent): persist trusted runtime identity"
```

---

### Task 7: Runtime Bootstrapper and Accepted Join Callback

**Files:**
- Create: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/trusted_connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Modify: `mix.exs`
- Create: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`

- [ ] **Step 1: Write failing callback test for Connection**

Add to `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`:

```elixir
test "stores runtime accepted callback in connection state" do
  callback = fn payload -> send(self(), {:accepted, payload}) end

  assert {:ok, pid} =
           Connection.start_link(
             agent_id: "agent-test-callback",
             core_url: "ws://localhost:19999",
             on_runtime_accepted: callback
           )

  state = :sys.get_state(pid)
  assert state.on_runtime_accepted == callback
  GenServer.stop(pid)
end
```

- [ ] **Step 2: Run failing callback test**

```bash
test-all apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs
```

Expected: fail because `on_runtime_accepted` is not in Connection state.

- [ ] **Step 3: Add callback to Connection**

Add `:on_runtime_accepted` to the state type and `init/1`. In the successful `join_channel/2` branch, invoke:

```elixir
notify_runtime_accepted(state, response)
```

Add:

```elixir
defp notify_runtime_accepted(%{on_runtime_accepted: callback}, payload)
     when is_function(callback, 1) do
  callback.(payload)
  :ok
end

defp notify_runtime_accepted(_state, _payload), do: :ok
```

Change `join_channel/2` to return `{:ok, response, channel}` so the accepted payload is available.

- [ ] **Step 4: Write failing bootstrapper tests**

Create `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`:

```elixir
defmodule SecretHub.Agent.RuntimeBootstrapperTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.RuntimeBootstrapper

  @tag :tmp_dir
  test "decides ready_for_runtime when trusted material exists", %{tmp_dir: tmp_dir} do
    :ok =
      SecretHub.Agent.IdentityStore.write(tmp_dir, %{
        agent_id: "agent-123",
        enrollment_id: "enrollment-123",
        certificate_pem: "cert",
        private_key_pem: "key",
        ca_chain_pem: "ca",
        connect_info: %{
          "trusted_websocket_endpoint" => "wss://localhost:4665/agent/socket/websocket",
          "expected_core_server_name" => "localhost"
        },
        identity: %{
          "agent_id" => "agent-123",
          "enrollment_id" => "enrollment-123",
          "certificate_fingerprint" => "fingerprint"
        }
      })

    assert {:ok, :ready_for_runtime, material} = RuntimeBootstrapper.plan_start(tmp_dir)
    assert material.agent_id == "agent-123"
  end

  @tag :tmp_dir
  test "decides needs_enrollment when trusted material is missing", %{tmp_dir: tmp_dir} do
    assert {:ok, :needs_enrollment} = RuntimeBootstrapper.plan_start(tmp_dir)
  end
end
```

- [ ] **Step 5: Implement bootstrapper planning and startup**

Create `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`:

```elixir
defmodule SecretHub.Agent.RuntimeBootstrapper do
  @moduledoc """
  Owns Agent startup: load trusted material, enroll when needed, start runtime.
  """

  use GenServer
  require Logger

  alias SecretHub.Agent.{Enrollment, IdentityStore, TrustedConnection}

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def plan_start(state_dir) do
    case IdentityStore.load(state_dir) do
      {:ok, material} -> {:ok, :ready_for_runtime, material}
      {:error, :missing_trusted_material} -> {:ok, :needs_enrollment}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def init(opts) do
    state = %{
      core_url: Keyword.fetch!(opts, :core_url),
      state_dir: Keyword.fetch!(opts, :state_dir),
      enrollment_opts: Keyword.get(opts, :enrollment_opts, [])
    }

    {:ok, state, {:continue, :start}}
  end

  @impl true
  def handle_continue(:start, state) do
    case plan_start(state.state_dir) do
      {:ok, :ready_for_runtime, material} ->
        start_runtime(material, state)

      {:ok, :needs_enrollment} ->
        enroll_and_start_runtime(state)

      {:error, reason} ->
        {:stop, reason, state}
    end
  end

  defp enroll_and_start_runtime(state) do
    opts =
      state.enrollment_opts
      |> Keyword.put(:core_url, enrollment_http_url(state.core_url))
      |> Keyword.put(:storage_dir, state.state_dir)

    case Enrollment.enroll(opts) do
      {:ok, enrolled} ->
        {:ok, material} = IdentityStore.load(state.state_dir)
        start_runtime(material, Map.put(state, :pending, enrolled.pending))

      {:error, reason} ->
        {:stop, reason, state}
    end
  end

  defp start_runtime(material, state) do
    on_runtime_accepted = fn payload ->
      send(self(), {:runtime_accepted, payload})
    end

    {:ok, _pid} =
      TrustedConnection.start_link(
        agent_id: material.agent_id,
        certificate_pem: material.certificate_pem,
        private_key_pem: material.private_key_pem,
        ca_pem: material.ca_chain_pem,
        connect_info: material.connect_info,
        on_runtime_accepted: on_runtime_accepted
      )

    {:noreply, Map.put(state, :material, material)}
  end

  @impl true
  def handle_info({:runtime_accepted, payload}, %{pending: pending} = state) do
    enrollment_url = enrollment_http_url(state.core_url)
    _ = Enrollment.finalize_success(enrollment_url, pending, state.state_dir)
    Logger.info("Agent trusted runtime accepted", payload: payload)
    {:noreply, state}
  end

  def handle_info({:runtime_accepted, payload}, state) do
    Logger.info("Agent trusted runtime accepted", payload: payload)
    {:noreply, state}
  end

  defp enrollment_http_url(core_url) do
    uri = URI.parse(core_url)

    scheme =
      case uri.scheme do
        "ws" -> "http"
        "wss" -> "https"
        other -> other || "https"
      end

    %{uri | scheme: scheme, path: nil, query: nil}
    |> URI.to_string()
  end
end
```

- [ ] **Step 6: Wire Application and mix alias**

Update `SecretHub.Agent.TrustedConnection.start_link/1` so loaded PEM material is converted before calling `Connection.start_link/1`:

```elixir
private_key =
  case Keyword.fetch(opts, :private_key_pem) do
    {:ok, private_key_pem} -> X509.PrivateKey.from_pem!(private_key_pem)
    :error -> Keyword.fetch!(opts, :private_key)
  end

Connection.start_link(
  agent_id: Keyword.get(opts, :agent_id, "certificate-derived"),
  core_url: fetch_connect_value(connect_info, "trusted_websocket_endpoint"),
  cert_pem: certificate_pem,
  private_key: private_key,
  ca_pem: Keyword.get(opts, :ca_pem) || fetch_connect_value(connect_info, "core_ca_cert_pem"),
  expected_server_name: fetch_connect_value(connect_info, "expected_core_server_name"),
  on_runtime_accepted: Keyword.get(opts, :on_runtime_accepted)
)
```

In `SecretHub.Agent.Application`, replace the static `ConnectionManager` child with:

```elixir
{SecretHub.Agent.RuntimeBootstrapper,
 [
   core_url: Application.get_env(:secrethub_agent, :core_url, "https://localhost:4664"),
   state_dir:
     Application.get_env(
       :secrethub_agent,
       :state_dir,
       System.get_env("SECRET_HUB_AGENT_STATE_DIR") || "/var/lib/secrethub-agent"
     ),
   enrollment_opts: []
 ]}
```

Update `mix.exs` `agent.run` to set `:state_dir` and start `:secrethub_agent`; remove duplicate enrollment/finalize orchestration from the mix alias after the coordinator owns it.

- [ ] **Step 7: Run Agent tests**

```bash
test-all apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs
```

Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex apps/secrethub_agent/lib/secrethub_agent/connection.ex apps/secrethub_agent/lib/secrethub_agent/trusted_connection.ex apps/secrethub_agent/lib/secrethub_agent/application.ex apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs mix.exs
git commit -m "feat(agent): add trusted runtime bootstrapper"
```

---

### Task 8: Trusted Runtime Integration Verification

**Files:**
- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `docs/architecture/agent-protocol.md`
- Modify: `docs/deployment/agent-deployment-guide.md`

- [x] **Step 1: Add integration test for accepted runtime finalization**

Add a test that uses the full enrollment functions through Core and then verifies `AgentRuntimeChannel` accepts a socket with certificate-derived assigns. The ChannelTest socket still bypasses the TLS handshake, so this verifies the application authorization and finalization behavior while lower-level TLS remains covered by endpoint config tests.

```elixir
test "trusted runtime join finalizes an enrolled agent", %{agent_id: agent_id} do
  socket =
    socket(AgentTrustedSocket, "agent:test", %{
      agent_id: agent_id,
      certificate_serial: "serial-finalize",
      certificate_fingerprint: "fingerprint-finalize"
    })

  assert {:ok, reply, socket} =
           subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

  assert reply.status == "accepted"
  assert reply.agent_id == agent_id
  leave(socket)
end
```

- [x] **Step 2: Run integration tests**

```bash
test-all apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs apps/secrethub_web/test/e2e/core_agent_flow_test.exs
```

Expected: pass.

- [x] **Step 3: Update stale docs**

Update `docs/architecture/agent-protocol.md` so runtime authentication says:

```markdown
Runtime Agent traffic uses the dedicated trusted Agent endpoint and mTLS client certificates. AppRole and pending tokens are enrollment-only and do not authorize runtime channel joins or secret reads.
```

Update `docs/deployment/agent-deployment-guide.md` so bootstrap describes:

```markdown
On first boot, the Agent creates a pending enrollment, waits for operator approval, generates a separate TLS client keypair, submits a CSR plus SSH-host-key proof, stores trusted material in the Agent state directory, and connects to the dedicated trusted Agent endpoint over mTLS.
```

- [x] **Step 4: Run docs and full targeted checks**

```bash
mix format --check-formatted
test-all apps/secrethub_shared/test/secrethub_shared/crypto/agent_csr_proof_test.exs apps/secrethub_agent/test/secrethub_agent/ apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs
```

Expected: format check passes and targeted tests pass.

- [ ] **Step 5: Run full quality gate**

```bash
./scripts/quality-check.sh
```

Expected: format, compile with warnings as errors, credo, dialyzer, and tests pass.

- [x] **Step 6: GitNexus change check before final commit**

Run GitNexus change detection if available:

```text
gitnexus_detect_changes()
```

Expected: affected scope is limited to Agent enrollment/runtime, Core enrollment/PKI verification, trusted Agent web channel/controller, and related tests/docs.

- [ ] **Step 7: Commit**

```bash
git add docs/architecture/agent-protocol.md docs/deployment/agent-deployment-guide.md apps/secrethub_web/test/e2e/core_agent_flow_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs
git commit -m "test(agent): verify trusted runtime enrollment path"
```

---

## Acceptance Criteria

- First boot with no state directory material enters enrollment mode.
- Pending token cannot authorize runtime secret access.
- Agent generates a TLS keypair separate from the SSH host key.
- Core verifies an SSH-host-key proof over the TLS CSR before certificate issuance.
- Issued Agent client certificates default to 30-day TTL and cannot exceed 90-day TTL.
- Trusted Agent endpoint requires client certificate TLS handshake.
- Trusted socket derives `agent_id` only from the verified certificate.
- Runtime channel accepts only sockets with certificate-derived identity.
- Agent finalizes enrollment only after `agent:runtime` accepted reply.
- State directory reload starts trusted runtime without requiring manual cert path config.

## Self-Review

- Spec coverage: The plan maps each accepted design decision into at least one task. Renewal is explicitly excluded from this first vertical slice except for TTL policy and callback placement.
- Placeholder scan: The plan uses concrete file paths, commands, test names, and implementation snippets rather than open-ended work items.
- Type consistency: The planned names are consistent across tasks: `AgentCSRProof`, `TLSIdentity`, `IdentityStore`, `RuntimeBootstrapper`, `ssh_proof`, `ssh_host_public_key`, and `on_runtime_accepted`.
