defmodule SecretHub.Shared.Schemas.AuditLog do
  @moduledoc """
  Schema for tamper-evident audit logging with hash chains.

  Every security-relevant event is logged with:
  - Complete actor information (agent, app, admin)
  - Secret access details
  - Authorization results
  - Source context (IP, hostname, K8s pod)
  - Hash chain fields for tamper detection

  The table is partitioned by timestamp for performance.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id
  @hash_versions [1, 2]
  @upgrade_event_types [
    "system.upgrade_gate_verified",
    "system.upgrade_stale_node_acknowledged"
  ]
  @upgrade_gate_evidence_keys [
    "acknowledgement_snapshot_hash",
    "capability",
    "gate",
    "report_hash"
  ]
  @app_certificate_issuance_rules %{
    "auth.app_certificate_issuance_allowed" => %{
      evidence_keys: ["agent_id", "app_id", "certificate_id", "request_id", "result_code"],
      result_codes: ["issued", "replayed"],
      uuid_keys: ["agent_id", "app_id", "certificate_id", "request_id"]
    },
    "auth.app_certificate_issuance_denied" => %{
      evidence_keys: ["request_id", "result_code"],
      result_codes: [
        "idempotency_conflict",
        "invalid_agent_assignment",
        "invalid_csr",
        "invalid_request_id",
        "invalid_token",
        "unsupported_key"
      ],
      requestless_result_codes: ["invalid_request_id"],
      uuid_keys: ["request_id"]
    },
    "auth.app_certificate_issuance_failed" => %{
      evidence_keys: ["request_id", "result_code"],
      result_codes: ["ca_unavailable", "issuance_failed"],
      uuid_keys: ["request_id"]
    }
  }
  @app_certificate_issuance_evidence_error "must contain exactly the sanitized application certificate issuance evidence"
  @app_certificate_lifecycle_rules %{
    "auth.app_certificate_renewal_allowed" => %{
      evidence_root: "app_certificate_renewal",
      evidence_keys: [
        "app_id",
        "current_certificate_id",
        "issued_certificate_id",
        "request_id",
        "result_code"
      ],
      result_codes: ["renewed", "replayed"],
      uuid_keys: [
        "app_id",
        "current_certificate_id",
        "issued_certificate_id",
        "request_id"
      ]
    },
    "auth.app_certificate_renewal_denied" => %{
      evidence_root: "app_certificate_renewal",
      evidence_keys: ["request_id", "result_code"],
      result_codes: [
        "idempotency_conflict",
        "invalid_agent_assignment",
        "invalid_app_id",
        "invalid_csr",
        "invalid_current_certificate",
        "invalid_fingerprint",
        "invalid_proof",
        "invalid_request",
        "invalid_request_id",
        "unsupported_algorithm",
        "unsupported_key"
      ],
      requestless_result_codes: ["invalid_request", "invalid_request_id"],
      uuid_keys: ["request_id"]
    },
    "auth.app_certificate_renewal_failed" => %{
      evidence_root: "app_certificate_renewal",
      evidence_keys: ["request_id", "result_code"],
      result_codes: ["ca_unavailable", "renewal_failed"],
      uuid_keys: ["request_id"]
    },
    "auth.app_certificate_revoked" => %{
      evidence_root: "app_certificate_revocation",
      evidence_keys: ["app_id", "certificate_id", "reason", "result_code"],
      result_codes: ["revoked"],
      reason_codes: ["app_suspended", "compromised", "operator_revoked", "superseded"],
      uuid_keys: ["app_id", "certificate_id"]
    }
  }
  @app_certificate_lifecycle_evidence_error "must contain exactly the sanitized application certificate lifecycle evidence"
  @sha256_hex ~r/\A[0-9a-f]{64}\z/
  @control_characters ~r/[\x00-\x1F\x7F]/u

  schema "audit_logs" do
    # Event identification
    field(:event_id, :binary_id)
    field(:sequence_number, :integer)
    field(:timestamp, :utc_datetime)
    field(:event_type, :string)

    # Actor information
    field(:actor_type, :string)
    field(:actor_id, :string)
    field(:agent_id, :string)
    field(:app_id, :string)
    field(:admin_id, :string)

    # Certificate fingerprints for non-repudiation
    field(:agent_cert_fingerprint, :string)
    field(:app_cert_fingerprint, :string)

    # Secret information
    field(:secret_id, :string)
    field(:secret_version, :integer)
    field(:secret_type, :string)
    field(:lease_id, :binary_id)

    # Access control
    field(:access_granted, :boolean)
    field(:policy_matched, :string)
    field(:denial_reason, :string)

    # Source context
    field(:source_ip, EctoNetwork.INET)
    field(:hostname, :string)
    field(:kubernetes_namespace, :string)
    field(:kubernetes_pod, :string)

    # Full event data (flexible storage for event-specific fields)
    field(:event_data, :map)

    # Tamper-evidence fields (hash chain)
    field(:hash_version, :integer, default: 1)
    field(:previous_hash, :string)
    field(:current_hash, :string)
    field(:signature, :string)

    # Performance tracking
    field(:response_time_ms, :integer)
    field(:correlation_id, :binary_id)

    field(:created_at, :utc_datetime)
  end

  @doc """
  Changeset for creating an audit log entry.
  """
  def changeset(audit_log, attrs) do
    audit_log
    |> cast(attrs, [
      :event_id,
      :sequence_number,
      :timestamp,
      :event_type,
      :actor_type,
      :actor_id,
      :agent_id,
      :app_id,
      :admin_id,
      :agent_cert_fingerprint,
      :app_cert_fingerprint,
      :secret_id,
      :secret_version,
      :secret_type,
      :lease_id,
      :access_granted,
      :policy_matched,
      :denial_reason,
      :source_ip,
      :hostname,
      :kubernetes_namespace,
      :kubernetes_pod,
      :event_data,
      :hash_version,
      :previous_hash,
      :current_hash,
      :signature,
      :response_time_ms,
      :correlation_id,
      :created_at
    ])
    |> validate_required([:event_id, :sequence_number, :timestamp, :event_type, :hash_version])
    |> validate_inclusion(:event_type, valid_event_types())
    |> validate_inclusion(:hash_version, @hash_versions)
    |> validate_hash_version_event_type()
    |> validate_upgrade_gate_evidence()
    |> validate_app_certificate_issuance_evidence()
    |> validate_app_certificate_lifecycle_evidence()
    |> unique_constraint(:event_id, name: :unique_event_id_timestamp)
    |> unique_constraint([:sequence_number, :timestamp], name: :unique_sequence_number_timestamp)
  end

  @doc """
  Valid event types for audit logging.
  """
  def valid_event_types do
    [
      # Secret access events
      "secret.accessed",
      "secret.dynamic_issued",
      "secret.lease_renewed",
      "secret.access_denied",
      # Secret mutation events
      "secret.created",
      "secret.updated",
      "secret.rotated",
      "secret.deleted",
      # Authentication events
      "auth.agent_bootstrap",
      "auth.agent_certificate_issued",
      "auth.agent_login",
      "auth.admin_login",
      "auth.app_certificate_issuance_allowed",
      "auth.app_certificate_issuance_denied",
      "auth.app_certificate_issuance_failed",
      "auth.app_certificate_renewal_allowed",
      "auth.app_certificate_renewal_denied",
      "auth.app_certificate_renewal_failed",
      "auth.app_certificate_revoked",
      "auth.failed",
      # AppRole authentication events
      "approle_created",
      "approle_deleted",
      "approle_login_failed",
      "approle_login_success",
      "approle_secret_rotated",
      "approle_token_issued",
      "approle_token_renewed",
      "approle_token_revoked",
      "approle.unauthorized_access",
      # Policy changes
      "policy.created",
      "policy.updated",
      "policy.deleted",
      "policy.bound",
      # System events
      "system.unsealed",
      "system.sealed",
      "system.backup_created",
      "system.certificate_revoked",
      "system.upgrade_gate_verified",
      "system.upgrade_stale_node_acknowledged",
      # Rate limiting events
      "rate_limit.exceeded",
      # Client Auth PKI events
      "pki.client_auth.authority_initialized",
      "pki.client_auth.identity_created",
      "pki.client_auth.identity_disabled",
      "pki.client_auth.certificate_issued",
      "pki.client_auth.certificate_revoked",
      "pki.client_auth.crl_published",
      "pki.client_auth.agent_receipt_recorded",
      # Vault lifecycle events
      "vault_started",
      "vault_initialized",
      "vault_unsealed",
      "vault_sealed",
      "vault_auto_sealed"
    ]
  end

  defp validate_hash_version_event_type(changeset) do
    event_type = get_field(changeset, :event_type)
    hash_version = get_field(changeset, :hash_version)

    cond do
      event_type in @upgrade_event_types and hash_version != 2 ->
        add_error(changeset, :hash_version, "must use hash version 2")

      hash_version == 2 and event_type not in @upgrade_event_types ->
        add_error(changeset, :hash_version, "is only supported for upgrade gate events")

      true ->
        changeset
    end
  end

  defp validate_upgrade_gate_evidence(changeset) do
    if get_field(changeset, :event_type) in @upgrade_event_types do
      case normalize_upgrade_gate_evidence(get_field(changeset, :event_data)) do
        {:ok, event_data} ->
          put_change(changeset, :event_data, event_data)

        {:error, reason} ->
          add_error(changeset, :event_data, reason)
      end
    else
      changeset
    end
  end

  defp validate_app_certificate_issuance_evidence(changeset) do
    event_type = get_field(changeset, :event_type)

    case Map.fetch(@app_certificate_issuance_rules, event_type) do
      {:ok, rule} ->
        case normalize_app_certificate_issuance_evidence(
               get_field(changeset, :event_data),
               rule
             ) do
          {:ok, event_data} ->
            put_change(changeset, :event_data, event_data)

          :error ->
            add_error(
              changeset,
              :event_data,
              @app_certificate_issuance_evidence_error
            )
        end

      :error ->
        changeset
    end
  end

  defp validate_app_certificate_lifecycle_evidence(changeset) do
    event_type = get_field(changeset, :event_type)

    case Map.fetch(@app_certificate_lifecycle_rules, event_type) do
      {:ok, rule} ->
        case normalize_app_certificate_lifecycle_evidence(
               get_field(changeset, :event_data),
               rule
             ) do
          {:ok, event_data} ->
            put_change(changeset, :event_data, event_data)

          :error ->
            add_error(
              changeset,
              :event_data,
              @app_certificate_lifecycle_evidence_error
            )
        end

      :error ->
        changeset
    end
  end

  defp normalize_app_certificate_lifecycle_evidence(event_data, rule) do
    evidence_root = rule.evidence_root

    with {:ok, %{^evidence_root => evidence}} <-
           normalize_exact_map(event_data, [evidence_root]),
         {:ok, evidence_pairs} <- normalize_pairs(evidence),
         evidence = Map.new(evidence_pairs),
         evidence_keys <- lifecycle_evidence_keys(rule, evidence),
         {:ok, normalized_evidence} <- normalize_exact_map(evidence, evidence_keys),
         true <- normalized_evidence["result_code"] in rule.result_codes,
         true <- valid_lifecycle_reason?(normalized_evidence, rule),
         {:ok, normalized_evidence} <-
           normalize_uuid_evidence(
             normalized_evidence,
             Enum.filter(rule.uuid_keys, &Map.has_key?(normalized_evidence, &1))
           ) do
      {:ok, %{evidence_root => normalized_evidence}}
    else
      _other -> :error
    end
  end

  defp lifecycle_evidence_keys(rule, evidence) do
    if evidence["result_code"] in Map.get(rule, :requestless_result_codes, []),
      do: ["result_code"],
      else: rule.evidence_keys
  end

  defp valid_lifecycle_reason?(evidence, rule) do
    case Map.fetch(rule, :reason_codes) do
      {:ok, reasons} -> evidence["reason"] in reasons
      :error -> not Map.has_key?(evidence, "reason")
    end
  end

  defp normalize_app_certificate_issuance_evidence(event_data, rule) do
    with {:ok, %{"app_certificate_issuance" => issuance}} <-
           normalize_exact_map(event_data, ["app_certificate_issuance"]),
         {:ok, issuance_pairs} <- normalize_pairs(issuance),
         issuance = Map.new(issuance_pairs),
         evidence_keys <- app_certificate_issuance_evidence_keys(rule, issuance),
         {:ok, normalized_issuance} <-
           normalize_exact_map(issuance, evidence_keys),
         true <- normalized_issuance["result_code"] in rule.result_codes,
         {:ok, normalized_issuance} <-
           normalize_uuid_evidence(
             normalized_issuance,
             Enum.filter(rule.uuid_keys, &Map.has_key?(normalized_issuance, &1))
           ) do
      {:ok, %{"app_certificate_issuance" => normalized_issuance}}
    else
      _other -> :error
    end
  end

  defp app_certificate_issuance_evidence_keys(rule, issuance) do
    if issuance["result_code"] in Map.get(rule, :requestless_result_codes, []),
      do: ["result_code"],
      else: rule.evidence_keys
  end

  defp normalize_uuid_evidence(evidence, uuid_keys) do
    Enum.reduce_while(uuid_keys, {:ok, evidence}, fn key, {:ok, normalized} ->
      case Ecto.UUID.cast(normalized[key]) do
        {:ok, uuid} -> {:cont, {:ok, Map.put(normalized, key, uuid)}}
        :error -> {:halt, :error}
      end
    end)
  end

  defp normalize_upgrade_gate_evidence(event_data) do
    with {:ok, %{"upgrade_gate" => upgrade_gate}} <-
           normalize_exact_map(event_data, ["upgrade_gate"]),
         {:ok, normalized_gate} <-
           normalize_exact_map(upgrade_gate, @upgrade_gate_evidence_keys),
         :ok <- validate_public_string(normalized_gate["gate"], "gate"),
         :ok <- validate_public_string(normalized_gate["capability"], "capability"),
         :ok <- validate_sha256(normalized_gate["report_hash"], "report_hash"),
         :ok <-
           validate_sha256(
             normalized_gate["acknowledgement_snapshot_hash"],
             "acknowledgement_snapshot_hash"
           ) do
      {:ok, %{"upgrade_gate" => normalized_gate}}
    end
  end

  defp normalize_exact_map(value, expected_keys) when is_map(value) do
    with {:ok, pairs} <- normalize_pairs(value),
         true <- Enum.sort(Enum.map(pairs, &elem(&1, 0))) == Enum.sort(expected_keys) do
      {:ok, Map.new(pairs)}
    else
      false -> {:error, "must contain exactly the sanitized upgrade gate evidence"}
      {:error, _reason} = error -> error
    end
  end

  defp normalize_exact_map(_value, _expected_keys) do
    {:error, "must contain exactly the sanitized upgrade gate evidence"}
  end

  defp normalize_pairs(value) when is_map(value) do
    pairs =
      Enum.map(value, fn {key, nested_value} ->
        {normalize_key(key), nested_value}
      end)

    cond do
      Enum.any?(pairs, fn {key, _value} -> key == :error end) ->
        {:error, "must use string or atom evidence keys"}

      pairs |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> length() != length(pairs) ->
        {:error, "must not contain keys duplicated after string normalization"}

      true ->
        {:ok, pairs}
    end
  end

  defp normalize_pairs(_value), do: {:error, "must be a map"}

  defp normalize_key(key) when is_binary(key), do: key
  defp normalize_key(key) when is_atom(key), do: Atom.to_string(key)
  defp normalize_key(_key), do: :error

  defp validate_public_string(value, field_name)
       when is_binary(value) and byte_size(value) > 0 do
    if String.valid?(value) and String.trim(value) != "" and
         not Regex.match?(@control_characters, value) do
      :ok
    else
      {:error, "#{field_name} must be a non-empty public string"}
    end
  end

  defp validate_public_string(_value, field_name) do
    {:error, "#{field_name} must be a non-empty public string"}
  end

  defp validate_sha256(value, _field_name)
       when is_binary(value) and byte_size(value) == 64 do
    if Regex.match?(@sha256_hex, value) do
      :ok
    else
      {:error, "upgrade gate hashes must be lowercase SHA-256 hex"}
    end
  end

  defp validate_sha256(_value, field_name) do
    {:error, "#{field_name} must be lowercase 64-character SHA-256 hex"}
  end
end
