defmodule SecretHub.Core.PKI.ClientAuth do
  @moduledoc """
  Public context for SecretHub Client Authentication PKI.

  Coordinates authority management, identity lifecycle, canonical certificate issuance,
  revocation, full CRL management, and public trust bundle distribution.
  """

  alias SecretHub.Core.Audit
  alias SecretHub.Core.PKI.ClientAuth.{Authority, CRLManager, Identity, Issuer, TrustBundle}
  alias SecretHub.Core.Repo

  alias SecretHub.Shared.Schemas.{
    Certificate,
    ClientAuthAuthority,
    ClientAuthBundleReceipt,
    ClientAuthCrl
  }

  import Ecto.Query

  @default_authority_slug "client-auth"

  # Authority Operations

  @doc """
  Initializes the client auth root CA and first CRL for the given authority.
  """
  def init_authority(attrs \\ %{}, opts \\ []) do
    Authority.initialize(attrs, opts)
  end

  def initialize_authority(attrs \\ %{}, opts \\ []) do
    Authority.initialize(attrs, opts)
  end

  @doc """
  Inspects authority operational status.
  """
  def authority_status(_slug \\ @default_authority_slug) do
    Authority.status()
  end

  def status do
    Authority.status()
  end

  @doc """
  Returns the active authority, CA certificate, and decrypted CA private key.
  """
  def get_active_ca_and_key do
    Authority.get_active_ca_and_key()
  end

  # Identity Operations

  @doc """
  Creates a new client identity.
  """
  def create_identity(attrs, opts \\ []) do
    Identity.create_identity(attrs, opts)
  end

  @doc """
  Lists client identities with optional filtering and pagination.
  """
  def list_identities(opts \\ []) do
    opts = normalize_opts(opts)
    Identity.list_identities(opts)
  end

  @doc """
  Fetches a single client identity by ID.
  """
  def get_identity(id) do
    Identity.get_identity(id)
  end

  @doc """
  Disables a client identity and revokes all of its active certificates.
  """
  def disable_identity(id, reason_or_params \\ "operator_disabled", opts \\ [])

  def disable_identity(id, params, opts) when is_map(params) do
    reason = Map.get(params, "reason") || Map.get(params, :reason) || "operator_disabled"
    Identity.disable_identity(id, reason, opts)
  end

  def disable_identity(id, reason, opts) when is_binary(reason) do
    Identity.disable_identity(id, reason, opts)
  end

  # Certificate Issuance & Inspection

  @doc """
  Issues a canonical client certificate for an identity from a CSR.
  """
  def issue_certificate(attrs, extra_opts \\ [])

  def issue_certificate(attrs, extra_opts) when is_map(attrs) do
    identity_id = Map.get(attrs, "identity_id") || Map.get(attrs, :identity_id)
    csr_pem = Map.get(attrs, "csr_pem") || Map.get(attrs, :csr_pem)
    request_id = Map.get(attrs, "request_id") || Map.get(attrs, :request_id)
    ttl_seconds = Map.get(attrs, "ttl_seconds") || Map.get(attrs, :ttl_seconds)

    opts =
      extra_opts
      |> Keyword.put_new(:ttl_seconds, ttl_seconds)

    Issuer.issue_certificate(identity_id, csr_pem, request_id, opts)
  end

  def issue_certificate(identity_id, csr_pem, request_id) do
    Issuer.issue_certificate(identity_id, csr_pem, request_id, [])
  end

  def issue_certificate(identity_id, csr_pem, request_id, opts) do
    Issuer.issue_certificate(identity_id, csr_pem, request_id, opts)
  end

  @doc """
  Fetches a single certificate by ID.
  """
  def get_certificate(certificate_id) do
    case Ecto.UUID.cast(certificate_id) do
      {:ok, uuid} ->
        case Repo.get(Certificate, uuid) do
          nil -> {:error, :certificate_not_found}
          cert -> {:ok, cert}
        end

      :error ->
        {:error, :certificate_not_found}
    end
  end

  @doc """
  Lists certificates with optional filters.
  """
  def list_certificates(opts \\ []) do
    opts = normalize_opts(opts)
    identity_id = Keyword.get(opts, :identity_id)
    revoked = Keyword.get(opts, :revoked)
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query =
      from(c in Certificate,
        where: c.cert_type in [:client_auth_client, :client_auth_ca],
        order_by: [desc: c.inserted_at],
        limit: ^limit,
        offset: ^offset
      )

    query =
      if identity_id do
        where(query, [c], c.client_auth_identity_id == ^identity_id)
      else
        query
      end

    query =
      case revoked do
        true -> where(query, [c], c.revoked == true)
        false -> where(query, [c], c.revoked == false and c.valid_until > ^DateTime.utc_now())
        _ -> query
      end

    Repo.all(query)
  end

  # Revocation & CRL Operations

  @doc """
  Revokes a client certificate and publishes a new signed CRL in a single transaction.
  """
  def revoke_certificate(certificate_id, reason_or_params, opts \\ [])

  def revoke_certificate(certificate_id, params, opts) when is_map(params) do
    reason = Map.get(params, "reason") || Map.get(params, :reason) || "keyCompromise"
    CRLManager.revoke_certificate(certificate_id, reason, opts)
  end

  def revoke_certificate(certificate_id, reason, opts) do
    CRLManager.revoke_certificate(certificate_id, reason, opts)
  end

  @doc """
  Refreshes the CRL if nearing expiry or if forced.
  """
  def refresh_crl(opts \\ []) do
    CRLManager.refresh_crl(opts)
  end

  @doc """
  Forces an immediate CRL refresh and generation bump.
  """
  def force_refresh_crl(slug_or_opts \\ @default_authority_slug, opts \\ [])

  def force_refresh_crl(slug, opts) when is_binary(slug) do
    opts = Keyword.merge(opts, authority_slug: slug, force: true)
    CRLManager.refresh_crl(opts)
  end

  def force_refresh_crl(opts, []) when is_list(opts) do
    opts = Keyword.put(opts, :force, true)
    CRLManager.refresh_crl(opts)
  end

  @doc """
  Refreshes the CRL only if within the refresh-ahead window.
  """
  def refresh_if_needed(opts \\ []) do
    CRLManager.refresh_if_needed(opts)
  end

  # Trust Bundle Operations

  @doc """
  Returns the current deterministic public trust bundle.
  """
  def current_bundle(slug \\ @default_authority_slug) do
    TrustBundle.current_bundle(slug)
  end

  # Bundle Receipts (Agent Convergence Tracking)

  @doc """
  Records or updates an Agent's trust bundle receipt.
  """
  def record_bundle_receipt(attrs) when is_map(attrs) do
    agent_id = Map.get(attrs, "agent_id") || Map.get(attrs, :agent_id)

    with {:ok, %ClientAuthAuthority{} = authority} <- get_active_authority() do
      raw_status = to_string(Map.get(attrs, "status") || Map.get(attrs, :status) || "applied")
      normalized_status = if raw_status in ["failed", "error"], do: "failed", else: "applied"

      applied_at =
        case Map.get(attrs, "applied_at") || Map.get(attrs, :applied_at) do
          nil -> nil
          val -> parse_receipt_datetime(val)
        end

      receipt_attrs = %{
        agent_id: to_string(agent_id),
        client_auth_authority_id: authority.id,
        generation: Map.get(attrs, "generation") || Map.get(attrs, :generation) || 0,
        crl_number: Map.get(attrs, "crl_number") || Map.get(attrs, :crl_number) || 0,
        bundle_sha256: Map.get(attrs, "bundle_sha256") || Map.get(attrs, :bundle_sha256) || "",
        status: normalized_status,
        last_error_code: Map.get(attrs, "last_error_code") || Map.get(attrs, :last_error_code),
        last_error_detail:
          Map.get(attrs, "last_error_detail") || Map.get(attrs, :last_error_detail),
        applied_at: applied_at,
        observation_sequence:
          Map.get(attrs, "observation_sequence") || Map.get(attrs, :observation_sequence)
      }

      receipt_attrs = verify_applied_bundle_authenticity(authority, receipt_attrs)

      res =
        Repo.transaction(fn ->
          existing =
            Repo.one(
              from(r in ClientAuthBundleReceipt,
                where:
                  r.agent_id == ^receipt_attrs.agent_id and
                    r.client_auth_authority_id == ^authority.id,
                lock: "FOR UPDATE"
              )
            )

          maybe_record_equivocation_audit(authority, receipt_attrs, existing)

          case transition_receipt(existing, receipt_attrs) do
            {:ignore, _} ->
              existing

            {:ok, update_attrs} ->
              changeset =
                case existing do
                  nil ->
                    %ClientAuthBundleReceipt{}
                    |> ClientAuthBundleReceipt.changeset(update_attrs)

                  rec ->
                    rec
                    |> ClientAuthBundleReceipt.changeset(update_attrs)
                end

              case Repo.insert_or_update(changeset) do
                {:ok, receipt} ->
                  actor_id = receipt.agent_id

                  event_data = %{
                    "agent_id" => receipt.agent_id,
                    "authority_id" => authority.id,
                    "generation" => receipt.generation,
                    "crl_number" => receipt.crl_number,
                    "bundle_sha256" => receipt.bundle_sha256,
                    "status" => receipt.status,
                    "last_error_code" => receipt.last_error_code,
                    "last_error_detail" => receipt.last_error_detail,
                    "applied_at" => receipt.applied_at && DateTime.to_iso8601(receipt.applied_at)
                  }

                  event_data =
                    if receipt.last_applied_generation != nil do
                      Map.put(
                        event_data,
                        "last_applied_generation",
                        receipt.last_applied_generation
                      )
                    else
                      event_data
                    end

                  event_data =
                    if receipt.observation_sequence != nil do
                      Map.put(
                        event_data,
                        "observation_sequence",
                        receipt.observation_sequence
                      )
                    else
                      event_data
                    end

                  attrs = %{
                    event_type: "pki.client_auth.agent_receipt_recorded",
                    actor_type: "agent",
                    actor_id: actor_id,
                    source_ip: "127.0.0.1",
                    access_granted: receipt.status == "applied",
                    correlation_id: receipt.id,
                    hash_version: 2,
                    event_data: event_data
                  }

                  case Audit.log_event(attrs) do
                    {:ok, _} ->
                      receipt

                    {:error, audit_err} ->
                      Repo.rollback({:audit_failed, audit_err})
                  end

                {:error, changeset} ->
                  Repo.rollback(changeset)
              end

            {:error, :conflicting_observation_sequence} ->
              case record_equivocation_audit_for_conflict(authority, receipt_attrs, existing) do
                {:ok, _} ->
                  {:conflict, :conflicting_observation_sequence}

                {:error, audit_err} ->
                  Repo.rollback({:audit_failed, audit_err})
              end
          end
        end)

      case res do
        {:ok, {:conflict, reason}} ->
          {:error, reason}

        {:ok, receipt} ->
          {:ok, receipt}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Pure state transition function for agent trust bundle receipts.
  Enforces sequence-first and bidirectional timestamp ordering:
  1. Monotonic sender sequence (`observation_sequence`):
     - `incoming_seq < existing_seq`: stale observation ignored (`{:ignore, existing}`).
     - `incoming_seq == existing_seq`: identical payload is idempotent replay (`{:ok, existing}`); differing payload is rejected (`{:error, :conflicting_observation_sequence}`).
     - `incoming_seq > existing_seq`: strictly updates state.
  2. Fallback to timestamp comparison when sequences are absent.
  3. Failed candidate observations never advance or clear the successful installation watermark (`last_applied_*`).
  4. Successful installations advance `last_applied_*` monotonically.
  5. Missing timestamps are not substituted with arrival time.
  """
  def transition_receipt(nil, attrs) do
    status = attrs[:status] || "applied"
    seq = attrs[:observation_sequence] || 1

    base_attrs =
      if status == "applied" do
        %{
          last_applied_generation: attrs[:generation],
          last_applied_crl_number: attrs[:crl_number],
          last_applied_bundle_sha256: attrs[:bundle_sha256],
          last_applied_at: attrs[:applied_at]
        }
      else
        %{
          last_applied_generation: nil,
          last_applied_crl_number: nil,
          last_applied_bundle_sha256: nil,
          last_applied_at: nil
        }
      end

    updated =
      attrs
      |> Map.merge(base_attrs)
      |> Map.put(:observation_sequence, seq)

    {:ok, updated}
  end

  def transition_receipt(%ClientAuthBundleReceipt{} = existing, attrs) do
    status = attrs[:status] || "applied"
    incoming_gen = attrs[:generation] || 0
    last_applied = existing.last_applied_generation

    incoming_seq = attrs[:observation_sequence]
    existing_seq = existing.observation_sequence

    cond do
      is_integer(incoming_seq) ->
        existing_seq_val = existing_seq || 0

        cond do
          incoming_seq < existing_seq_val ->
            {:ignore, existing}

          incoming_seq == existing_seq_val ->
            if is_duplicate_observation?(existing, attrs) do
              {:ignore, existing}
            else
              {:error, :conflicting_observation_sequence}
            end

          incoming_seq > existing_seq_val ->
            apply_receipt_update(existing, attrs, incoming_seq)
        end

      true ->
        # Fallback when incoming observation has no sender-assigned sequence
        cond do
          status == "applied" and last_applied != nil and incoming_gen < last_applied ->
            {:ignore, existing}

          status == "failed" and last_applied != nil and incoming_gen < last_applied ->
            {:ignore, existing}

          status == "failed" and last_applied == nil and incoming_gen < existing.generation ->
            {:ignore, existing}

          true ->
            incoming_dt = parse_receipt_datetime(attrs[:applied_at])
            existing_dt = parse_receipt_datetime(existing.applied_at || existing.updated_at)

            order =
              compare_observation_order(incoming_dt, existing_dt, incoming_seq, existing_seq)

            case order do
              :older ->
                {:ignore, existing}

              :same ->
                {:ignore, existing}

              newer when newer in [:newer, :newer_candidate] ->
                if newer == :newer_candidate and is_duplicate_observation?(existing, attrs) do
                  {:ignore, existing}
                else
                  next_seq =
                    if is_integer(incoming_seq) and incoming_seq > (existing_seq || 0) do
                      incoming_seq
                    else
                      (existing_seq || 0) + 1
                    end

                  apply_receipt_update(existing, attrs, next_seq)
                end
            end
        end
    end
  end

  defp apply_receipt_update(existing, attrs, next_seq) do
    status = attrs[:status] || "applied"
    incoming_gen = attrs[:generation] || 0
    last_applied = existing.last_applied_generation
    applied_at = attrs[:applied_at]

    installation_attrs =
      if status == "applied" do
        if last_applied != nil and incoming_gen < last_applied do
          %{
            last_applied_generation: existing.last_applied_generation,
            last_applied_crl_number: existing.last_applied_crl_number,
            last_applied_bundle_sha256: existing.last_applied_bundle_sha256,
            last_applied_at: existing.last_applied_at
          }
        else
          %{
            last_applied_generation: attrs[:generation],
            last_applied_crl_number: attrs[:crl_number],
            last_applied_bundle_sha256: attrs[:bundle_sha256],
            last_applied_at: applied_at || existing.last_applied_at
          }
        end
      else
        # Failed candidate preserves existing last_applied watermark
        %{
          last_applied_generation: existing.last_applied_generation,
          last_applied_crl_number: existing.last_applied_crl_number,
          last_applied_bundle_sha256: existing.last_applied_bundle_sha256,
          last_applied_at: existing.last_applied_at
        }
      end

    updated =
      attrs
      |> Map.merge(installation_attrs)
      |> Map.put(:observation_sequence, next_seq)

    {:ok, updated}
  end

  defp compare_observation_order(incoming_dt, existing_dt, incoming_seq, existing_seq) do
    cond do
      incoming_dt != nil and existing_dt != nil ->
        case DateTime.compare(incoming_dt, existing_dt) do
          :lt ->
            :older

          :gt ->
            :newer

          :eq ->
            cond do
              is_integer(incoming_seq) and is_integer(existing_seq) and
                  incoming_seq != existing_seq ->
                if incoming_seq > existing_seq, do: :newer, else: :older

              true ->
                :newer_candidate
            end
        end

      incoming_dt != nil and existing_dt == nil ->
        :newer

      incoming_dt == nil and existing_dt != nil ->
        # Incoming report is undated but arrived live; if sequence was not assigned, treat as candidate update
        :newer_candidate

      true ->
        if is_integer(incoming_seq) and is_integer(existing_seq) and incoming_seq != existing_seq do
          if incoming_seq > existing_seq, do: :newer, else: :older
        else
          :same
        end
    end
  end

  defp is_duplicate_observation?(existing, attrs) do
    attrs_status = to_string(attrs[:status] || "applied")

    existing.status == attrs_status and
      existing.generation == attrs[:generation] and
      existing.crl_number == attrs[:crl_number] and
      existing.bundle_sha256 == attrs[:bundle_sha256] and
      existing.last_error_code == attrs[:last_error_code]
  end

  defp record_equivocation_audit_for_conflict(authority, receipt_attrs, _existing) do
    attrs = %{
      event_type: "pki.client_auth.agent_equivocation_detected",
      actor_type: "agent",
      actor_id: receipt_attrs.agent_id,
      source_ip: "127.0.0.1",
      access_granted: false,
      correlation_id: authority.id,
      hash_version: 2,
      event_data: %{
        "agent_id" => receipt_attrs.agent_id,
        "authority_id" => authority.id,
        "generation" => receipt_attrs.generation,
        "reported_bundle_sha256" => receipt_attrs.bundle_sha256,
        "reported_status" => receipt_attrs.status
      }
    }

    Audit.log_event(attrs)
  end

  defp parse_receipt_datetime(%DateTime{} = dt), do: DateTime.truncate(dt, :second)

  defp parse_receipt_datetime(iso_str) when is_binary(iso_str) do
    case DateTime.from_iso8601(iso_str) do
      {:ok, dt, _} -> DateTime.truncate(dt, :second)
      _ -> nil
    end
  end

  defp parse_receipt_datetime(_), do: nil

  @doc """
  Lists bundle receipts with pagination.
  """
  @spec list_bundle_receipts(keyword() | binary() | ClientAuthAuthority.t()) ::
          [ClientAuthBundleReceipt.t()]
  @spec list_bundle_receipts(ClientAuthAuthority.t() | binary(), keyword() | map()) ::
          [ClientAuthBundleReceipt.t()]
  def list_bundle_receipts(authority_or_opts \\ [])

  def list_bundle_receipts(opts) when is_list(opts) do
    opts = normalize_opts(opts)
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    query =
      from(r in ClientAuthBundleReceipt,
        order_by: [desc: r.updated_at],
        limit: ^limit,
        offset: ^offset
      )

    Repo.all(query)
  end

  def list_bundle_receipts(%ClientAuthAuthority{id: authority_id}) do
    list_bundle_receipts(authority_id, [])
  end

  def list_bundle_receipts(slug_or_id) when is_binary(slug_or_id) do
    list_bundle_receipts(slug_or_id, [])
  end

  def list_bundle_receipts(%ClientAuthAuthority{id: authority_id}, opts) do
    list_bundle_receipts(authority_id, opts)
  end

  def list_bundle_receipts(slug_or_id, opts) when is_binary(slug_or_id) do
    opts = normalize_opts(opts)
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    authority_id =
      case Ecto.UUID.cast(slug_or_id) do
        {:ok, uuid} ->
          uuid

        :error ->
          case Repo.one(
                 from(a in ClientAuthAuthority, where: a.slug == ^slug_or_id, select: a.id)
               ) do
            nil -> nil
            id -> id
          end
      end

    if authority_id do
      query =
        from(r in ClientAuthBundleReceipt,
          where: r.client_auth_authority_id == ^authority_id,
          order_by: [desc: r.updated_at],
          limit: ^limit,
          offset: ^offset
        )

      Repo.all(query)
    else
      []
    end
  end

  defp verify_applied_bundle_authenticity(authority, receipt_attrs) do
    if receipt_attrs.status == "applied" do
      crl =
        Repo.one(
          from(c in ClientAuthCrl,
            where: c.authority_id == ^authority.id and c.generation == ^receipt_attrs.generation
          )
        )

      ca = authority.ca_certificate

      cond do
        is_nil(crl) or is_nil(ca) ->
          record_unknown_bundle_audit(authority, receipt_attrs, "unknown_generation")

          %{
            receipt_attrs
            | status: "failed",
              last_error_code: "unknown_generation_bundle",
              last_error_detail:
                "Generation #{receipt_attrs.generation} is not an authentic Core bundle"
          }

        receipt_attrs.crl_number != nil and receipt_attrs.crl_number != crl.crl_number ->
          record_unknown_bundle_audit(authority, receipt_attrs, "crl_number_mismatch")

          %{
            receipt_attrs
            | status: "failed",
              last_error_code: "crl_number_mismatch",
              last_error_detail:
                "Reported crl_number #{receipt_attrs.crl_number} does not match historical #{crl.crl_number}"
          }

        true ->
          expected_bundle = TrustBundle.build(authority, ca, crl, generation: crl.generation)

          if expected_bundle["bundle_sha256"] != receipt_attrs.bundle_sha256 do
            record_unknown_bundle_audit(authority, receipt_attrs, "hash_mismatch")

            %{
              receipt_attrs
              | status: "failed",
                last_error_code: "bundle_hash_mismatch_equivocation",
                last_error_detail:
                  "Reported hash #{receipt_attrs.bundle_sha256} does not match expected #{expected_bundle["bundle_sha256"]}"
            }
          else
            receipt_attrs
          end
      end
    else
      receipt_attrs
    end
  end

  defp maybe_record_equivocation_audit(authority, receipt_attrs, existing) do
    has_conflict =
      existing != nil and
        existing.generation == receipt_attrs.generation and
        existing.bundle_sha256 != "" and
        receipt_attrs.bundle_sha256 != "" and
        existing.bundle_sha256 != receipt_attrs.bundle_sha256

    if has_conflict do
      attrs = %{
        event_type: "pki.client_auth.agent_equivocation_detected",
        actor_type: "agent",
        actor_id: receipt_attrs.agent_id,
        source_ip: "127.0.0.1",
        access_granted: false,
        correlation_id: authority.id,
        hash_version: 2,
        event_data: %{
          "agent_id" => receipt_attrs.agent_id,
          "authority_id" => authority.id,
          "generation" => receipt_attrs.generation,
          "reported_bundle_sha256" => receipt_attrs.bundle_sha256,
          "reported_status" => receipt_attrs.status
        }
      }

      Audit.log_event(attrs)
    else
      :ok
    end
  end

  defp record_unknown_bundle_audit(authority, receipt_attrs, _reason) do
    attrs = %{
      event_type: "pki.client_auth.agent_equivocation_detected",
      actor_type: "agent",
      actor_id: receipt_attrs.agent_id,
      source_ip: "127.0.0.1",
      access_granted: false,
      correlation_id: authority.id,
      hash_version: 2,
      event_data: %{
        "agent_id" => receipt_attrs.agent_id,
        "authority_id" => authority.id,
        "generation" => receipt_attrs.generation,
        "reported_bundle_sha256" => receipt_attrs.bundle_sha256,
        "reported_status" => receipt_attrs.status
      }
    }

    Audit.log_event(attrs)
  end

  defp get_active_authority do
    case Repo.one(
           from(a in ClientAuthAuthority,
             where: a.slug == "client-auth" and a.status == "active",
             preload: [:ca_certificate, :current_crl]
           )
         ) do
      nil -> {:error, :authority_not_initialized}
      authority -> {:ok, authority}
    end
  end

  defp normalize_opts(opts) when is_map(opts) do
    Enum.reduce(opts, [], fn
      {"identity_id", val}, acc -> Keyword.put(acc, :identity_id, val)
      {:identity_id, val}, acc -> Keyword.put(acc, :identity_id, val)
      {"status", val}, acc -> Keyword.put(acc, :status, to_string(val))
      {:status, val}, acc -> Keyword.put(acc, :status, to_string(val))
      {"search", val}, acc -> Keyword.put(acc, :search, to_string(val))
      {:search, val}, acc -> Keyword.put(acc, :search, to_string(val))
      {"revoked", val}, acc -> Keyword.put(acc, :revoked, parse_bool(val))
      {:revoked, val}, acc -> Keyword.put(acc, :revoked, parse_bool(val))
      {"limit", val}, acc -> Keyword.put(acc, :limit, parse_int(val, 100))
      {:limit, val}, acc -> Keyword.put(acc, :limit, parse_int(val, 100))
      {"offset", val}, acc -> Keyword.put(acc, :offset, parse_int(val, 0))
      {:offset, val}, acc -> Keyword.put(acc, :offset, parse_int(val, 0))
      {k, v}, acc when is_atom(k) -> Keyword.put(acc, k, v)
      {_k, _v}, acc -> acc
    end)
  end

  defp normalize_opts(opts) when is_list(opts), do: opts

  defp parse_bool(true), do: true
  defp parse_bool(false), do: false
  defp parse_bool("true"), do: true
  defp parse_bool("false"), do: false
  defp parse_bool(_), do: nil

  defp parse_int(val, _default) when is_integer(val), do: val

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, ""} -> int
      _ -> default
    end
  end

  defp parse_int(_, default), do: default
end
