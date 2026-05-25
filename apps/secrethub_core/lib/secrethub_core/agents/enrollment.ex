defmodule SecretHub.Core.Agents.Enrollment do
  @moduledoc """
  Pending HTTPS Agent enrollment workflow.
  """

  import Ecto.Query

  alias SecretHub.Core.PKI
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias SecretHub.Shared.Schemas.{Agent, AgentEnrollment}

  @pending_ttl_seconds 24 * 60 * 60
  @default_presence_timeout_ms 10_000
  @max_ssh_host_public_key_bytes 16 * 1024
  @presence_statuses [:pending_registered, :approved_waiting_for_csr]
  @stale_cleanup_statuses [:pending_registered]
  @pending_list_statuses [:pending_registered]
  @blocked_reenrollment_agent_statuses [:revoked, :suspended]
  @finalize_success_statuses [
    :certificate_issued,
    :connect_info_delivered,
    :trusted_connecting,
    :trusted_connected
  ]
  @finalize_failure_statuses [:certificate_issued, :connect_info_delivered, :trusted_connecting]

  def create_pending(attrs, source_ip \\ nil) do
    pending_token = new_pending_token()

    attrs =
      attrs
      |> atomize_keys()
      |> Map.put(:source_ip, source_ip)
      |> Map.put(:pending_token_hash, hash_token(pending_token))
      |> Map.put(:expires_at, seconds_from_now(@pending_ttl_seconds))

    with {:ok, attrs} <- validate_ssh_host_public_key(attrs),
         {:ok, enrollment} <-
           %AgentEnrollment{}
           |> AgentEnrollment.pending_changeset(attrs)
           |> Repo.insert() do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}}
    else
      {:error, %Ecto.Changeset{} = changeset} -> {:error, changeset}
    end
  end

  def authorize(enrollment_id, pending_token) do
    with %AgentEnrollment{} = enrollment <- Repo.get(AgentEnrollment, enrollment_id),
         :ok <- verify_token(enrollment, pending_token) do
      {:ok, enrollment}
    else
      nil -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  def status(enrollment_id, pending_token) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token),
         :ok <- verify_not_expired(enrollment) do
      enrollment = touch_presence(enrollment)
      {:ok, status_payload(enrollment)}
    end
  end

  def approve(enrollment_id, operator_id) do
    with %AgentEnrollment{} = enrollment <- Repo.get(AgentEnrollment, enrollment_id),
         :ok <- verify_not_expired(enrollment),
         :ok <- verify_status(enrollment, [:pending_registered]),
         {:ok, _ca} <- PKI.Issuer.active_signing_ca(),
         {:ok, agent} <- create_or_reuse_agent(enrollment),
         required_fields <- required_csr_fields(enrollment, agent.agent_id) do
      enrollment
      |> AgentEnrollment.changeset(%{
        status: :approved_waiting_for_csr,
        agent_id: agent.agent_id,
        approved_by: operator_id,
        approved_at: now(),
        required_csr_fields: required_fields
      })
      |> Repo.update()
    else
      nil -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  def reject(enrollment_id, operator_id, reason \\ "rejected") do
    update_decision(enrollment_id, %{
      status: :rejected,
      rejected_by: operator_id,
      rejected_at: now(),
      last_error: %{"reason" => reason}
    })
  end

  def expire(enrollment_id) do
    update_decision(enrollment_id, %{status: :expired, last_error: %{"reason" => "expired"}})
  end

  def reset(enrollment_id) do
    update_decision(enrollment_id, %{
      status: :pending_registered,
      agent_id: nil,
      required_csr_fields: %{},
      csr_pem: nil,
      last_error: nil,
      approved_by: nil,
      approved_at: nil,
      rejected_by: nil,
      rejected_at: nil,
      expires_at: seconds_from_now(@pending_ttl_seconds)
    })
  end

  def submit_csr(enrollment_id, pending_token, payload) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token),
         :ok <- verify_not_expired(enrollment),
         :ok <- verify_status(enrollment, [:approved_waiting_for_csr, :csr_invalid]),
         {:ok, csr_pem, proof} <- csr_submission(payload),
         {:ok, ssh_host_public_key} <- decode_enrollment_ssh_public_key(enrollment),
         :ok <- verify_enrollment_host_fingerprint(enrollment, ssh_host_public_key),
         :ok <- verify_csr_proof(enrollment, ssh_host_public_key, csr_pem, proof),
         {:ok, csr} <- PKI.CSR.parse(csr_pem),
         :ok <- verify_csr_identity(enrollment, csr, ssh_host_public_key),
         :ok <- verify_agent_can_receive_certificate(enrollment.agent_id) do
      issue_certificate(enrollment, csr_pem, csr)
    else
      {:error, reason}
      when reason in [
             :not_found,
             :expired,
             :invalid_pending_token,
             :invalid_status,
             :missing_proof,
             :invalid_host_public_key,
             :host_public_key_mismatch,
             :unsupported_key_algorithm,
             :agent_not_found,
             :agent_reenrollment_blocked
           ] ->
        {:error, reason}

      {:error, reason} ->
        mark_csr_invalid(enrollment_id, reason)
    end
  end

  def connect_info(enrollment_id, pending_token) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token),
         :ok <- verify_not_expired(enrollment),
         :ok <- verify_status(enrollment, [:certificate_issued, :connect_info_delivered]) do
      endpoint = Application.get_env(:secrethub_web, :agent_trusted_endpoint)
      server_name = endpoint && URI.parse(endpoint).host

      enrollment
      |> AgentEnrollment.changeset(%{status: :connect_info_delivered})
      |> Repo.update()
      |> case do
        {:ok, _} ->
          {:ok,
           %{
             trusted_websocket_endpoint: endpoint,
             expected_core_server_name: server_name,
             core_ca_cert_pem: ca_chain_pem(),
             core_ca_fingerprint: ca_fingerprint(),
             heartbeat_interval_ms: 30_000,
             connect_timeout_ms: 10_000
           }}

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  def finalize(enrollment_id, pending_token, %{"status" => "trusted_connected"}) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token) do
      finalize_success(enrollment)
    end
  end

  def finalize(enrollment_id, pending_token, %{
        "status" => "trusted_endpoint_failed",
        "error" => error
      }) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token) do
      finalize_failure(enrollment, error)
    end
  end

  def finalize(_enrollment_id, _pending_token, _payload), do: {:error, :invalid_finalize_payload}

  def list_pending(opts \\ []) do
    cleanup_stale_pending(opts)

    AgentEnrollment
    |> where([e], e.status in ^@pending_list_statuses)
    |> order_by([e], desc: e.inserted_at)
    |> Repo.all()
  end

  def get_enrollment(id), do: Repo.get(AgentEnrollment, id)

  defp finalize_success(%AgentEnrollment{id: enrollment_id}) do
    case guarded_finalize_update(enrollment_id, @finalize_success_statuses,
           status: :finalized,
           last_error: nil
         ) do
      {:ok, enrollment} ->
        {:ok, enrollment}

      {:error, :invalid_status} ->
        case Repo.get(AgentEnrollment, enrollment_id) do
          %AgentEnrollment{status: :finalized} = enrollment -> {:ok, enrollment}
          %AgentEnrollment{} -> {:error, :invalid_status}
          nil -> {:error, :not_found}
        end
    end
  end

  defp finalize_failure(%AgentEnrollment{id: enrollment_id}, error) do
    case guarded_finalize_update(enrollment_id, @finalize_failure_statuses,
           status: :trusted_endpoint_failed,
           last_error: error
         ) do
      {:ok, enrollment} ->
        {:ok, enrollment}

      {:error, :invalid_status} ->
        case Repo.get(AgentEnrollment, enrollment_id) do
          %AgentEnrollment{status: :trusted_endpoint_failed} = enrollment -> {:ok, enrollment}
          %AgentEnrollment{} -> {:error, :invalid_status}
          nil -> {:error, :not_found}
        end
    end
  end

  defp guarded_finalize_update(enrollment_id, allowed_statuses, attrs) do
    updates = Keyword.put(attrs, :updated_at, now())

    {count, _} =
      AgentEnrollment
      |> where([e], e.id == ^enrollment_id)
      |> where([e], e.status in ^allowed_statuses)
      |> Repo.update_all(set: updates)

    case count do
      1 -> {:ok, Repo.get!(AgentEnrollment, enrollment_id)}
      0 -> {:error, :invalid_status}
    end
  end

  defp issue_certificate(enrollment, csr_pem, csr) do
    enrollment
    |> AgentEnrollment.changeset(%{status: :csr_submitted, csr_pem: csr_pem, last_error: nil})
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        case PKI.Issuer.issue_agent_certificate_from_csr(updated, csr) do
          {:ok, certificate} ->
            case bind_agent_certificate(updated.agent_id, certificate.id) do
              {:ok, _agent} ->
                updated
                |> AgentEnrollment.changeset(%{
                  status: :certificate_issued,
                  last_error: nil
                })
                |> Repo.update()
                |> case do
                  {:ok, enrollment} -> {:ok, %{enrollment: enrollment, certificate: certificate}}
                  error -> error
                end

              {:error, reason} ->
                Repo.delete(certificate)
                mark_certificate_issue_failed(updated, reason)
            end

          {:error, reason} ->
            mark_certificate_issue_failed(updated, reason)
        end

      error ->
        error
    end
  end

  defp bind_agent_certificate(agent_id, certificate_id) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{status: status} when status in @blocked_reenrollment_agent_statuses ->
        {:error, :agent_reenrollment_blocked}

      %Agent{} = agent ->
        agent
        |> Agent.changeset(%{status: :certificate_issued, certificate_id: certificate_id})
        |> Repo.update()

      nil ->
        {:error, :agent_not_found}
    end
  end

  defp mark_certificate_issue_failed(enrollment, reason) do
    enrollment
    |> AgentEnrollment.changeset(%{
      status: :certificate_issue_failed,
      last_error: %{"reason" => inspect(reason)}
    })
    |> Repo.update()

    {:error, {:certificate_issue_failed, reason}}
  end

  defp mark_csr_invalid(enrollment_id, reason) do
    case Repo.get(AgentEnrollment, enrollment_id) do
      %AgentEnrollment{} = enrollment ->
        enrollment
        |> AgentEnrollment.changeset(%{
          status: :csr_invalid,
          last_error: %{"reason" => "CSR invalid: #{inspect(reason)}"}
        })
        |> Repo.update()

      nil ->
        :ok
    end

    {:error, :csr_invalid}
  end

  defp csr_submission(%{"csr_pem" => csr_pem, "ssh_proof" => proof}) when is_map(proof),
    do: {:ok, csr_pem, proof}

  defp csr_submission(%{"csr_pem" => _csr_pem}), do: {:error, :missing_proof}
  defp csr_submission(_payload), do: {:error, :missing_proof}

  defp decode_enrollment_ssh_public_key(%AgentEnrollment{ssh_host_public_key: public_key_text})
       when is_binary(public_key_text) do
    case apply(:ssh_file, :decode, [public_key_text, :public_key]) do
      [{public_key, _attrs}] -> {:ok, public_key}
      _other -> {:error, :invalid_host_public_key}
    end
  rescue
    _e -> {:error, :invalid_host_public_key}
  end

  defp decode_enrollment_ssh_public_key(_enrollment), do: {:error, :invalid_host_public_key}

  defp verify_enrollment_host_fingerprint(enrollment, ssh_host_public_key) do
    if PKI.CSR.ssh_fingerprint(ssh_host_public_key) == enrollment.ssh_host_key_fingerprint do
      :ok
    else
      {:error, :host_public_key_mismatch}
    end
  end

  defp verify_csr_proof(enrollment, ssh_host_public_key, csr_pem, proof) do
    case AgentCSRProof.verify(ssh_host_public_key, %{
           enrollment_id: enrollment.id,
           challenge: enrollment.required_csr_fields["challenge"],
           csr_pem: csr_pem,
           proof: proof
         }) do
      {:ok, _metadata} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_csr_identity(enrollment, csr, ssh_host_public_key) do
    with :ok <- verify_csr_tls_key_is_distinct(csr, ssh_host_public_key),
         :ok <- verify_csr_subject(enrollment, csr),
         :ok <- verify_csr_sans(enrollment, csr) do
      :ok
    end
  end

  defp verify_csr_tls_key_is_distinct(csr, ssh_host_public_key) do
    if X509.CSR.public_key(csr) == ssh_host_public_key do
      {:error, :tls_key_matches_ssh_host_key}
    else
      :ok
    end
  end

  defp verify_csr_subject(enrollment, csr) do
    expected_subject = enrollment.required_csr_fields["subject"] || %{}
    subject = X509.CSR.subject(csr)

    with :ok <- verify_csr_subject_attr(subject, "O", expected_subject["O"]),
         :ok <- verify_csr_subject_attr(subject, "CN", expected_subject["CN"]) do
      :ok
    end
  end

  defp verify_csr_subject_attr(_subject, _attr, nil), do: :ok

  defp verify_csr_subject_attr(subject, attr, expected) do
    if X509.RDNSequence.get_attr(subject, attr) == [expected] do
      :ok
    else
      {:error, :csr_subject_mismatch}
    end
  end

  defp verify_csr_sans(enrollment, csr) do
    expected_sans = enrollment.required_csr_fields["san"] || %{}
    actual_sans = csr_sans(csr)

    with :ok <- verify_csr_san_values(actual_sans.uri, expected_sans["uri"]),
         :ok <- verify_csr_san_values(actual_sans.dns, expected_sans["dns"]) do
      :ok
    end
  end

  defp verify_csr_san_values(_actual, nil), do: :ok

  defp verify_csr_san_values(actual, expected) do
    expected = expected |> List.wrap() |> Enum.sort()

    if Enum.sort(actual) == expected do
      :ok
    else
      {:error, :csr_san_mismatch}
    end
  end

  defp csr_sans(csr) do
    extension =
      csr
      |> X509.CSR.extension_request()
      |> X509.Certificate.Extension.find(:subject_alt_name)

    values = if extension, do: elem(extension, 3), else: []

    Enum.reduce(values, %{uri: [], dns: []}, fn
      {:uniformResourceIdentifier, value}, acc ->
        %{acc | uri: [to_string(value) | acc.uri]}

      {:dNSName, value}, acc ->
        %{acc | dns: [to_string(value) | acc.dns]}

      _other, acc ->
        acc
    end)
  end

  defp create_or_reuse_agent(enrollment) do
    case Repo.get_by(Agent, ssh_host_key_fingerprint: enrollment.ssh_host_key_fingerprint) do
      %Agent{status: status} when status in @blocked_reenrollment_agent_statuses ->
        {:error, :agent_reenrollment_blocked}

      %Agent{} = agent ->
        agent
        |> Ecto.Changeset.change(ssh_host_public_key: enrollment.ssh_host_public_key)
        |> Repo.update()

      nil ->
        agent_id = "agent-#{Ecto.UUID.generate()}"

        %Agent{}
        |> Agent.pki_registration_changeset(%{
          agent_id: agent_id,
          name: enrollment.hostname || agent_id,
          hostname: enrollment.hostname,
          fqdn: enrollment.fqdn,
          machine_id: enrollment.machine_id,
          ssh_host_key_algorithm: enrollment.ssh_host_key_algorithm,
          ssh_host_key_fingerprint: enrollment.ssh_host_key_fingerprint,
          ssh_host_public_key: enrollment.ssh_host_public_key,
          metadata: %{
            "os" => enrollment.os,
            "arch" => enrollment.arch,
            "agent_version" => enrollment.agent_version,
            "capabilities" => enrollment.capabilities || %{}
          },
          status: :approved_waiting_for_csr
        })
        |> Repo.insert()
    end
  end

  defp verify_agent_can_receive_certificate(agent_id) do
    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{status: status} when status in @blocked_reenrollment_agent_statuses ->
        {:error, :agent_reenrollment_blocked}

      %Agent{} ->
        :ok

      nil ->
        {:error, :agent_not_found}
    end
  end

  defp required_csr_fields(enrollment, agent_id) do
    uri_sans = [
      "urn:secrethub:agent:#{agent_id}",
      "urn:secrethub:hostkey-sha256:#{strip_sha256_prefix(enrollment.ssh_host_key_fingerprint)}"
    ]

    dns_sans =
      [enrollment.hostname, enrollment.fqdn]
      |> Enum.filter(&valid_dns?/1)
      |> Enum.uniq()

    %{
      "subject" => %{"O" => "SecretHub Agents", "CN" => agent_id},
      "san" => %{"uri" => uri_sans, "dns" => dns_sans},
      "challenge" => :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false),
      "key_usage" => ["digitalSignature"],
      "extended_key_usage" => ["clientAuth"],
      "validity" => %{"ttl_seconds" => certificate_ttl_seconds()}
    }
  end

  defp status_payload(enrollment) do
    payload = %{
      id: enrollment.id,
      status: enrollment.status,
      poll_interval_ms: 2_500
    }

    if enrollment.status == :approved_waiting_for_csr do
      Map.merge(payload, %{
        agent_id: enrollment.agent_id,
        required_csr_fields: enrollment.required_csr_fields,
        csr_submit_url: "/v1/agent/enrollments/#{enrollment.id}/csr"
      })
    else
      payload
    end
  end

  defp update_decision(enrollment_id, attrs) do
    case Repo.get(AgentEnrollment, enrollment_id) do
      %AgentEnrollment{} = enrollment ->
        enrollment
        |> AgentEnrollment.changeset(attrs)
        |> Repo.update()

      nil ->
        {:error, :not_found}
    end
  end

  defp cleanup_stale_pending(opts) do
    stale_after_ms =
      Keyword.get(
        opts,
        :stale_after_ms,
        Application.get_env(
          :secrethub_core,
          :agent_pending_presence_timeout_ms,
          @default_presence_timeout_ms
        )
      )

    cutoff =
      DateTime.utc_now()
      |> DateTime.add(-stale_after_ms, :millisecond)
      |> DateTime.truncate(:second)

    AgentEnrollment
    |> where([e], e.status in ^@stale_cleanup_statuses)
    |> where([e], e.updated_at < ^cutoff)
    |> Repo.delete_all()
  end

  defp touch_presence(%AgentEnrollment{status: status} = enrollment)
       when status in @presence_statuses do
    enrollment
    |> Ecto.Changeset.change()
    |> Ecto.Changeset.force_change(:updated_at, now())
    |> Repo.update()
    |> case do
      {:ok, updated} -> updated
      {:error, _changeset} -> enrollment
    end
  end

  defp touch_presence(enrollment), do: enrollment

  defp verify_token(%AgentEnrollment{pending_token_hash: hash}, pending_token)
       when is_binary(hash) and is_binary(pending_token) do
    if Plug.Crypto.secure_compare(hash, hash_token(pending_token)) do
      :ok
    else
      {:error, :invalid_pending_token}
    end
  end

  defp verify_token(_, _), do: {:error, :invalid_pending_token}

  defp verify_not_expired(enrollment) do
    if DateTime.compare(now(), enrollment.expires_at) == :gt do
      {:error, :expired}
    else
      :ok
    end
  end

  defp verify_status(enrollment, allowed) do
    if enrollment.status in allowed, do: :ok, else: {:error, :invalid_status}
  end

  defp new_pending_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp hash_token(token), do: :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

  @allowed_request_keys ~w(
    hostname fqdn machine_id os arch agent_version ssh_host_key_algorithm
    ssh_host_key_fingerprint ssh_host_public_key capabilities
  )

  defp validate_ssh_host_public_key(%{ssh_host_public_key: public_key_text} = attrs)
       when is_binary(public_key_text) do
    case normalize_ssh_host_public_key(public_key_text) do
      {:ok, public_key, normalized_public_key} ->
        with :ok <- verify_ssh_host_key_algorithm(public_key, attrs[:ssh_host_key_algorithm]),
             :ok <- verify_ssh_host_key_fingerprint(public_key, attrs[:ssh_host_key_fingerprint]) do
          {:ok, Map.put(attrs, :ssh_host_public_key, normalized_public_key)}
        else
          {:error, message} -> {:error, pending_changeset_error(attrs, message)}
        end

      {:error, message} ->
        {:error, pending_changeset_error(attrs, message)}
    end
  end

  defp validate_ssh_host_public_key(attrs), do: {:ok, attrs}

  defp normalize_ssh_host_public_key(public_key_text) do
    trimmed_public_key = String.trim(public_key_text)

    cond do
      String.contains?(public_key_text, <<0>>) ->
        {:error, "must not contain NUL bytes"}

      byte_size(public_key_text) > @max_ssh_host_public_key_bytes ->
        {:error, "must be #{@max_ssh_host_public_key_bytes} bytes or less"}

      String.contains?(trimmed_public_key, ["\n", "\r"]) ->
        {:error, "must be a single OpenSSH public key line"}

      true ->
        decode_ssh_host_public_key(trimmed_public_key)
    end
  end

  defp decode_ssh_host_public_key(trimmed_public_key) do
    case apply(:ssh_file, :decode, [trimmed_public_key, :public_key]) do
      [{public_key, _attrs}] ->
        case ssh_host_key_algorithm(public_key) do
          nil ->
            {:error, "must be an RSA or ECDSA OpenSSH public key"}

          _algorithm ->
            {:ok, public_key, encode_ssh_host_public_key(public_key)}
        end

      _other ->
        {:error, "must contain exactly one OpenSSH public key"}
    end
  rescue
    _e -> {:error, "must be a valid OpenSSH public key"}
  end

  defp encode_ssh_host_public_key(public_key) do
    [{public_key, []}]
    |> then(&apply(:ssh_file, :encode, [&1, :openssh_key]))
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp verify_ssh_host_key_algorithm(_public_key, nil), do: :ok

  defp verify_ssh_host_key_algorithm(public_key, algorithm) do
    if ssh_host_key_algorithm(public_key) == algorithm do
      :ok
    else
      {:error, "does not match ssh_host_key_algorithm"}
    end
  end

  defp verify_ssh_host_key_fingerprint(_public_key, nil), do: :ok

  defp verify_ssh_host_key_fingerprint(public_key, fingerprint) do
    if PKI.CSR.ssh_fingerprint(public_key) == fingerprint do
      :ok
    else
      {:error, "does not match ssh_host_key_fingerprint"}
    end
  end

  defp ssh_host_key_algorithm({:RSAPublicKey, _modulus, _exponent}), do: "rsa"

  defp ssh_host_key_algorithm({{:ECPoint, _point}, {:namedCurve, curve}})
       when curve in [
              {1, 2, 840, 10045, 3, 1, 7},
              {1, 3, 132, 0, 34},
              {1, 3, 132, 0, 35}
            ],
       do: "ecdsa"

  defp ssh_host_key_algorithm({_point, {:namedCurve, curve}})
       when curve in [
              {1, 2, 840, 10045, 3, 1, 7},
              {1, 3, 132, 0, 34},
              {1, 3, 132, 0, 35}
            ],
       do: "ecdsa"

  defp ssh_host_key_algorithm(_public_key), do: nil

  defp pending_changeset_error(attrs, message) do
    %AgentEnrollment{}
    |> AgentEnrollment.pending_changeset(attrs)
    |> Ecto.Changeset.add_error(:ssh_host_public_key, message)
  end

  defp atomize_keys(map) do
    Enum.reduce(map, %{}, fn
      {key, value}, acc when is_binary(key) and key in @allowed_request_keys ->
        Map.put(acc, String.to_existing_atom(key), value)

      {key, value}, acc when is_atom(key) ->
        Map.put(acc, key, value)

      _entry, acc ->
        acc
    end)
  end

  defp valid_dns?(value) when is_binary(value), do: String.contains?(value, ".")
  defp valid_dns?(_), do: false

  defp strip_sha256_prefix("SHA256:" <> fingerprint), do: fingerprint
  defp strip_sha256_prefix(fingerprint), do: fingerprint

  defp certificate_ttl_seconds do
    PKI.Issuer.agent_certificate_ttl_seconds()
  end

  defp seconds_from_now(seconds) do
    DateTime.utc_now()
    |> DateTime.add(seconds, :second)
    |> DateTime.truncate(:second)
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp ca_chain_pem do
    case SecretHub.Core.PKI.CA.get_ca_chain() do
      {:ok, chain} -> chain
      {:error, _} -> nil
    end
  end

  defp ca_fingerprint do
    case ca_chain_pem() do
      nil -> nil
      pem -> :crypto.hash(:sha256, pem) |> Base.encode16(case: :lower)
    end
  end
end
