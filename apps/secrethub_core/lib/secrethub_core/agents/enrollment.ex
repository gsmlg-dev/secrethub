defmodule SecretHub.Core.Agents.Enrollment do
  @moduledoc """
  Pending HTTPS Agent enrollment workflow.
  """

  import Ecto.Query

  alias SecretHub.Core.PKI
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, AgentEnrollment}

  @pending_ttl_seconds 24 * 60 * 60

  def create_pending(attrs, source_ip \\ nil) do
    pending_token = new_pending_token()

    attrs =
      attrs
      |> atomize_keys()
      |> Map.put(:source_ip, source_ip)
      |> Map.put(:pending_token_hash, hash_token(pending_token))
      |> Map.put(:expires_at, seconds_from_now(@pending_ttl_seconds))

    %AgentEnrollment{}
    |> AgentEnrollment.pending_changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, enrollment} -> {:ok, %{enrollment: enrollment, pending_token: pending_token}}
      {:error, changeset} -> {:error, changeset}
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
      {:ok, status_payload(enrollment)}
    end
  end

  def approve(enrollment_id, operator_id) do
    with %AgentEnrollment{} = enrollment <- Repo.get(AgentEnrollment, enrollment_id),
         :ok <- verify_not_expired(enrollment),
         :ok <- verify_status(enrollment, [:pending_registered]),
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

  def submit_csr(enrollment_id, pending_token, csr_pem) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token),
         :ok <- verify_not_expired(enrollment),
         :ok <- verify_status(enrollment, [:approved_waiting_for_csr, :csr_invalid]),
         {:ok, csr} <- PKI.CSR.parse(csr_pem),
         :ok <- verify_csr_fingerprint(enrollment, csr) do
      issue_certificate(enrollment, csr_pem, csr)
    else
      {:error, reason}
      when reason in [
             :not_found,
             :expired,
             :invalid_pending_token,
             :invalid_status,
             :fingerprint_mismatch
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
      enrollment
      |> AgentEnrollment.changeset(%{status: :finalized, last_error: nil})
      |> Repo.update()
    end
  end

  def finalize(enrollment_id, pending_token, %{
        "status" => "trusted_endpoint_failed",
        "error" => error
      }) do
    with {:ok, enrollment} <- authorize(enrollment_id, pending_token) do
      enrollment
      |> AgentEnrollment.changeset(%{status: :trusted_endpoint_failed, last_error: error})
      |> Repo.update()
    end
  end

  def finalize(_enrollment_id, _pending_token, _payload), do: {:error, :invalid_finalize_payload}

  def list_pending do
    AgentEnrollment
    |> order_by([e], desc: e.inserted_at)
    |> Repo.all()
  end

  def get_enrollment(id), do: Repo.get(AgentEnrollment, id)

  defp issue_certificate(enrollment, csr_pem, csr) do
    enrollment
    |> AgentEnrollment.changeset(%{status: :csr_submitted, csr_pem: csr_pem, last_error: nil})
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        case PKI.Issuer.issue_agent_certificate_from_csr(updated, csr) do
          {:ok, certificate} ->
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
            updated
            |> AgentEnrollment.changeset(%{
              status: :certificate_issue_failed,
              last_error: %{"reason" => inspect(reason)}
            })
            |> Repo.update()

            {:error, :certificate_issue_failed}
        end

      error ->
        error
    end
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

  defp verify_csr_fingerprint(enrollment, csr) do
    if PKI.CSR.public_key_fingerprint(csr) == enrollment.ssh_host_key_fingerprint do
      :ok
    else
      {:error, :fingerprint_mismatch}
    end
  end

  defp create_or_reuse_agent(enrollment) do
    case Repo.get_by(Agent, ssh_host_key_fingerprint: enrollment.ssh_host_key_fingerprint) do
      %Agent{} = agent ->
        {:ok, agent}

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

  defp required_csr_fields(enrollment, agent_id) do
    uri_sans = [
      "urn:secrethub:agent:#{agent_id}",
      "urn:secrethub:ssh-hostkey-sha256:#{strip_sha256_prefix(enrollment.ssh_host_key_fingerprint)}"
    ]

    dns_sans =
      [enrollment.hostname, enrollment.fqdn]
      |> Enum.filter(&valid_dns?/1)
      |> Enum.uniq()

    %{
      "subject" => %{"O" => "SecretHub Agents", "CN" => agent_id},
      "san" => %{"uri" => uri_sans, "dns" => dns_sans},
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
    ssh_host_key_fingerprint capabilities
  )

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
    Application.get_env(:secrethub_core, :agent_certificate_ttl_seconds, 90 * 24 * 60 * 60)
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
