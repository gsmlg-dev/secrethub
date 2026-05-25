defmodule SecretHub.Agent.Enrollment do
  @moduledoc """
  Pending HTTPS enrollment client for SecretHub Agent.

  This workflow uses an existing SSH host key to prove host identity and a
  separate TLS keypair for the runtime client certificate.
  """

  require Logger

  alias SecretHub.Agent.{HostKey, IdentityStore, TLSIdentity}
  alias SecretHub.Shared.Crypto.AgentCSRProof

  @default_poll_interval_ms 2_500
  @default_timeout_ms 300_000

  def enroll(opts) do
    core_url = Keyword.fetch!(opts, :core_url)
    storage_dir = Keyword.get(opts, :storage_dir, "priv/cert")

    with {:ok, host_key} <- host_key(opts),
         {:ok, pending} <- create_pending(core_url, host_key, opts),
         pending <- Map.put(pending, "enrollment_core_url", core_url),
         :ok <- notify_pending(pending, opts),
         {:ok, approved} <- wait_for_approval(core_url, pending, opts),
         {:ok, tls_identity} <- TLSIdentity.generate(approved["required_csr_fields"]),
         {:ok, issued} <- submit_csr(core_url, pending, approved, tls_identity, host_key),
         {:ok, connect_info} <- connect_info(core_url, pending),
         :ok <- store_material(storage_dir, pending, issued, connect_info, tls_identity) do
      {:ok,
       %{
         agent_id: issued["agent_id"] || approved["agent_id"],
         pending: pending,
         host_key: host_key,
         tls_identity: tls_identity,
         certificate_pem: issued["certificate_pem"],
         ca_chain_pem: issued["ca_chain_pem"] || connect_info["core_ca_cert_pem"],
         connect_info: connect_info,
         storage_dir: storage_dir
       }}
    end
  end

  def create_pending(core_url, %HostKey{} = host_key, opts \\ []) do
    payload = pending_payload(host_key, opts)

    core_url
    |> endpoint_url("/v1/agent/enrollments")
    |> post_json(payload, [])
  end

  def wait_for_approval(core_url, pending, opts \\ []) do
    timeout_ms = Keyword.get(opts, :approval_timeout_ms, @default_timeout_ms)
    deadline = approval_deadline(timeout_ms)

    poll_until_approved(core_url, pending, deadline)
  end

  def submit_csr(
        core_url,
        pending,
        approved,
        %TLSIdentity{} = tls_identity,
        %HostKey{} = host_key
      ) do
    with {:ok, challenge} <- csr_challenge(approved) do
      proof =
        AgentCSRProof.sign(host_key.private_key, %{
          enrollment_id: pending["enrollment_id"],
          challenge: challenge,
          csr_pem: tls_identity.csr_pem
        })

      core_url
      |> endpoint_url("/v1/agent/enrollments/#{pending["enrollment_id"]}/csr")
      |> post_json(
        %{"csr_pem" => tls_identity.csr_pem, "ssh_proof" => proof},
        bearer_headers(pending)
      )
    end
  end

  def connect_info(core_url, pending) do
    core_url
    |> endpoint_url("/v1/agent/enrollments/#{pending["enrollment_id"]}/connect-info")
    |> get_json(bearer_headers(pending))
  end

  def finalize(core_url, pending, payload) do
    core_url
    |> endpoint_url("/v1/agent/enrollments/#{pending["enrollment_id"]}/finalize")
    |> post_json(payload, bearer_headers(pending))
  end

  def finalize_failure(core_url, pending, error) do
    finalize(core_url, pending, %{
      "status" => "trusted_endpoint_failed",
      "error" => error
    })
  end

  def finalize_success(core_url, pending, storage_dir \\ "priv/cert") do
    with {:ok, finalized} <- finalize(core_url, pending, %{"status" => "trusted_connected"}),
         :ok <- delete_pending_token(storage_dir) do
      {:ok, finalized}
    end
  end

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

  def store_material(storage_dir, pending, issued, connect_info, tls_identity \\ nil) do
    with {:ok, material} <- trusted_material(pending, issued, connect_info, tls_identity),
         :ok <- write_pending_token(storage_dir, pending),
         :ok <- IdentityStore.write(storage_dir, material) do
      :ok
    end
  end

  defp trusted_material(pending, issued, connect_info, tls_identity) do
    with {:ok, private_key_pem} <- tls_private_key_pem(tls_identity) do
      {:ok,
       %{
         agent_id: first_present([issued, connect_info, pending], "agent_id"),
         certificate_pem: issued["certificate_pem"],
         private_key_pem: private_key_pem,
         ca_chain_pem: issued["ca_chain_pem"] || connect_info["core_ca_cert_pem"],
         connect_info: connect_info,
         identity: identity_metadata(pending, issued, connect_info)
       }}
    end
  end

  defp tls_private_key_pem(%TLSIdentity{private_key_pem: private_key_pem})
       when is_binary(private_key_pem) and private_key_pem != "" do
    {:ok, private_key_pem}
  end

  defp tls_private_key_pem(%TLSIdentity{}), do: {:error, :missing_tls_private_key_pem}
  defp tls_private_key_pem(_missing), do: {:error, :missing_tls_private_key_pem}

  defp identity_metadata(pending, issued, connect_info) do
    [
      {"agent_id", first_present([issued, connect_info, pending], "agent_id")},
      {"enrollment_id", first_present([pending, issued, connect_info], "enrollment_id")},
      {"certificate_fingerprint",
       first_present_key([issued, connect_info], ["certificate_fingerprint", "fingerprint"])},
      {"certificate_serial",
       first_present_key([issued, connect_info], ["certificate_serial", "serial_number", "serial"])},
      {"valid_until", first_present([issued, connect_info], "valid_until")},
      {"ssh_host_key_fingerprint",
       first_present([pending, connect_info], "ssh_host_key_fingerprint")},
      {"hostname", first_present([pending], "hostname")},
      {"fqdn", first_present([pending], "fqdn")},
      {"machine_id", first_present([pending], "machine_id")}
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp first_present_key(sources, keys) do
    Enum.find_value(keys, fn key -> first_present(sources, key) end)
  end

  defp first_present(sources, key) do
    Enum.find_value(sources, &source_value(&1, key))
  end

  defp source_value(source, key) when is_map(source) do
    Map.get(source, key) || Map.get(source, String.to_atom(key))
  end

  defp source_value(_source, _key), do: nil

  defp write_pending_token(storage_dir, pending) do
    pending_path = Path.join(storage_dir, "pending.json")

    with :ok <- File.mkdir_p(storage_dir),
         :ok <- File.chmod(storage_dir, 0o700),
         :ok <- File.write(pending_path, Jason.encode!(pending)) do
      File.chmod(pending_path, 0o600)
    end
  end

  def delete_pending_token(storage_dir) do
    pending_path = Path.join(storage_dir, "pending.json")

    if File.exists?(pending_path), do: File.rm(pending_path), else: :ok
  end

  defp poll_until_approved(core_url, pending, deadline) do
    case status(core_url, pending) do
      {:ok, %{"status" => "approved_waiting_for_csr"} = approved} ->
        {:ok, approved}

      {:ok, %{"status" => status} = payload}
      when status in ["rejected", "expired", "csr_invalid", "revoked"] ->
        {:error, {:enrollment_rejected, payload}}

      {:ok, payload} ->
        if approval_deadline_expired?(deadline) do
          {:error, :approval_timeout}
        else
          Process.sleep(payload["poll_interval_ms"] || @default_poll_interval_ms)
          poll_until_approved(core_url, pending, deadline)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp approval_deadline(:infinity), do: :infinity
  defp approval_deadline(timeout_ms), do: System.monotonic_time(:millisecond) + timeout_ms

  defp approval_deadline_expired?(:infinity), do: false

  defp approval_deadline_expired?(deadline) do
    System.monotonic_time(:millisecond) >= deadline
  end

  defp host_key(opts) do
    case Keyword.fetch(opts, :host_key) do
      {:ok, %HostKey{} = host_key} -> {:ok, host_key}
      :error -> HostKey.discover(opts)
    end
  end

  defp notify_pending(pending, opts) do
    case Keyword.get(opts, :on_pending) do
      callback when is_function(callback, 1) -> callback.(pending)
      _other -> :ok
    end
  end

  defp status(core_url, pending) do
    core_url
    |> endpoint_url("/v1/agent/enrollments/#{pending["enrollment_id"]}/status")
    |> get_json(bearer_headers(pending))
  end

  defp bearer_headers(%{"pending_token" => token}) do
    [{"authorization", "Bearer #{token}"}]
  end

  defp csr_challenge(approved) do
    case get_in(approved, ["required_csr_fields", "challenge"]) do
      challenge when is_binary(challenge) and byte_size(challenge) > 0 ->
        {:ok, challenge}

      _missing_or_invalid ->
        {:error, :missing_csr_challenge}
    end
  end

  defp endpoint_url(base_url, path) do
    base_url
    |> URI.parse()
    |> Map.put(:path, path)
    |> Map.put(:query, nil)
    |> URI.to_string()
  end

  defp post_json(url, payload, headers) do
    headers = [{"content-type", "application/json"} | headers]
    opts = [body: Jason.encode!(payload), headers: headers] ++ req_options()

    case Req.post(url, opts) do
      {:ok, %Req.Response{status: code, body: body}} when code in 200..299 ->
        decode_json(body)

      {:ok, %Req.Response{status: code, body: body}} ->
        {:error, {:http_error, code, decode_body(body)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_json(url, headers) do
    case Req.get(url, [headers: headers] ++ req_options()) do
      {:ok, %Req.Response{status: code, body: body}} when code in 200..299 ->
        decode_json(body)

      {:ok, %Req.Response{status: code, body: body}} ->
        {:error, {:http_error, code, decode_body(body)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp decode_json(body) when is_binary(body), do: Jason.decode(body)
  defp decode_json(body), do: {:ok, body}

  defp decode_body(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> decoded
      {:error, _} -> body
    end
  end

  defp decode_body(body), do: body

  defp req_options do
    Application.get_env(:secrethub_agent, :enrollment_req_options, [])
  end

  defp hostname do
    case :inet.gethostname() do
      {:ok, name} -> to_string(name)
      {:error, _} -> "unknown"
    end
  end

  defp fqdn, do: hostname()

  defp machine_id do
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
    |> Enum.find_value(fn path ->
      case File.read(path) do
        {:ok, value} -> String.trim(value)
        {:error, _} -> nil
      end
    end)
  end
end
