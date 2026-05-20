defmodule SecretHub.Agent.Enrollment do
  @moduledoc """
  Pending HTTPS enrollment client for SecretHub Agent.

  This workflow uses an existing SSH host key to create the CSR and stores only
  Core-issued certificate material plus temporary pending state.
  """

  require Logger

  alias SecretHub.Agent.HostKey

  @default_poll_interval_ms 2_500
  @default_timeout_ms 300_000

  def enroll(opts) do
    core_url = Keyword.fetch!(opts, :core_url)
    storage_dir = Keyword.get(opts, :storage_dir, "priv/cert")

    with {:ok, host_key} <- host_key(opts),
         {:ok, pending} <- create_pending(core_url, host_key, opts),
         :ok <- notify_pending(pending, opts),
         {:ok, approved} <- wait_for_approval(core_url, pending, opts),
         {:ok, csr_pem} <- HostKey.csr_pem(host_key, approved["required_csr_fields"]),
         {:ok, issued} <- submit_csr(core_url, pending, csr_pem),
         {:ok, connect_info} <- connect_info(core_url, pending),
         :ok <- store_material(storage_dir, pending, issued, connect_info, host_key) do
      {:ok,
       %{
         agent_id: issued["agent_id"] || approved["agent_id"],
         pending: pending,
         host_key: host_key,
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

  def submit_csr(core_url, pending, csr_pem) do
    core_url
    |> endpoint_url("/v1/agent/enrollments/#{pending["enrollment_id"]}/csr")
    |> post_json(%{"csr_pem" => csr_pem}, bearer_headers(pending))
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
      "capabilities" => Keyword.get(opts, :capabilities, %{})
    }
  end

  def store_material(storage_dir, pending, issued, connect_info, host_key \\ nil) do
    with :ok <- File.mkdir_p(storage_dir),
         :ok <- File.write(Path.join(storage_dir, "agent-cert.pem"), issued["certificate_pem"]),
         :ok <- write_agent_key(storage_dir, host_key),
         :ok <- File.write(Path.join(storage_dir, "ca-chain.pem"), issued["ca_chain_pem"] || ""),
         :ok <-
           File.write(Path.join(storage_dir, "connect-info.json"), Jason.encode!(connect_info)),
         :ok <- File.write(Path.join(storage_dir, "pending.json"), Jason.encode!(pending)) do
      :ok
    end
  end

  defp write_agent_key(_storage_dir, nil), do: :ok

  defp write_agent_key(storage_dir, %HostKey{private_key_pem: private_key_pem})
       when is_binary(private_key_pem) do
    File.write(Path.join(storage_dir, "agent-key.pem"), private_key_pem)
  end

  defp write_agent_key(_storage_dir, %HostKey{}), do: {:error, :missing_tls_private_key_pem}

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

  defp endpoint_url(base_url, path) do
    base_url
    |> URI.parse()
    |> Map.put(:path, path)
    |> Map.put(:query, nil)
    |> URI.to_string()
  end

  defp post_json(url, payload, headers) do
    headers = [{"content-type", "application/json"} | headers]

    case Req.post(url, body: Jason.encode!(payload), headers: headers) do
      {:ok, %Req.Response{status: code, body: body}} when code in 200..299 ->
        decode_json(body)

      {:ok, %Req.Response{status: code, body: body}} ->
        {:error, {:http_error, code, decode_body(body)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_json(url, headers) do
    case Req.get(url, headers: headers) do
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
