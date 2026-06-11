defmodule SecretHub.Web.AgentEndpointManager do
  @moduledoc """
  Ensures the trusted Agent endpoint is available for local development.
  """

  require Logger

  @cert_dir Path.join([System.tmp_dir!(), "secrethub", "agent_endpoint"])

  def ensure_started do
    cond do
      dev_mode?() ->
        ensure_dev_endpoint()

      configured_for_runtime?() ->
        start_endpoint()

      true ->
        {:error, :trusted_endpoint_not_started}
    end
  end

  defp ensure_dev_endpoint do
    endpoint = Application.get_env(:secrethub_web, :agent_trusted_endpoint)
    uri = URI.parse(endpoint)
    host = uri.host || "localhost"
    port = uri.port || 4665

    with {:ok, paths, changed?} <- write_dev_certificate(host),
         :ok <- configure_endpoint(host, port, paths),
         :ok <- restart_stale_endpoint(changed?),
         :ok <- start_endpoint() do
      :ok
    end
  end

  defp write_dev_certificate(host) do
    File.mkdir_p!(@cert_dir)

    fingerprint_path = Path.join(@cert_dir, "ca-fingerprint")
    cert_path = Path.join(@cert_dir, "server-cert.pem")
    key_path = Path.join(@cert_dir, "server-key.pem")
    ca_path = Path.join(@cert_dir, "ca-cert.pem")

    with {:ok, material} <-
           SecretHub.Core.PKI.Issuer.issue_server_certificate(host, [
             host,
             "localhost"
           ]) do
      current_fingerprint =
        if File.exists?(fingerprint_path), do: File.read!(fingerprint_path), else: nil

      changed? =
        current_fingerprint != material.ca_fingerprint or
          Enum.any?([cert_path, key_path, ca_path], &(not File.exists?(&1)))

      if changed? do
        File.write!(cert_path, material.certificate_pem)
        File.write!(key_path, material.private_key_pem)
        File.write!(ca_path, material.ca_certificate_pem)
        File.write!(fingerprint_path, material.ca_fingerprint)
      end

      {:ok, %{certfile: cert_path, keyfile: key_path, cacertfile: ca_path}, changed?}
    end
  end

  defp configure_endpoint(host, port, paths) do
    config =
      SecretHub.Web.AgentEndpoint
      |> Application.get_env(:secrethub_web, [])
      |> Keyword.merge(
        adapter: Bandit.PhoenixAdapter,
        server: true,
        pubsub_server: SecretHub.Web.PubSub,
        url: [host: host, port: port],
        https: [
          # Bind IPv4 in dev: the Agent's Erlang websocket client resolves
          # "localhost" to 127.0.0.1, which an IPv6-only listener rejects.
          ip: {0, 0, 0, 0},
          port: port,
          cipher_suite: :strong,
          certfile: paths.certfile,
          keyfile: paths.keyfile,
          thousand_island_options: [
            transport_options: [
              cacertfile: to_charlist(paths.cacertfile),
              verify: :verify_peer,
              fail_if_no_peer_cert: true,
              versions: [:"tlsv1.2", :"tlsv1.3"]
            ]
          ]
        ]
      )

    Application.put_env(:secrethub_web, SecretHub.Web.AgentEndpoint, config)
    :ok
  end

  defp start_endpoint do
    case Supervisor.start_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint) do
      {:ok, _pid} ->
        Logger.info("Trusted Agent endpoint started")
        :ok

      {:error, {:already_started, _pid}} ->
        :ok

      {:error, :already_present} ->
        case Supervisor.restart_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint) do
          {:ok, _pid} -> :ok
          {:ok, _pid, _info} -> :ok
          {:error, {:already_started, _pid}} -> :ok
          {:error, reason} -> {:error, {:trusted_endpoint_start_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:trusted_endpoint_start_failed, reason}}
    end
  end

  defp restart_stale_endpoint(true) do
    if endpoint_running?() do
      Supervisor.terminate_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      Supervisor.delete_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
    end

    :ok
  end

  defp restart_stale_endpoint(false), do: :ok

  defp endpoint_running? do
    SecretHub.Web.AgentEndpoint
    |> Process.whereis()
    |> is_pid()
  end

  defp configured_for_runtime? do
    SecretHub.Web.AgentEndpoint
    |> Application.get_env(:secrethub_web, [])
    |> Keyword.get(:server, false)
  end

  defp dev_mode? do
    Application.get_env(:secrethub_web, :dev_mode, false)
  end
end
