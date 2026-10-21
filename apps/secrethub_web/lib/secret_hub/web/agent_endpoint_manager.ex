defmodule SecretHub.Web.AgentEndpointManager do
  @moduledoc """
  Ensures the configured runtime or local-development trusted Agent endpoint is available.
  """

  require Logger

  alias SecretHub.Core.PKI.Issuer

  @cert_dir Path.join([System.tmp_dir!(), "secrethub", "agent_endpoint"])

  def ensure_started do
    config = Application.get_env(:secrethub_web, SecretHub.Web.AgentEndpoint, [])

    cond do
      config[:server] && (not dev_mode?() or not generated_dev_tls?(config)) ->
        with :ok <- validate_explicit_tls(config), do: start_endpoint()

      dev_mode?() ->
        ensure_dev_endpoint()

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
         :ok <- restart_stale_endpoint(changed?) do
      start_endpoint()
    end
  end

  defp write_dev_certificate(host) do
    File.mkdir_p!(@cert_dir)

    fingerprint_path = Path.join(@cert_dir, "ca-fingerprint")
    host_path = Path.join(@cert_dir, "server-host")
    cert_path = Path.join(@cert_dir, "server-cert.pem")
    key_path = Path.join(@cert_dir, "server-key.pem")
    ca_path = Path.join(@cert_dir, "ca-cert.pem")

    with {:ok, material} <-
           Issuer.issue_server_certificate(host, [
             host,
             "localhost"
           ]) do
      current_fingerprint =
        if File.exists?(fingerprint_path), do: File.read!(fingerprint_path), else: nil

      current_host = if File.exists?(host_path), do: File.read!(host_path), else: nil

      changed? =
        current_fingerprint != material.ca_fingerprint or current_host != host or
          Enum.any?([cert_path, key_path, ca_path], &(not File.exists?(&1)))

      if changed? do
        File.write!(cert_path, material.certificate_pem)
        File.write!(key_path, material.private_key_pem)
        File.write!(ca_path, material.ca_certificate_pem)
        File.write!(fingerprint_path, material.ca_fingerprint)
        File.write!(host_path, host)
      end

      {:ok, %{certfile: cert_path, keyfile: key_path, cacertfile: ca_path}, changed?}
    end
  end

  defp configure_endpoint(host, port, paths) do
    config =
      Application.get_env(:secrethub_web, SecretHub.Web.AgentEndpoint, [])
      |> Keyword.merge(
        # TODO(upstream): gsmlg-dev/gaoxy#5 - verified client certificates block adapter replacement.
        adapter: Bandit.PhoenixAdapter,
        server: true,
        http: false,
        dev_generated_tls_paths: paths,
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
              fail_if_no_peer_cert: false,
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

  defp generated_dev_tls?(config) do
    case config[:dev_generated_tls_paths] do
      nil -> false
      paths -> paths == tls_paths(config)
    end
  end

  defp tls_paths(config) do
    https = config[:https] || []
    transport = get_in(https, [:thousand_island_options, :transport_options]) || []

    %{
      certfile: https[:certfile],
      keyfile: https[:keyfile],
      cacertfile: normalize_path(transport[:cacertfile])
    }
  end

  defp validate_explicit_tls(config) do
    paths = tls_paths(config)
    transport = get_in(config[:https] || [], [:thousand_island_options, :transport_options]) || []

    cond do
      Enum.any?(Map.values(paths), &(not readable_file?(&1))) ->
        {:error, {:invalid_agent_endpoint_tls, :incomplete_tls_material}}

      config[:http] not in [nil, false] ->
        {:error, {:invalid_agent_endpoint_tls, :plaintext_listener_enabled}}

      transport[:verify] != :verify_peer or transport[:fail_if_no_peer_cert] != false or
          Keyword.has_key?(transport, :verify_fun) ->
        {:error, {:invalid_agent_endpoint_tls, :invalid_client_verification}}

      true ->
        :ok
    end
  end

  defp normalize_path(path) when is_list(path), do: List.to_string(path)
  defp normalize_path(path), do: path

  defp readable_file?(path) when is_binary(path) or is_list(path) do
    case File.open(path, [:read]) do
      {:ok, file} ->
        File.close(file)
        true

      {:error, _reason} ->
        false
    end
  end

  defp readable_file?(_), do: false

  defp dev_mode? do
    Application.get_env(:secrethub_web, :dev_mode, false)
  end
end
