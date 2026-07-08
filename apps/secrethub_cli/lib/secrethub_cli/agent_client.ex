defmodule SecretHub.CLI.AgentClient do
  @moduledoc """
  Client for the local SecretHub Agent Unix socket protocol.
  """

  @default_timeout 5_000

  @doc """
  Retrieves a secret from the local Agent.

  Required options:
    - `:socket_path` - Unix socket path for the local Agent
    - `:certificate_path` - PEM application certificate used for Agent auth
  """
  def get_secret(path, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    with {:ok, socket_path} <- required_option(opts, :socket_path, "agent socket path"),
         {:ok, certificate_path} <- required_option(opts, :certificate_path, "agent certificate"),
         {:ok, certificate_pem} <- read_certificate(certificate_path),
         {:ok, socket} <- connect(socket_path, timeout) do
      try do
        with :ok <- authenticate(socket, certificate_pem, timeout),
             {:ok, secret} <- request_secret(socket, path, timeout) do
          {:ok, normalize_secret(secret)}
        end
      after
        :gen_tcp.close(socket)
      end
    end
  end

  defp required_option(opts, key, name) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, "Missing required #{name}"}
    end
  end

  defp read_certificate(path) do
    case File.read(path) do
      {:ok, pem} -> {:ok, pem}
      {:error, reason} -> {:error, "Failed to read agent certificate: #{inspect(reason)}"}
    end
  end

  defp connect(socket_path, timeout) do
    case :gen_tcp.connect(
           {:local, String.to_charlist(socket_path)},
           0,
           [:binary, packet: :line, active: false],
           timeout
         ) do
      {:ok, socket} -> {:ok, socket}
      {:error, reason} -> {:error, "Failed to connect to agent socket: #{inspect(reason)}"}
    end
  end

  defp authenticate(socket, certificate_pem, timeout) do
    request_id = request_id()

    request = %{
      request_id: request_id,
      action: "authenticate",
      params: %{certificate: certificate_pem}
    }

    with :ok <- send_request(socket, request),
         {:ok, _data} <- receive_ok(socket, request_id, timeout) do
      :ok
    end
  end

  defp request_secret(socket, path, timeout) do
    request_id = request_id()

    request = %{
      request_id: request_id,
      action: "get_secret",
      params: %{path: path}
    }

    with :ok <- send_request(socket, request),
         {:ok, data} <- receive_ok(socket, request_id, timeout) do
      {:ok, data}
    end
  end

  defp send_request(socket, request) do
    case Jason.encode(request) do
      {:ok, json} -> :gen_tcp.send(socket, json <> "\n")
      {:error, reason} -> {:error, "Failed to encode agent request: #{inspect(reason)}"}
    end
  end

  defp receive_ok(socket, request_id, timeout) do
    with {:ok, line} <- receive_line(socket, timeout),
         {:ok, response} <- decode_response(line),
         :ok <- match_request_id(response, request_id) do
      case response do
        %{"status" => "ok", "data" => data} ->
          {:ok, data}

        %{"status" => "error", "error" => %{"message" => message}} ->
          {:error, message}

        %{"status" => "error", "error" => error} ->
          {:error, inspect(error)}

        other ->
          {:error, "Unexpected agent response: #{inspect(other)}"}
      end
    end
  end

  defp receive_line(socket, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, line} -> {:ok, line}
      {:error, reason} -> {:error, "Agent socket read failed: #{inspect(reason)}"}
    end
  end

  defp decode_response(line) do
    case Jason.decode(line) do
      {:ok, response} -> {:ok, response}
      {:error, reason} -> {:error, "Invalid agent response JSON: #{inspect(reason)}"}
    end
  end

  defp match_request_id(%{"request_id" => request_id}, request_id), do: :ok

  defp match_request_id(%{"request_id" => other}, _request_id),
    do: {:error, "Mismatched agent response: #{other}"}

  defp match_request_id(_response, _request_id), do: {:error, "Agent response missing request_id"}

  defp normalize_secret(%{"data" => data}) when is_map(data), do: data
  defp normalize_secret(%{"value" => value}) when is_map(value), do: value
  defp normalize_secret(%{"value" => value}), do: %{"value" => value}
  defp normalize_secret(secret) when is_map(secret), do: secret

  defp request_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end
end
