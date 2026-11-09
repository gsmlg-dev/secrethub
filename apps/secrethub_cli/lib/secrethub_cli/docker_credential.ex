defmodule SecretHub.CLI.DockerCredential do
  @moduledoc """
  `docker-credential-secrethub`: docker-credential-helpers protocol.

  `run/3` returns `{stdout, exit_status, diagnostics}`. Protocol-defined
  errors are written to stdout, as the Docker client reads them from there;
  unrelated diagnostics go to stderr. A genuine miss is the exact message
  `credentials not found in native keychain`.

  Registry keys use a Docker-specific resolver: a finite Docker Hub alias table
  and `host[:port]` for other registries. It is never applied to Git.
  """
  alias SecretHub.CLI.AgentClient

  @not_found "credentials not found in native keychain"
  @docker_hub "https://index.docker.io/v1/"
  @hub_hosts ~w(docker.io index.docker.io registry-1.docker.io registry.hub.docker.com)
  @max_pages 100

  def not_found_message, do: @not_found
  def docker_hub_key, do: @docker_hub

  def run(operation, input, opts \\ []) do
    client = Keyword.get(opts, :client, &AgentClient.credential/3)
    handle(operation, input, client, opts)
  end

  defp handle("store", input, client, opts) do
    with {:ok, %{"ServerURL" => url, "Username" => username, "Secret" => secret}}
         when is_binary(url) and is_binary(username) and is_binary(secret) <- Jason.decode(input),
         {:ok, key} <- registry_key(url) do
      params = %{
        "namespace" => "docker",
        "service" => key,
        "username" => username,
        "value" => secret
      }

      case client.("credential_put", params, opts) do
        {:ok, _} -> {"", 0, []}
        {:error, code} -> error("credential store failed: #{code}")
      end
    else
      {:error, message} when is_binary(message) -> error(message)
      _ -> error("invalid credentials payload")
    end
  end

  defp handle("get", input, client, opts) do
    with {:ok, url} <- server_url(input),
         {:ok, key} <- registry_key(url) do
      case client.("credential_get", %{"namespace" => "docker", "service" => key}, opts) do
        {:ok, %{"username" => username, "value" => secret}} ->
          json = Jason.encode!(%{"ServerURL" => url, "Username" => username, "Secret" => secret})
          {json <> "\n", 0, []}

        {:error, "NOT_FOUND"} ->
          {@not_found <> "\n", 1, []}

        {:error, code} ->
          error("credential lookup failed: #{code}")

        _ ->
          error("credential lookup failed: invalid Agent response")
      end
    else
      {:error, message} -> error(message)
    end
  end

  defp handle("erase", input, client, opts) do
    with {:ok, url} <- server_url(input),
         {:ok, key} <- registry_key(url) do
      case client.("credential_delete", %{"namespace" => "docker", "service" => key}, opts) do
        {:ok, %{"status" => "absent"}} -> {@not_found <> "\n", 1, []}
        {:ok, _} -> {"", 0, []}
        {:error, code} -> error("credential erase failed: #{code}")
      end
    else
      {:error, message} -> error(message)
    end
  end

  defp handle("list", _input, client, opts) do
    case list_pages(client, opts, nil, %{}, @max_pages) do
      {:ok, entries} -> {Jason.encode!(entries) <> "\n", 0, []}
      {:error, code} -> error("credential list failed: #{code}")
    end
  end

  defp handle(operation, _input, _client, _opts),
    do: {"", 1, ["secrethub: unknown docker credential operation #{inspect(operation)}"]}

  defp list_pages(_client, _opts, _cursor, _acc, 0), do: {:error, "TOO_MANY_PAGES"}

  defp list_pages(client, opts, cursor, acc, remaining) do
    params =
      %{"namespace" => "docker", "limit" => 100}
      |> then(&if(cursor, do: Map.put(&1, "cursor", cursor), else: &1))

    case client.("credential_list", params, opts) do
      {:ok, %{"entries" => entries} = page} when is_list(entries) ->
        acc =
          Enum.reduce(entries, acc, fn entry, acc ->
            Map.put(acc, entry["service"], entry["username"] || "")
          end)

        case page["next_cursor"] do
          next when is_binary(next) -> list_pages(client, opts, next, acc, remaining - 1)
          _ -> {:ok, acc}
        end

      {:error, code} ->
        {:error, code}

      _ ->
        {:error, "invalid Agent response"}
    end
  end

  defp server_url(input) when is_binary(input) do
    case String.trim(input) do
      "" -> {:error, "no credentials server URL"}
      url -> {:ok, url}
    end
  end

  @doc """
  Normalizes a registry address into its credential key. Docker Hub aliases
  map to `#{@docker_hub}`; other registries to lowercase `host[:port]`.
  """
  def registry_key(url) when is_binary(url) and byte_size(url) <= 255 do
    {host_part, path} = url |> strip_scheme() |> split_path()
    host_part = String.downcase(host_part)

    cond do
      host_part in @hub_hosts and path in ["", "/", "/v1", "/v1/", "/v2", "/v2/"] ->
        {:ok, @docker_hub}

      path not in ["", "/"] ->
        {:error, "unsupported registry path in #{inspect(url)}"}

      Regex.match?(
        ~r/\A(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?\z/,
        host_part
      ) ->
        {:ok, host_part}

      true ->
        {:error, "invalid registry address"}
    end
  end

  def registry_key(_), do: {:error, "invalid registry address"}

  defp strip_scheme("https://" <> rest), do: rest
  defp strip_scheme("http://" <> rest), do: rest
  defp strip_scheme(other), do: other

  defp split_path(value) do
    case String.split(value, "/", parts: 2) do
      [host] -> {host, ""}
      [host, rest] -> {host, "/" <> rest}
    end
  end

  defp error(message), do: {message <> "\n", 1, []}
end
