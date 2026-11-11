defmodule SecretHub.SDK do
  @moduledoc """
  Publish and read SecretHub static secrets through the local SecretHub Agent.

  Every call opens the Agent's owner-only Unix socket, sends one request and
  closes it. The Agent acts with its own Core-issued identity: Core authorizes
  each call against the Agent's policies (`secret_write` / `secret_delete` to
  publish, `read` to read) and audits it. The SDK holds no credentials of its
  own; access to the socket is the local trust boundary.

      path = SecretHub.SDK.path(["backplane", "llm", "OpenAI_Main"])
      #=> "backplane.llm.openai-main"

      {:ok, %{status: :created, version: 1}} =
        SecretHub.SDK.put_secret(path, %{"api_key" => key})

      {:ok, %{data: %{"api_key" => ^key}}} = SecretHub.SDK.get_secret(path)

      {:ok, %{status: :deleted}} = SecretHub.SDK.delete_secret(path)

  ## Options

    * `:socket_path` - Agent socket; defaults to `$SECRET_HUB_AGENT_SOCKET_PATH`
      or `/var/run/secrethub/agent.sock`.
    * `:timeout` - milliseconds to wait for the Agent (default 15 000; writes
      include a live Core decision).

  Errors are `{:error, %SecretHub.SDK.Error{}}`; see that module for codes.
  Secret values are never included in errors.
  """

  alias SecretHub.SDK.{Client, Error}

  @type data :: %{optional(String.t()) => String.t()}
  @type write_status :: :created | :updated | :unchanged
  @type delete_status :: :deleted | :absent

  @doc """
  Publishes `data` (string field names to string values) at `path`.

  Republishing identical data returns `:unchanged` without a new version.

  Extra options:

    * `:expected_version` - only write if the current version matches; use
      when another publisher may write the same path. A missing secret never
      matches.
    * `:description` - description recorded when the secret is created.
  """
  @spec put_secret(String.t(), data(), keyword()) ::
          {:ok, %{status: write_status(), path: String.t(), version: pos_integer()}}
          | {:error, Error.t()}
  def put_secret(path, data, opts \\ []) when is_binary(path) and is_map(data) do
    params =
      %{"path" => path, "data" => data}
      |> put_opt("expected_version", opts[:expected_version])
      |> put_opt("description", opts[:description])

    with {:ok, response} <- Client.request("secret_put", params, opts) do
      {:ok,
       %{status: status(response["status"]), path: response["path"], version: response["version"]}}
    end
  end

  @doc """
  Deletes the secret at `path`. Deleting a missing secret returns `:absent`.
  Accepts `:expected_version`.
  """
  @spec delete_secret(String.t(), keyword()) ::
          {:ok, %{status: delete_status()}} | {:error, Error.t()}
  def delete_secret(path, opts \\ []) when is_binary(path) do
    params = put_opt(%{"path" => path}, "expected_version", opts[:expected_version])

    with {:ok, response} <- Client.request("secret_delete", params, opts) do
      {:ok, %{status: status(response["status"])}}
    end
  end

  @doc """
  Reads the secret at `path` with the Agent's own read grant. Text secrets are
  returned as `%{"value" => text}`.
  """
  @spec get_secret(String.t(), keyword()) ::
          {:ok, %{data: map(), version: pos_integer() | nil}} | {:error, Error.t()}
  def get_secret(path, opts \\ []) when is_binary(path) do
    with {:ok, response} <- Client.request("get_secret", %{"path" => path}, opts) do
      data =
        case response["value"] do
          value when is_map(value) -> value
          value -> %{"value" => value}
        end

      {:ok, %{data: data, version: response["version"]}}
    end
  end

  @doc """
  Builds a SecretHub path from segments.

  Each segment is lowercased; runs of characters other than `a-z`, `0-9` and
  `-` become a single `-`, and leading/trailing `-` are removed. Distinct
  names can normalize to the same segment (`"My_Key"` and `"my-key"`), so
  callers that need distinct paths should keep their names distinct after
  normalization. Raises `ArgumentError` if a segment normalizes to empty.
  """
  @spec path([String.t() | atom()]) :: String.t()
  def path(segments) when is_list(segments) and segments != [] do
    Enum.map_join(segments, ".", fn segment ->
      normalized =
        segment
        |> to_string()
        |> String.downcase()
        |> String.replace(~r/[^a-z0-9-]+/, "-")
        |> String.trim("-")

      if normalized == "",
        do: raise(ArgumentError, "path segment #{inspect(segment)} is empty after normalization"),
        else: normalized
    end)
  end

  defp put_opt(params, _key, nil), do: params
  defp put_opt(params, key, value), do: Map.put(params, key, value)

  @statuses %{
    "created" => :created,
    "updated" => :updated,
    "unchanged" => :unchanged,
    "deleted" => :deleted,
    "absent" => :absent
  }

  defp status(value), do: Map.get(@statuses, value, :unknown)
end
