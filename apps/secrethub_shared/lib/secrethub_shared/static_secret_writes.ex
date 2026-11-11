defmodule SecretHub.Shared.StaticSecretWrites do
  @moduledoc """
  Bounded wire contract for Agent-scoped static secret writes (`secret_write_v1`).

  A local process that can reach the Agent's owner-only socket publishes a
  static secret at a Core path on behalf of that Agent. Core authorizes each
  request with the dedicated `secret_write`/`secret_delete` policy operations;
  the generic `write`/`delete` operations used by older policies never apply.
  """

  @capability "secret_write_v1"
  @operations %{"secret_put" => "secret_write", "secret_delete" => "secret_delete"}
  @path ~r/\A[a-z0-9\-]+(\.[a-z0-9\-]+)*\z/
  @field ~r/\A[A-Za-z0-9_.\-]{1,128}\z/
  @reserved_prefix "host-credentials."
  @max_path 500
  @max_fields 64
  @max_data_bytes 65_536
  @max_description 500

  def capability, do: @capability
  def actions, do: Map.keys(@operations)

  @doc "Maps a local action to its policy operation."
  def operation(action) when is_map_key(@operations, action), do: {:ok, @operations[action]}
  def operation(_), do: :error

  @doc "Paths reserved for other subsystems cannot be written through this contract."
  def reserved_path?(path) when is_binary(path), do: String.starts_with?(path, @reserved_prefix)

  @doc """
  Validates a request. `secret_put` takes `path`, `data` (a map of string
  fields to string values), and optional `expected_version` and
  `description`; `secret_delete` takes `path` and optional `expected_version`.
  """
  def validate(action, params) when is_map(params) do
    with {:ok, _} <- operation(action),
         :ok <- only(params, allowed(action)),
         {:ok, path} <- path(params["path"]),
         {:ok, expected} <- expected_version(params["expected_version"]),
         {:ok, request} <- body(action, params) do
      {:ok, Map.merge(request, %{"path" => path, "expected_version" => expected})}
    else
      _ -> {:error, :invalid_request}
    end
  end

  def validate(_, _), do: {:error, :invalid_request}

  defp allowed("secret_put"), do: ~w(path data expected_version description)
  defp allowed("secret_delete"), do: ~w(path expected_version)

  defp only(params, allowed),
    do: if(Enum.all?(Map.keys(params), &(&1 in allowed)), do: :ok, else: :error)

  defp path(path) when is_binary(path) and byte_size(path) <= @max_path do
    if Regex.match?(@path, path) and not reserved_path?(path), do: {:ok, path}, else: :error
  end

  defp path(_), do: :error

  defp expected_version(nil), do: {:ok, nil}
  defp expected_version(v) when is_integer(v) and v > 0, do: {:ok, v}
  defp expected_version(_), do: :error

  defp body("secret_delete", _params), do: {:ok, %{}}

  defp body("secret_put", %{"data" => data} = params)
       when is_map(data) and map_size(data) in 1..@max_fields do
    with true <- Enum.all?(data, &valid_field?/1),
         true <- byte_size(Jason.encode!(data)) <= @max_data_bytes,
         {:ok, description} <- description(params["description"]) do
      {:ok, %{"data" => data, "description" => description}}
    else
      _ -> :error
    end
  end

  defp body(_, _), do: :error

  defp valid_field?({key, value}) when is_binary(key) and is_binary(value),
    do: Regex.match?(@field, key) and String.valid?(value)

  defp valid_field?(_), do: false

  defp description(nil), do: {:ok, nil}

  defp description(text) when is_binary(text) and byte_size(text) <= @max_description,
    do: if(String.valid?(text), do: {:ok, text}, else: :error)

  defp description(_), do: :error
end
