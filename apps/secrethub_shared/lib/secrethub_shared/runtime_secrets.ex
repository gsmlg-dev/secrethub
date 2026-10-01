defmodule SecretHub.Shared.RuntimeSecrets do
  @moduledoc "Runtime-only environment or file inputs with bounded, redacted errors."

  @max_bytes 4096

  def read!(name, opts \\ []) do
    case read(name, opts) do
      {:ok, value} -> value
      {:error, reason} -> raise ArgumentError, "#{name}: #{reason}"
    end
  end

  def read(name, opts \\ []) do
    get_env = Keyword.get(opts, :get_env, &System.get_env/1)

    case {get_env.(name), get_env.(name <> "_FILE")} do
      {nil, nil} ->
        if Keyword.get(opts, :required, true), do: {:error, :missing}, else: {:ok, nil}

      {value, nil} ->
        validate(value)

      {nil, path} ->
        read_file(path)

      {_, _} ->
        {:error, :conflicting_sources}
    end
  end

  defp read_file(path) do
    if String.starts_with?(Path.expand(path), "/nix/store/") do
      {:error, :immutable_secret_source}
    else
      with {:ok, %{type: :regular, size: size}} when size <= @max_bytes <- File.stat(path),
           {:ok, value} <- File.read(path) do
        value |> String.trim_trailing("\n") |> String.trim_trailing("\r") |> validate()
      else
        _ -> {:error, :invalid_file}
      end
    end
  end

  defp validate(""), do: {:error, :empty}
  defp validate(value) when byte_size(value) > @max_bytes, do: {:error, :too_large}
  defp validate(value), do: {:ok, value}
end
