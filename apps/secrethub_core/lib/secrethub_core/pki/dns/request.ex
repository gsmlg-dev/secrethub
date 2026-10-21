defmodule SecretHub.Core.PKI.DNS.Request do
  @moduledoc false
  alias SecretHub.Core.PKI.HTTP

  def request(method, url, headers, body, opts) do
    case HTTP.request(method, url, headers, body, opts) do
      {:ok, %{status: status} = response} when status in 200..299 ->
        {:ok, response}

      {:ok, %{status: status}} when status in [401, 403] ->
        {:error, %{reason: :authentication, status: status}}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: 429, headers: headers}} ->
        {:error, %{reason: :throttled, retry_after: first_header(headers, "retry-after")}}

      {:ok, %{status: status}} when status in 400..499 ->
        {:error, %{reason: :provider_rejected, status: status}}

      {:ok, %{status: status}} ->
        {:error, %{reason: :provider_unavailable, status: status}}

      {:error, _} ->
        {:error, :transport_unavailable}
    end
  end

  def first_header(headers, name) do
    case Map.get(headers, name, []) do
      [value | _] -> value
      value when is_binary(value) -> value
      _ -> nil
    end
  end
end
