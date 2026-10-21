defmodule SecretHub.Core.PKI.ACME.Client do
  @moduledoc """
  Narrow ACME v2 wire adapter. The caller owns keys, URLs and durable effects.

  Mutating transport failures are ambiguous and are never automatically retried.
  Only a CA's explicit `badNonce` rejection permits a bounded signed retry.
  """

  alias SecretHub.Core.PKI.HTTP

  @directories %{
    "production" => "https://acme-v02.api.letsencrypt.org/directory",
    "staging" => "https://acme-staging-v02.api.letsencrypt.org/directory"
  }
  @required_endpoints ~w(newNonce newAccount newOrder revokeCert)
  @bad_nonce "urn:ietf:params:acme:error:badNonce"

  def directory_url(environment), do: Map.fetch(@directories, to_string(environment))

  def directory(url, opts \\ []) do
    with :ok <- directory_policy(url, opts),
         {:ok, response} <- HTTP.request(:get, url, [{"accept", "application/json"}], "", opts),
         {:ok, result} <- result(response, opts),
         true <- is_map(result.body),
         directory = Map.put(result.body, "_directory_url", url),
         :ok <- directory_endpoints(directory, opts) do
      {:ok, directory}
    else
      false -> {:error, :invalid_directory}
      {:error, _} = error -> error
    end
  end

  def register_account(directory, key_pem, contacts, terms_accepted, opts \\ [])
  def register_account(_, _, _, false, _), do: {:error, :terms_not_accepted}

  def register_account(directory, key_pem, contacts, true, opts) do
    signed(
      directory,
      %{key_pem: key_pem},
      directory["newAccount"],
      %{
        "contact" => contacts,
        "termsOfServiceAgreed" => true
      },
      opts
    )
  end

  def recover_account(directory, key_pem, opts \\ []) do
    signed(
      directory,
      %{key_pem: key_pem},
      directory["newAccount"],
      %{"onlyReturnExisting" => true},
      opts
    )
  end

  def new_order(directory, account, identifiers, opts \\ []) do
    payload = %{"identifiers" => Enum.map(identifiers, &%{"type" => "dns", "value" => &1})}
    payload = if opts[:replaces], do: Map.put(payload, "replaces", opts[:replaces]), else: payload
    signed(directory, account, directory["newOrder"], payload, opts)
  end

  def read_order(directory, account, url, opts \\ []),
    do: signed(directory, account, url, :post_as_get, opts)

  def authorization(directory, account, url, opts \\ []),
    do: signed(directory, account, url, :post_as_get, opts)

  def acknowledge(directory, account, url, opts \\ []),
    do: signed(directory, account, url, %{}, opts)

  def finalize(directory, account, url, csr_der, opts \\ []) do
    signed(directory, account, url, %{"csr" => Base.url_encode64(csr_der, padding: false)}, opts)
  end

  def download(directory, account, url, opts \\ []) do
    signed(directory, account, url, :post_as_get, Keyword.put(opts, :certificate_response, true))
  end

  def revoke(directory, account, certificate_der, reason \\ 0, opts \\ []) do
    if reason in [0, 1, 3, 4, 5] do
      signed(
        directory,
        account,
        directory["revokeCert"],
        %{
          "certificate" => Base.url_encode64(certificate_der, padding: false),
          "reason" => reason
        },
        opts
      )
    else
      {:error, :unsupported_revocation_reason}
    end
  end

  def renewal_info(directory, certificate_id, opts \\ []) do
    with base when is_binary(base) <- directory["renewalInfo"],
         true <- Regex.match?(~r/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, certificate_id),
         url = String.trim_trailing(base, "/") <> "/" <> certificate_id,
         :ok <- endpoint_policy(directory, url, opts),
         {:ok, response} <- HTTP.request(:get, url, [{"accept", "application/json"}], "", opts) do
      result(response, opts)
    else
      nil -> {:error, :ari_unavailable}
      false -> {:error, :invalid_certificate_id}
      {:error, _} = error -> error
    end
  end

  def dns_value(token, thumbprint) do
    :crypto.hash(:sha256, token <> "." <> thumbprint) |> Base.url_encode64(padding: false)
  end

  def retry_at(headers, now \\ DateTime.utc_now()) do
    case first_header(headers, "retry-after") do
      nil ->
        nil

      value ->
        case Integer.parse(value) do
          {seconds, ""} when seconds >= 0 -> DateTime.add(now, min(seconds, 604_800))
          _ -> http_date(value)
        end
    end
  end

  defp signed(directory, account, url, payload, opts) do
    with :ok <- endpoint_policy(directory, url, opts),
         :ok <- account_policy(directory, account, opts),
         :ok <- endpoint_policy(directory, directory["newNonce"], opts),
         {:ok, nonce} <- nonce(directory, opts) do
      signed_attempt(directory, account, url, payload, nonce, 2, opts)
    end
  rescue
    _ -> {:error, :invalid_account_key}
  end

  defp signed_attempt(directory, account, url, payload, nonce, retries, opts) do
    jwk = JOSE.JWK.from_pem(account.key_pem)
    {_module, public} = JOSE.JWK.to_public_map(jwk)
    algorithm = if public["kty"] == "RSA", do: "RS256", else: "ES256"
    protected = %{"alg" => algorithm, "nonce" => nonce, "url" => url}

    protected =
      if account[:kid],
        do: Map.put(protected, "kid", account.kid),
        else: Map.put(protected, "jwk", public)

    encoded_payload = if payload == :post_as_get, do: "", else: JSON.encode!(payload)
    {_module, envelope} = JOSE.JWS.sign(jwk, encoded_payload, protected)
    headers = [{"content-type", "application/jose+json"}, {"accept", accept(opts)}]

    case HTTP.request(:post, url, headers, JSON.encode!(envelope), opts) do
      {:ok, response} ->
        signed_response(response, directory, account, url, payload, retries, opts)

      {:error, reason} ->
        {:error, %{kind: :transport, reason: safe_reason(reason), uncertain: true}}
    end
  end

  defp signed_response(response, directory, account, url, payload, retries, opts) do
    case result(response, opts) do
      {:error, %{type: @bad_nonce}} when retries > 0 ->
        with {:ok, fresh} <- response_nonce(directory, response, opts) do
          signed_attempt(directory, account, url, payload, fresh, retries - 1, opts)
        end

      result ->
        result
    end
  end

  defp nonce(directory, opts) do
    with {:ok, %{status: status} = response} <-
           HTTP.request(:head, directory["newNonce"], [], "", opts),
         true <- status in [200, 204],
         nonce when is_binary(nonce) <- first_header(response.headers, "replay-nonce") do
      {:ok, nonce}
    else
      {:error, reason} ->
        {:error, %{kind: :transport, reason: safe_reason(reason), uncertain: false}}

      _ ->
        {:error, :nonce_unavailable}
    end
  end

  defp response_nonce(directory, response, opts) do
    case first_header(response.headers, "replay-nonce") do
      nonce when is_binary(nonce) -> {:ok, nonce}
      nil -> nonce(directory, opts)
    end
  end

  defp result(%{status: status, headers: headers, body: body}, opts) when status in 200..299 do
    case decode_body(body, opts) do
      {:ok, body} ->
        {:ok,
         %{
           status: status,
           headers: headers,
           body: body,
           location: first_header(headers, "location"),
           retry_at: retry_at(headers)
         }}

      {:error, _} = error ->
        error
    end
  end

  defp result(%{status: status, headers: headers, body: body}, opts) do
    {:error,
     %{
       kind: :acme,
       type: problem_type(decode_body(body, opts)),
       status: status,
       retry_at: retry_at(headers),
       uncertain: status >= 500
     }}
  end

  defp problem_type({:ok, %{"type" => type}}) when is_binary(type) do
    if String.starts_with?(type, "urn:ietf:params:acme:error:"),
      do: String.slice(type, 0, 120),
      else: "unknown"
  end

  defp problem_type(_), do: "unknown"

  defp decode_body("", _), do: {:ok, %{}}

  defp decode_body(body, opts) do
    if Keyword.get(opts, :certificate_response, false) and
         String.starts_with?(String.trim_leading(body), "-----BEGIN CERTIFICATE-----") do
      {:ok, body}
    else
      case JSON.decode(body) do
        {:ok, value} when is_map(value) -> {:ok, value}
        _ -> {:error, :invalid_acme_response}
      end
    end
  end

  defp directory_endpoints(directory, opts) do
    Enum.reduce_while(@required_endpoints, :ok, fn key, :ok ->
      case endpoint_policy(directory, directory[key], opts) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp account_policy(directory, %{kid: kid}, opts), do: endpoint_policy(directory, kid, opts)
  defp account_policy(_, %{key_pem: key}, _) when is_binary(key), do: :ok

  defp endpoint_policy(directory, url, opts) when is_binary(url) do
    directory_url = directory["_directory_url"]

    with :ok <- directory_policy(directory_url, opts) do
      base = URI.parse(directory_url)
      endpoint = URI.parse(url)

      if endpoint.scheme == base.scheme and endpoint.host == base.host and
           endpoint.port == base.port and
           endpoint.userinfo == nil and endpoint.fragment == nil do
        :ok
      else
        {:error, :untrusted_acme_url}
      end
    end
  end

  defp endpoint_policy(_, _, _), do: {:error, :untrusted_acme_url}

  defp directory_policy(url, opts) when is_binary(url) do
    uri = URI.parse(url)

    test_endpoint =
      Keyword.get(opts, :test_mode, false) and uri.host in ["localhost", "127.0.0.1", "::1"] and
        uri.scheme in ["http", "https"]

    if url in Map.values(@directories) or
         (test_endpoint and uri.userinfo == nil and uri.fragment == nil),
       do: :ok,
       else: {:error, :untrusted_acme_url}
  end

  defp directory_policy(_, _), do: {:error, :untrusted_acme_url}

  defp accept(opts),
    do:
      if(opts[:certificate_response],
        do: "application/pem-certificate-chain",
        else: "application/json"
      )

  defp first_header(headers, key), do: headers |> Map.get(key, []) |> List.wrap() |> List.first()
  defp safe_reason(reason) when is_atom(reason), do: reason
  defp safe_reason(%{reason: reason}) when is_atom(reason), do: reason
  defp safe_reason(_), do: :request_failed

  defp http_date(value) do
    case :httpd_util.convert_request_date(String.to_charlist(value)) do
      {{year, month, day}, {hour, minute, second}} ->
        DateTime.new!(Date.new!(year, month, day), Time.new!(hour, minute, second), "Etc/UTC")

      _ ->
        nil
    end
  rescue
    _ -> nil
  end
end
