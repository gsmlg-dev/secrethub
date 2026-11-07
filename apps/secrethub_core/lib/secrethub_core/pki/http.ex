defmodule SecretHub.Core.PKI.HTTP do
  @moduledoc "Bounded, explicitly trusted HTTPS transport for public PKI integrations."

  alias SecretHub.Core.PKI.TrustStores

  @max_body_bytes 2_097_152

  def request(method, url, headers, body, opts \\ []) do
    with :ok <- validate_url(url, opts),
         {:ok, response} <- transport(method, url, headers, body, opts) do
      normalize(response, Keyword.get(opts, :max_body_bytes, @max_body_bytes))
    end
  rescue
    _ -> {:error, :transport_failure}
  catch
    _, _ -> {:error, :transport_failure}
  end

  defp validate_url(url, opts) when is_binary(url) do
    uri = URI.parse(url)

    cond do
      is_nil(uri.host) or uri.userinfo != nil or uri.fragment != nil ->
        {:error, :invalid_url}

      uri.scheme == "https" ->
        :ok

      uri.scheme == "http" and Keyword.get(opts, :test_mode, false) and
          uri.host in ["localhost", "127.0.0.1", "::1"] ->
        :ok

      true ->
        {:error, :https_required}
    end
  end

  defp validate_url(_, _), do: {:error, :invalid_url}

  defp transport(method, url, headers, body, opts) do
    case Keyword.get(opts, :transport) do
      fun when is_function(fun, 5) -> fun.(method, url, headers, body, opts)
      nil -> real_request(method, url, headers, body, opts)
    end
  end

  defp real_request(method, url, headers, body, opts) do
    with {:ok, cacerts} <- public_roots(opts) do
      limit = Keyword.get(opts, :max_body_bytes, @max_body_bytes)
      host = URI.parse(url).host

      ssl = [
        verify: :verify_peer,
        cacerts: cacerts,
        server_name_indication: String.to_charlist(host),
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]

      timeout = min(Keyword.get(opts, :receive_timeout, 15_000), 60_000)
      deadline = System.monotonic_time(:millisecond) + timeout
      {:ok, controller} = HTTP.AbortController.start_link()

      try do
        case url
             |> HTTP.fetch(
               method: method,
               headers: headers,
               body: body,
               redirect: :manual,
               decode_body: false,
               stream_response: true,
               timeout: timeout,
               connect_timeout: 5_000,
               ssl: ssl,
               signal: controller
             )
             |> HTTP.Promise.await(timeout + 1_000) do
          %HTTP.Response{} = response ->
            with {:ok, body} <- read_body(response.body, limit, deadline) do
              {:ok,
               %{
                 status: response.status,
                 headers: HTTP.Headers.to_list(response.headers),
                 body: body
               }}
            end

          {:error, reason} ->
            {:error, reason}
        end
      after
        HTTP.AbortController.abort(controller)
        GenServer.stop(controller)
      end
    end
  end

  defp read_body(body, limit, _) when is_binary(body) do
    if byte_size(body) <= limit, do: {:ok, body}, else: {:error, :response_too_large}
  end

  defp read_body(stream, limit, deadline) when is_pid(stream) do
    monitor = Process.monitor(stream)
    send(stream, {:read_chunk, self(), :ack})

    try do
      collect_body(stream, monitor, [], 0, limit, deadline)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp collect_body(stream, monitor, chunks, size, limit, deadline) do
    receive do
      {:stream_chunk, ^stream, chunk, ack} ->
        next_size = size + byte_size(chunk)

        if next_size > limit do
          {:error, :response_too_large}
        else
          send(stream, {:stream_chunk_ack, ack})
          collect_body(stream, monitor, [chunk | chunks], next_size, limit, deadline)
        end

      {:stream_end, ^stream} ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {:stream_error, ^stream, reason} ->
        {:error, reason}

      {:DOWN, ^monitor, :process, ^stream, reason} ->
        {:error, {:stream_closed, reason}}
    after
      max(deadline - System.monotonic_time(:millisecond), 0) -> {:error, :timeout}
    end
  end

  defp public_roots(opts) do
    case Keyword.get(opts, :test_cacerts) do
      nil ->
        TrustStores.cacerts("mozilla_webpki")

      roots when is_list(roots) ->
        if Keyword.get(opts, :test_mode, false),
          do: {:ok, roots},
          else: {:error, :test_trust_forbidden}
    end
  end

  defp normalize(%{body: :response_too_large}, _), do: {:error, :response_too_large}

  defp normalize(%{status: status, headers: headers, body: body}, limit)
       when is_integer(status) and is_binary(body) do
    if byte_size(body) <= limit do
      normalized_headers =
        Enum.reduce(headers, %{}, fn {key, values}, acc ->
          key = key |> to_string() |> String.downcase()
          Map.update(acc, key, List.wrap(values), &(&1 ++ List.wrap(values)))
        end)

      {:ok, %{status: status, headers: normalized_headers, body: body}}
    else
      {:error, :response_too_large}
    end
  end

  defp normalize(_, _), do: {:error, :invalid_transport_response}
end
