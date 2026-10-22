defmodule SecretHub.Core.PKI.ACME.Renewal do
  @moduledoc "RFC 9773 renewal identifiers/windows and actual-lifetime fallback."

  alias SecretHub.Core.PKI.ACME.Client

  def certificate_id(certificate) when is_binary(certificate) do
    certificate = X509.Certificate.from_der!(certificate)
    certificate_id(certificate)
  rescue
    _ -> {:error, :invalid_certificate}
  end

  def certificate_id(certificate) do
    case X509.Certificate.extension(certificate, :authority_key_identifier) do
      {:Extension, _, _, {:AuthorityKeyIdentifier, key_id, _, _}} when is_binary(key_id) ->
        serial = certificate |> X509.Certificate.serial() |> :binary.encode_unsigned()

        {:ok,
         Base.url_encode64(key_id, padding: false) <>
           "." <> Base.url_encode64(serial, padding: false)}

      _ ->
        {:error, :authority_key_identifier_unavailable}
    end
  end

  def fallback(%DateTime{} = not_before, %DateTime{} = not_after, opts \\ []) do
    lifetime = DateTime.diff(not_after, not_before)
    fraction = if lifetime < 10 * 86_400, do: 0.5, else: 2 / 3
    jitter = Keyword.get_lazy(opts, :jitter, &:rand.uniform/0)
    # Centered 4% lifetime jitter; never beyond the expiry safety margin.
    seconds = round(lifetime * (fraction + (jitter - 0.5) * 0.04))
    safety = max(1, min(86_400, div(lifetime, 10)))
    DateTime.add(not_before, min(max(seconds, 1), max(1, lifetime - safety)))
  end

  def window(body, headers, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)
    jitter = Keyword.get_lazy(opts, :jitter, &:rand.uniform/0)

    with %{"suggestedWindow" => %{"start" => start, "end" => finish}} <- body,
         {:ok, start, _} <- DateTime.from_iso8601(start),
         {:ok, finish, _} <- DateTime.from_iso8601(finish),
         true <- DateTime.compare(start, finish) == :lt,
         true <- DateTime.compare(finish, now) == :gt,
         true <- is_number(jitter) and jitter >= 0 and jitter <= 1 do
      seconds = DateTime.diff(finish, start)
      chosen = DateTime.add(start, min(trunc(seconds * jitter), max(0, seconds - 1)))
      renew_at = if DateTime.compare(chosen, now) == :lt, do: now, else: chosen
      refresh_at = Client.retry_at(headers, now) || DateTime.add(now, 6 * 3600)

      refresh_at =
        if DateTime.compare(refresh_at, now) == :gt, do: refresh_at, else: DateTime.add(now, 60)

      {:ok,
       %{window_start: start, window_end: finish, renew_at: renew_at, refresh_at: refresh_at}}
    else
      _ -> {:error, :invalid_renewal_window}
    end
  end
end
