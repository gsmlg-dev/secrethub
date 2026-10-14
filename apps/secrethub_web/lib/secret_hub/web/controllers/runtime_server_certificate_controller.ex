defmodule SecretHub.Web.RuntimeServerCertificateController do
  @moduledoc """
  Operator issuance and renewal of Agent runtime server material.

  Accessible only through the CSRF-protected management API behind Caddy mTLS.
  """

  use SecretHub.Web, :controller

  alias SecretHub.Core.Audit
  alias SecretHub.Core.PKI.Issuer
  alias SecretHub.Shared.Schemas.Certificate

  def create(conn, params) do
    conn =
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")

    with {:ok, host, names} <- server_names(params),
         {:ok, material} <- Issuer.issue_server_certificate(host, names),
         :ok <- audit_issuance(conn, host, names, material) do
      conn |> put_status(:created) |> json(%{data: material})
    else
      {:error, :invalid_server_names} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_server_names"})

      {:error, reason}
      when reason in [:no_active_ca, :ca_private_key_unavailable, :audit_unavailable] ->
        conn |> put_status(:service_unavailable) |> json(%{error: to_string(reason)})
    end
  end

  defp server_names(params) do
    host = Map.get(params, "advertised_host")
    names = Map.get(params, "subject_alt_names", [host])

    if valid_host?(host) and is_list(names) and length(names) in 1..32 and
         host in names and Enum.all?(names, &valid_host?/1) do
      {:ok, host, Enum.uniq(names)}
    else
      {:error, :invalid_server_names}
    end
  end

  defp valid_host?(host) when is_binary(host) and byte_size(host) in 1..253 do
    case :inet.parse_address(to_charlist(host)) do
      {:ok, _address} ->
        true

      {:error, _reason} ->
        not Regex.match?(~r/\A[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\z/, host) and
          host
          |> String.split(".")
          |> Enum.all?(&Regex.match?(~r/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/, &1))
    end
  end

  defp valid_host?(_host), do: false

  defp audit_issuance(conn, host, names, material) do
    {:ok, certificate} = Certificate.from_pem(material.certificate_pem)

    case Audit.log_event(%{
           event_type: "system.runtime_server_certificate_issued",
           actor_type: "admin",
           actor_id: "operator",
           source_ip: conn.remote_ip |> :inet.ntoa() |> to_string(),
           event_data: %{
             advertised_host: host,
             subject_alt_names: names,
             serial_number: certificate.serial_number,
             ca_fingerprint: material.ca_fingerprint
           }
         }) do
      {:ok, _audit} -> :ok
      {:error, _reason} -> {:error, :audit_unavailable}
    end
  end
end
