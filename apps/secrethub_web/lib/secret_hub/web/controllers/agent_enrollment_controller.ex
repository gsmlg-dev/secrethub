defmodule SecretHub.Web.AgentEnrollmentController do
  use SecretHub.Web, :controller

  alias SecretHub.Core.Agents.Enrollment

  def create(conn, params) do
    source_ip = conn.remote_ip |> :inet.ntoa() |> to_string()

    case Enrollment.create_pending(params, source_ip) do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} ->
        conn
        |> put_status(:created)
        |> json(%{
          enrollment_id: enrollment.id,
          pending_token: pending_token,
          status: :pending,
          status_url: "/v1/agent/enrollments/#{enrollment.id}/status",
          poll_interval_ms: 2_500
        })

      {:error, changeset} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_enrollment", details: inspect(changeset.errors)})
    end
  end

  def status(conn, %{"id" => id}) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, payload} <- Enrollment.status(id, token) do
      json(conn, payload)
    else
      {:error, reason} -> enrollment_error(conn, reason)
    end
  end

  def submit_csr(conn, %{"id" => id, "csr_pem" => csr_pem}) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, result} <- Enrollment.submit_csr(id, token, csr_pem) do
      certificate = result.certificate

      json(conn, %{
        agent_id: result.enrollment.agent_id,
        certificate_pem: certificate.certificate_pem,
        ca_chain_pem: ca_chain_pem(),
        certificate_serial: certificate.serial_number,
        certificate_fingerprint: certificate.fingerprint,
        connect_info_url: "/v1/agent/enrollments/#{id}/connect-info"
      })
    else
      {:error, reason} -> enrollment_error(conn, reason)
    end
  end

  def submit_csr(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "csr_pem is required"})
  end

  def connect_info(conn, %{"id" => id}) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, payload} <- Enrollment.connect_info(id, token) do
      json(conn, payload)
    else
      {:error, reason} -> enrollment_error(conn, reason)
    end
  end

  def finalize(conn, %{"id" => id} = params) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, enrollment} <- Enrollment.finalize(id, token, Map.delete(params, "id")) do
      json(conn, %{status: enrollment.status})
    else
      {:error, reason} -> enrollment_error(conn, reason)
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      _ -> {:error, :missing_pending_token}
    end
  end

  defp enrollment_error(conn, :not_found),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp enrollment_error(conn, :expired),
    do: conn |> put_status(:gone) |> json(%{error: "expired"})

  defp enrollment_error(conn, :invalid_pending_token),
    do: conn |> put_status(:unauthorized) |> json(%{error: "invalid_pending_token"})

  defp enrollment_error(conn, reason),
    do: conn |> put_status(:bad_request) |> json(%{error: inspect(reason)})

  defp ca_chain_pem do
    case SecretHub.Core.PKI.CA.get_ca_chain() do
      {:ok, chain} -> chain
      {:error, _} -> nil
    end
  end
end
