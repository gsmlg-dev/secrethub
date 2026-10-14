defmodule SecretHub.Web.VaultRecoveryController do
  @moduledoc "Authenticated recovery of a sealed legacy Vault through management ingress."
  use SecretHub.Web, :controller

  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Shamir

  @unavailable "Vault recovery is unavailable. Preserve your backup and original shares, then try again when the service is ready."
  @ineligible "This Vault is not eligible for legacy recovery. Refresh its status before continuing."
  @verification_failed "Recovery could not verify these shares against existing encrypted data. No Vault data was changed. Preserve your backup and original shares."

  def show(conn, _params) do
    status = vault_status()

    case eligibility(status) do
      :ok -> render_page(conn, status, 200)
      :unavailable -> render_page(conn, status, 503, @unavailable)
      :ineligible -> render_page(conn, status, 409, @ineligible)
    end
  end

  def recover(conn, params) do
    status = vault_status()

    with :ok <- eligibility(status),
         {:ok, shares} <- input_shares(params, status) do
      case recover_shares(shares, status) do
        {:ok, new_shares} ->
          recovered_status = %{status | recovery_required: false, progress: 0}

          render_page(
            conn,
            recovered_status,
            200,
            nil,
            Enum.map(new_shares, &Shamir.encode_share/1)
          )

        {:error, :verification_failed} ->
          render_page(conn, vault_status(), 422, @verification_failed)

        {:error, :ineligible} ->
          render_page(conn, vault_status(), 409, @ineligible)

        _ ->
          render_page(conn, vault_status(), 503, @unavailable)
      end
    else
      :unavailable -> render_page(conn, status, 503, @unavailable)
      :ineligible -> render_page(conn, status, 409, @ineligible)
      {:error, message} -> render_page(conn, status, 400, message)
    end
  end

  defp eligibility(%{state: state}) when state in [:loading, :unavailable], do: :unavailable

  defp eligibility(%{
         state: :sealed,
         initialized: true,
         sealed: true,
         recovery_required: true,
         threshold: threshold,
         total_shares: total
       })
       when is_integer(threshold) and is_integer(total) and threshold > 0 and
              threshold <= total,
       do: :ok

  defp eligibility(_), do: :ineligible

  defp input_shares(%{"recovery" => %{"backup_confirmed" => "true", "shares" => input}}, status)
       when is_binary(input) and byte_size(input) <= 32_768 do
    shares = String.split(input, ~r/[\s,]+/, trim: true)

    cond do
      length(shares) < status.threshold ->
        {:error, "Provide at least #{status.threshold} original shares."}

      length(shares) > status.total_shares ->
        {:error, "Provide no more than #{status.total_shares} original shares."}

      length(Enum.uniq(shares)) != length(shares) ->
        {:error, "Each original share must be distinct. Remove duplicate shares."}

      true ->
        {:ok, shares}
    end
  end

  defp input_shares(_, _),
    do:
      {:error,
       "Confirm that you preserved a database backup and original shares, then provide the original shares (maximum 32 KiB)."}

  defp recover_shares(shares, status) do
    # A committed recovery returns its new shares only once. Do not abandon that
    # reply at the ordinary GenServer timeout after the database has committed.
    case SealState.recover_legacy(shares, status.total_shares, status.threshold, :infinity) do
      {:ok, shares} ->
        {:ok, shares}

      {:error,
       "Legacy recovery blocked: valid shares and trusted authenticated ciphertext required"} ->
        {:error, :verification_failed}

      {:error, message}
      when message in [
             "Vault does not require legacy recovery",
             "Vault unavailable or not eligible for legacy recovery"
           ] ->
        if eligibility(vault_status()) == :unavailable,
          do: {:error, :unavailable},
          else: {:error, :ineligible}

      _ ->
        {:error, :unavailable}
    end
  rescue
    _ -> {:error, :unavailable}
  catch
    :exit, _ -> {:error, :unavailable}
  end

  defp vault_status do
    SealState.status()
  rescue
    _ -> unavailable_status()
  catch
    :exit, _ -> unavailable_status()
  end

  defp unavailable_status do
    %{
      state: :unavailable,
      initialized: false,
      sealed: true,
      recovery_required: false,
      progress: 0,
      threshold: nil,
      total_shares: nil
    }
  end

  defp render_page(conn, status, code, error \\ nil, shares \\ nil) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_status(code)
    |> put_layout(html: {SecretHub.Web.Layouts, :app})
    |> render(:index,
      vault_status: status,
      recovered_shares: shares,
      error_message: error,
      form: Phoenix.Component.to_form(%{"shares" => ""}, as: "recovery")
    )
  end
end
