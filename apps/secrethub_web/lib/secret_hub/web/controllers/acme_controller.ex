defmodule SecretHub.Web.AcmeController do
  @moduledoc "Private management HTTP surface for public trust and managed server certificates."
  use SecretHub.Web, :controller

  alias SecretHub.Core.PKI.{ManagedCertificates, TrustStores}

  @account_fields ~w(id name environment directory_url contact terms_url terms_accepted_at account_url status enabled last_error inserted_at updated_at)a
  @provider_fields ~w(id name provider credential_mode credential_secret_id zones enabled inserted_at updated_at)a
  @managed_fields ~w(id slug account_id identifiers bindings key_policy configuration_revision publication_sequence enabled current_version_id output_secret_id next_renewal_at last_error inserted_at updated_at)a
  @version_fields ~w(id managed_certificate_id order_id publication_sequence environment fingerprint certificate_pem chain_pem fullchain_pem identifiers not_before not_after key_policy output_secret_id secret_version_number ari renewal_due_at ari_refresh_at quarantined_at revocation_state revocation_reason revocation_next_attempt_at revocation_error inserted_at)a
  @order_fields ~w(id managed_certificate_id request_id configuration_revision expected_prior_version_id state phase identifiers remote_url remote_status next_attempt_at deadline_at attempts uncertain_creates last_error inserted_at updated_at)a
  @cleanup_fields ~w(id order_id authorization_id provider_id original_owner owner state cleanup_status next_attempt_at last_error inserted_at updated_at)a

  def trust_stores(conn, _params), do: reply(conn, TrustStores.list())
  def trust_store(conn, %{"id" => id}), do: reply(conn, TrustStores.catalogue(id))

  def trust_bundle(conn, %{"id" => id}) do
    # Only the default public bundle is an exportable public trust store.
    with true <- id == "mozilla_webpki", {:ok, pem} <- TrustStores.pem(id) do
      conn
      |> put_resp_content_type("application/x-pem-file")
      |> put_resp_header("content-disposition", ~s(attachment; filename="mozilla-webpki.pem"))
      |> put_resp_header(
        "x-content-sha256",
        Base.encode16(:crypto.hash(:sha256, pem), case: :lower)
      )
      |> send_resp(200, pem)
    else
      false -> error(conn, :unknown_trust_store)
      {:error, reason} -> error(conn, reason)
    end
  end

  def index(conn, _params) do
    json(conn, %{
      data: %{
        accounts: Enum.map(ManagedCertificates.list_accounts(), &public_account/1),
        providers: Enum.map(ManagedCertificates.list_providers(), &public_provider/1),
        certificates: Enum.map(ManagedCertificates.list_managed(), &public_managed/1),
        cleanup: Enum.map(ManagedCertificates.list_cleanup(), &public_cleanup/1)
      }
    })
  end

  def show(conn, %{"id" => id}) do
    case ManagedCertificates.get_managed(id) do
      {:ok, certificate} ->
        json(conn, %{
          data: %{
            certificate: public_managed(certificate),
            versions: Enum.map(ManagedCertificates.list_versions(id), &public_version/1),
            orders: Enum.map(ManagedCertificates.list_orders(id), &public_order/1)
          }
        })

      {:error, reason} ->
        error(conn, reason)
    end
  end

  def create_provider(conn, params),
    do: reply(conn, ManagedCertificates.create_provider(params), &public_provider/1, 201)

  def update_provider(conn, %{"id" => id} = params),
    do:
      reply(
        conn,
        ManagedCertificates.update_provider(id, Map.delete(params, "id")),
        &public_provider/1
      )

  def create_account(conn, params),
    do: reply(conn, ManagedCertificates.create_account(params), &public_account/1, 202)

  def update_account(conn, %{"id" => id} = params) do
    attrs = Map.take(params, ~w(enabled terms_url terms_accepted))

    cond do
      Map.has_key?(attrs, "enabled") and not is_boolean(attrs["enabled"]) ->
        error(conn, :invalid_enabled_value)

      Map.has_key?(attrs, "terms_url") and attrs["terms_accepted"] != true ->
        error(conn, :terms_acceptance_required)

      attrs == %{} ->
        error(conn, :account_update_required)

      true ->
        reply(conn, ManagedCertificates.update_account(id, attrs), &public_account/1)
    end
  end

  def register_account(conn, %{"id" => id}),
    do: reply(conn, ManagedCertificates.register_account(id), &job/1, 202)

  def create_managed(conn, params),
    do: reply(conn, ManagedCertificates.create_managed(params), &public_managed/1, 201)

  def update_managed(conn, %{"id" => id} = params),
    do:
      reply(
        conn,
        ManagedCertificates.update_managed(id, Map.delete(params, "id")),
        &public_managed/1
      )

  def issue(conn, %{"id" => id} = params) do
    request_id = params["request_id"] || List.first(get_req_header(conn, "idempotency-key"))

    if is_binary(request_id) and byte_size(request_id) in 1..160,
      do: reply(conn, ManagedCertificates.request_issue(id, request_id), &public_order/1, 202),
      else: error(conn, :request_id_required)
  end

  def cancel(conn, %{"id" => id}),
    do: reply(conn, ManagedCertificates.cancel_order(id), &public_order/1, 202)

  def retry_cleanup(conn, %{"id" => id}),
    do: reply(conn, ManagedCertificates.retry_cleanup(id), &job/1, 202)

  def revoke(conn, %{"id" => id} = params) do
    case revocation_reason(params["reason"] || 0) do
      {:ok, reason} ->
        reply(conn, ManagedCertificates.request_revocation(id, reason), &public_version/1, 202)

      {:error, reason} ->
        error(conn, reason)
    end
  end

  def export_pem(conn, params), do: export(conn, Map.put(params, "format", "pem"))

  def export(conn, %{"id" => id} = params) do
    conn =
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")

    case ManagedCertificates.export_version(id) do
      {:ok, material} ->
        if params["format"] == "pem" do
          combined = material["fullchain"] <> "\n" <> material["private_key"]

          conn
          |> put_resp_content_type("application/x-pem-file")
          |> put_resp_header(
            "content-disposition",
            ~s(attachment; filename="certificate-#{id}.pem")
          )
          |> send_resp(200, combined)
        else
          json(conn, %{data: material})
        end

      {:error, reason} ->
        error(conn, reason)
    end
  end

  def public_account(record), do: Map.take(record, @account_fields)
  def public_provider(record), do: Map.take(record, @provider_fields)
  def public_managed(record), do: Map.take(record, @managed_fields)
  def public_version(record), do: Map.take(record, @version_fields)
  def public_order(record), do: Map.take(record, @order_fields)
  def public_cleanup(record), do: Map.take(record, @cleanup_fields)

  defp job(record), do: Map.take(record, [:id, :state, :scheduled_at])
  defp reply(conn, result, render \\ &Function.identity/1, status \\ 200)

  defp reply(conn, {:ok, value}, render, status),
    do: conn |> put_status(status) |> json(%{data: render.(value)})

  defp reply(conn, {:error, reason}, _render, _status), do: error(conn, reason)

  defp error(conn, %Ecto.Changeset{} = changeset) do
    errors = Ecto.Changeset.traverse_errors(changeset, fn {message, _opts} -> message end)
    conn |> put_status(422) |> json(%{error: "validation_failed", fields: errors})
  end

  defp error(conn, reason) do
    status =
      cond do
        reason in [:not_found, :unknown_trust_store] ->
          404

        reason in [
          :active_order,
          :idempotency_conflict,
          :outstanding_obligations,
          :already_published
        ] ->
          409

        reason in [:certificate_quarantined, :certificate_expired] ->
          410

        reason in [:disabled, :feature_unavailable, :vault_unavailable, :public_trust_unavailable] ->
          503

        true ->
          400
      end

    code = if is_atom(reason), do: Atom.to_string(reason), else: "request_failed"
    conn |> put_status(status) |> json(%{error: code})
  end

  defp revocation_reason(reason) when reason in [0, 1, 3, 4, 5], do: {:ok, reason}

  defp revocation_reason(reason) when is_binary(reason) do
    case Integer.parse(reason) do
      {reason, ""} -> revocation_reason(reason)
      _ -> {:error, :unsupported_revocation_reason}
    end
  end

  defp revocation_reason(_), do: {:error, :unsupported_revocation_reason}
end
