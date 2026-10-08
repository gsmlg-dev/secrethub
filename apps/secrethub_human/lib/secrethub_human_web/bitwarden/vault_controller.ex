defmodule SecretHub.HumanWeb.Bitwarden.VaultController do
  alias SecretHub.Human.Notifications
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.{Accounts, Vault}
  alias SecretHub.HumanWeb.Bitwarden.DTO

  def profile(conn, _params) do
    Accounts.profile(actor(conn)) |> respond(conn, &DTO.profile/1)
  end

  def revision(conn, _), do: json(conn, DateTime.to_unix(DateTime.utc_now(), :millisecond))

  def sync(conn, _) do
    with {:ok, user} <- Accounts.profile(actor(conn)),
         {:ok, data} <- complete_sync(actor(conn)) do
      json(conn, %{
        object: "sync",
        userDecryption: DTO.user_decryption(user),
        profile: DTO.profile(user),
        ciphers: Enum.map(data.items, &DTO.cipher/1),
        folders: data.folders |> Enum.filter(&is_nil(&1.deleted_at)) |> Enum.map(&DTO.folder/1),
        collections: [],
        domains: %{equivalentDomains: [], globalEquivalentDomains: []},
        policies: [],
        sends: []
      })
    else
      {:error, reason} -> error(conn, reason)
    end
  end

  def list_ciphers(conn, _) do
    complete_sync(actor(conn))
    |> respond(conn, fn data ->
      %{object: "list", data: Enum.map(data.items, &DTO.cipher/1), continuationToken: nil}
    end)
  end

  def get_cipher(conn, %{"id" => id}),
    do: Vault.get_item(actor(conn), id) |> respond(conn, &DTO.cipher/1)

  def create_cipher(conn, params),
    do: Vault.create_item(actor(conn), DTO.item_input(params)) |> respond(conn, &DTO.cipher/1)

  def update_cipher(conn, %{"id" => id} = params) do
    attrs = DTO.item_input(params) |> Map.delete(:type)
    Vault.update_item(actor(conn), id, attrs) |> respond(conn, &DTO.cipher/1)
  end

  def delete_cipher(conn, %{"id" => id}),
    do: Vault.delete_item(actor(conn), id) |> respond(conn, fn _ -> %{} end)

  def list_folders(conn, _) do
    complete_sync(actor(conn))
    |> respond(conn, fn data ->
      %{
        object: "list",
        data: data.folders |> Enum.filter(&is_nil(&1.deleted_at)) |> Enum.map(&DTO.folder/1),
        continuationToken: nil
      }
    end)
  end

  def create_folder(conn, params),
    do: Vault.create_folder(actor(conn), %{name: params["name"]}) |> respond(conn, &DTO.folder/1)

  def update_folder(conn, %{"id" => id} = params),
    do:
      Vault.update_folder(actor(conn), id, %{name: params["name"]})
      |> respond(conn, &DTO.folder/1)

  def delete_folder(conn, %{"id" => id}),
    do: Vault.delete_folder(actor(conn), id) |> respond(conn, fn _ -> %{} end)

  defp complete_sync(actor), do: Vault.snapshot(actor)
  defp actor(conn), do: conn.assigns.human_actor

  defp respond({:ok, value}, conn, mapper) do
    if conn.method in ["POST", "PUT", "DELETE"],
      do: Notifications.changed(actor(conn))

    json(conn, mapper.(value))
  end

  defp respond({:error, reason}, conn, _), do: error(conn, reason)

  defp error(conn, reason) do
    status =
      case reason do
        :unauthenticated -> 401
        :not_found -> 404
        :conflict -> 409
        _ -> 400
      end

    conn |> put_status(status) |> json(%{error: "request_failed"})
  end
end
