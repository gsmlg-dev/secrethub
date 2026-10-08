defmodule SecretHub.HumanWeb.Native.VaultController do
  alias SecretHub.Human.Notifications
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.Vault

  def index(conn, params) do
    with {cursor, ""} <- Integer.parse(Map.get(params, "cursor", "0")),
         {:ok, page} <- Vault.sync(conn.assigns.human_actor, cursor) do
      json(conn, %{
        items: Enum.map(page.items, &Vault.dto/1),
        folders: Enum.map(page.folders, &Vault.dto/1),
        cursor: page.cursor
      })
    else
      _ -> error(conn, :invalid_input)
    end
  end

  def create(conn, params),
    do: respond(conn, Vault.create_item(conn.assigns.human_actor, params), &Vault.dto/1)

  def show(conn, %{"id" => id}),
    do: respond(conn, Vault.get_item(conn.assigns.human_actor, id), &Vault.dto/1)

  def update(conn, %{"id" => id} = params),
    do: respond(conn, Vault.update_item(conn.assigns.human_actor, id, params), &Vault.dto/1)

  def delete(conn, %{"id" => id}),
    do: respond(conn, Vault.delete_item(conn.assigns.human_actor, id), &Vault.dto/1)

  def history(conn, %{"id" => id}) do
    respond(conn, Vault.item_history(conn.assigns.human_actor, id), fn versions ->
      %{versions: Enum.map(versions, &Map.take(&1, [:id, :revision, :ciphertext, :inserted_at]))}
    end)
  end

  def export(conn, params),
    do:
      respond(
        conn,
        Vault.export(conn.assigns.human_actor, %{confirm: params["confirm"] == true}),
        & &1
      )

  defp respond(conn, {:ok, value}, mapper) do
    if conn.method in ["POST", "PUT", "DELETE"],
      do: Notifications.changed(conn.assigns.human_actor)

    json(conn, mapper.(value))
  end

  defp respond(conn, {:error, reason}, _), do: error(conn, reason)

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
