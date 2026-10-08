defmodule SecretHub.HumanWeb.Native.OrganizationController do
  alias SecretHub.Human.DynamicSecrets
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.Organizations
  def index(conn, _), do: respond(conn, Organizations.list(actor(conn)))
  def create(conn, params), do: respond(conn, Organizations.create(actor(conn), params))
  def members(conn, %{"id" => id}), do: respond(conn, Organizations.list_members(actor(conn), id))

  def add_member(conn, %{"id" => id} = params),
    do: respond(conn, Organizations.add_member(actor(conn), id, params))

  def remove_member(conn, %{"id" => id, "user_id" => user}),
    do: respond(conn, Organizations.remove_member(actor(conn), id, user))

  def collections(conn, %{"id" => id}),
    do: respond(conn, Organizations.list_collections(actor(conn), id))

  def create_collection(conn, %{"id" => id} = params),
    do: respond(conn, Organizations.create_collection(actor(conn), id, params))

  def update_collection(conn, %{"id" => id} = params),
    do: respond(conn, Organizations.update_collection(actor(conn), id, params))

  def permission(conn, %{"id" => id} = params),
    do: respond(conn, Organizations.set_collection_permission(actor(conn), id, params))

  def items(conn, %{"id" => id}), do: respond(conn, Organizations.list_items(actor(conn), id))

  def share(conn, %{"id" => id, "item_id" => item} = params),
    do: respond(conn, Organizations.share_item(actor(conn), id, item, params))

  def show_item(conn, %{"id" => id}), do: respond(conn, Organizations.get_item(actor(conn), id))

  def update_item(conn, %{"id" => id} = params),
    do: respond(conn, Organizations.update_item(actor(conn), id, params))

  def delete_item(conn, %{"id" => id}),
    do: respond(conn, Organizations.delete_item(actor(conn), id))

  def references(conn, %{"id" => id}),
    do: respond(conn, Organizations.list_dynamic_references(actor(conn), id))

  def create_reference(conn, %{"id" => id} = params),
    do:
      respond(
        conn,
        Organizations.create_dynamic_reference(
          actor(conn),
          id,
          Map.take(params, ~w(mount_id role_id requested_ttl))
        )
      )

  def request(conn, %{"id" => id, "reference_id" => ref} = params),
    do:
      respond(
        conn,
        DynamicSecrets.request_shared(
          conn.assigns.human_access_token,
          id,
          ref,
          params
        )
      )

  def request_approval(conn, %{"id" => id, "reference_id" => ref} = params),
    do:
      respond(
        conn,
        DynamicSecrets.request_shared_approval(
          conn.assigns.human_access_token,
          id,
          ref,
          params
        )
      )

  defp actor(conn), do: conn.assigns.human_actor
  defp respond(conn, {:ok, value}), do: json(conn, %{data: value})
  defp respond(conn, :ok), do: json(conn, %{data: %{}})

  defp respond(conn, {:error, reason}),
    do:
      conn
      |> put_status(if(reason == :not_found, do: 404, else: 400))
      |> json(%{error: Atom.to_string(reason)})
end
