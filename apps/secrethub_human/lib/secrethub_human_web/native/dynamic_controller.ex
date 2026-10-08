defmodule SecretHub.HumanWeb.Native.DynamicController do
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.DynamicSecrets
  def capabilities(conn, _), do: respond(conn, DynamicSecrets.capabilities(token(conn)))
  def references(conn, _), do: respond(conn, DynamicSecrets.references(token(conn)))

  def create_reference(conn, params),
    do: respond(conn, DynamicSecrets.create_reference(token(conn), params))

  def request(conn, %{"id" => id} = params),
    do: respond(conn, DynamicSecrets.request(token(conn), id, params))

  def reveal(conn, %{"token" => reveal}),
    do: respond(conn, DynamicSecrets.reveal(token(conn), reveal))

  def reveal(conn, _), do: respond(conn, {:error, :invalid_input})
  def leases(conn, _), do: respond(conn, DynamicSecrets.leases(token(conn)))

  def renew(conn, %{"id" => id} = params),
    do: respond(conn, DynamicSecrets.renew(token(conn), Map.put(params, "lease_id", id)))

  def revoke(conn, %{"id" => id}), do: respond(conn, DynamicSecrets.revoke(token(conn), id))
  def approvals(conn, _), do: respond(conn, DynamicSecrets.approvals(token(conn)))

  def request_approval(conn, %{"id" => id} = params),
    do: respond(conn, DynamicSecrets.request_approval(token(conn), id, params))

  def approve(conn, %{"id" => id}), do: respond(conn, DynamicSecrets.approve(token(conn), id))
  def deny(conn, %{"id" => id}), do: respond(conn, DynamicSecrets.deny(token(conn), id))
  defp token(conn), do: conn.assigns.human_access_token
  defp respond(conn, {:ok, value}), do: json(conn, %{data: value})
  defp respond(conn, :ok), do: json(conn, %{data: %{}})

  defp respond(conn, {:error, reason}) do
    status = if reason in [:unauthenticated, :unauthorized], do: 403, else: 400
    conn |> put_status(status) |> json(%{error: Atom.to_string(reason)})
  end
end
