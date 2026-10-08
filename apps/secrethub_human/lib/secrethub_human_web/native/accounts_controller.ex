defmodule SecretHub.HumanWeb.Native.AccountsController do
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.Accounts

  def devices(conn, _) do
    case Accounts.list_devices(conn.assigns.human_actor) do
      {:ok, devices} ->
        json(conn, %{devices: Enum.map(devices, &Map.take(&1, [:id, :name, :type, :inserted_at]))})

      {:error, _} ->
        conn |> put_status(401) |> json(%{error: "unauthorized"})
    end
  end

  def remove_device(conn, %{"id" => id}),
    do: respond(conn, Accounts.remove_device(conn.assigns.human_actor, id))

  def revoke_session(conn, %{"id" => id}),
    do: respond(conn, Accounts.revoke_session(conn.assigns.human_actor, id))

  defp respond(conn, :ok), do: json(conn, %{})
  defp respond(conn, {:error, _}), do: conn |> put_status(404) |> json(%{error: "not_found"})
end
