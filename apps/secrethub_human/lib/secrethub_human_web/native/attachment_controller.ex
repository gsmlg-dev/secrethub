defmodule SecretHub.HumanWeb.Native.AttachmentController do
  use SecretHub.HumanWeb, :controller
  alias SecretHub.Human.Attachments

  def index(conn, %{"id" => id}),
    do: respond(conn, Attachments.list(conn.assigns.human_actor, id))

  def create(conn, %{"id" => id} = params),
    do: respond(conn, Attachments.upload(conn.assigns.human_actor, id, params))

  def delete(conn, %{"id" => id}),
    do: respond(conn, Attachments.delete(conn.assigns.human_actor, id))

  def download(conn, %{"id" => id}) do
    case Attachments.download(conn.assigns.human_actor, id) do
      {:ok, content} ->
        conn
        |> put_resp_content_type("application/octet-stream")
        |> put_resp_header("content-disposition", "attachment")
        |> send_resp(200, content)

      {:error, _} ->
        conn |> put_status(404) |> json(%{error: "not_found"})
    end
  end

  defp respond(conn, {:ok, value}), do: json(conn, %{data: value})
  defp respond(conn, :ok), do: json(conn, %{data: %{}})

  defp respond(conn, {:error, reason}),
    do: conn |> put_status(400) |> json(%{error: Atom.to_string(reason)})
end
