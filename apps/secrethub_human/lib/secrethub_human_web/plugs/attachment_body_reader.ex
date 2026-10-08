defmodule SecretHub.HumanWeb.Plugs.AttachmentBodyReader do
  @moduledoc false
  # Filename and key each use the one-megabyte envelope limit.
  @metadata_bytes 2_010_000

  def read_body(
        %Plug.Conn{method: "POST", path_info: ["human", "vault", "items", _id, "attachments"]} =
          conn,
        opts
      ) do
    max_bytes = Application.get_env(:secrethub_human, :attachment_max_bytes, 10_485_760)
    Plug.Conn.read_body(conn, Keyword.put(opts, :length, max_bytes + @metadata_bytes))
  end

  def read_body(conn, opts), do: Plug.Conn.read_body(conn, opts)
end
