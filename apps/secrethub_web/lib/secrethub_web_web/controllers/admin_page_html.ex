defmodule SecretHub.WebWeb.AdminPageHTML do
  @moduledoc """
  Renders admin page templates.
  """

  use SecretHub.WebWeb, :html
  import Plug.Conn, only: [get_req_header: 2]

  embed_templates "../templates/admin_page/*"
end
