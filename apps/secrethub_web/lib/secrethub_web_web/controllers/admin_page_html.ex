defmodule SecretHub.WebWeb.AdminPageHTML do
  @moduledoc """
  Renders admin page templates.
  """

  use SecretHub.WebWeb, :html

  embed_templates "../../templates/admin_page/*"
end
