defmodule SecretHub.Web.AdminPageHTML do
  @moduledoc """
  Renders admin page templates.
  """

  use SecretHub.Web, :html

  embed_templates "../templates/admin_page/*"
end
