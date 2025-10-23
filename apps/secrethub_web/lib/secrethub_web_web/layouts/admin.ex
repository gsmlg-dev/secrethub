defmodule SecretHub.WebWeb.Layouts.Admin do
  @moduledoc """
  Admin layout for SecretHub web interface.
  """

  use SecretHub.WebWeb, :html

  embed_templates "layouts/admin_html/*"
end
