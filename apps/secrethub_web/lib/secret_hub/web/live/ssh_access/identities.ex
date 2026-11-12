defmodule SecretHub.Web.SSHAccess.Identities do
  @moduledoc "Identities tab."
  use Phoenix.Component
  attr :inventory, :map, required: true

  def tab(assigns) do
    ~H"""
    <div id="identities-tab"></div>
    """
  end
end
