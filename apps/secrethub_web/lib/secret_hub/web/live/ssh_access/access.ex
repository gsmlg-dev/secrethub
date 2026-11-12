defmodule SecretHub.Web.SSHAccess.Access do
  @moduledoc "Access tab."
  use Phoenix.Component
  attr :inventory, :map, required: true
  attr :editing_group, :map, default: nil
  # Task 14 moves these onto the group drawer's native-checkbox <fieldset>:
  # TODO(upstream): duskmoon-dev/phoenix-duskmoon-ui#205
  # WORKAROUND(upstream): duskmoon-dev/phoenix-duskmoon-ui#205
  # dm_checkbox currently emits boolean values only. Compose native controls
  # for record selection until the package supports explicit array values.
  def tab(assigns) do
    ~H"""
    <div id="access-tab"></div>
    """
  end

  def cell_changes(_inventory, _attrs), do: []
end
