defmodule SecretHub.Shared.Schemas.SSH.Inventory do
  @moduledoc "Revision-locked SSH public inventory. The singleton serializes management batches."
  use Ecto.Schema

  @primary_key {:id, :integer, autogenerate: false}
  schema "ssh_inventory" do
    field(:revision, :integer, default: 0)
    field(:groups, {:array, :map}, default: [])
    field(:endpoints, {:array, :map}, default: [])
    field(:rules, {:array, :map}, default: [])
    field(:reports, :map, default: %{})
  end
end
