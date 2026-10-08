defmodule SecretHub.Human.Vault.Head do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:user_id, :binary_id, autogenerate: false}
  schema "vault_heads" do
    field(:revision, :integer, default: 0)
  end
end
