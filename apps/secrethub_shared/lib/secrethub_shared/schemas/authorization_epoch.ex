defmodule SecretHub.Shared.Schemas.AuthorizationEpoch do
  @moduledoc "Singleton runtime authorization epoch and irreversible local authentication floor."
  use Ecto.Schema
  @primary_key {:id, :integer, autogenerate: false}
  schema "authorization_epochs" do
    field(:version, :integer, default: 1)
    field(:minimum_uds_auth_version, :integer, default: 1)
  end
end
