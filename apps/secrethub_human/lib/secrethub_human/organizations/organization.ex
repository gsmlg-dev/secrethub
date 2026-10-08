defmodule SecretHub.Human.Organizations.Organization do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:id, :binary_id, autogenerate: true}
  schema "human_organizations" do
    field(:name, :string, redact: true)
    timestamps(type: :utc_datetime_usec)
  end
end
