defmodule SecretHub.Shared.Schemas.SecretPathRevision do
  @moduledoc "Retained monotonic mutation revision for a canonical secret path."
  use Ecto.Schema
  @primary_key {:secret_path, :string, autogenerate: false}
  schema "secret_path_revisions" do
    field(:revision, :integer, default: 1)
  end
end
