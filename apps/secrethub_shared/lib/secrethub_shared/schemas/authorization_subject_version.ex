defmodule SecretHub.Shared.Schemas.AuthorizationSubjectVersion do
  @moduledoc "Monotonic version for a typed Agent or application authorization subject."
  use Ecto.Schema
  @primary_key {:subject, :string, autogenerate: false}
  schema "authorization_subject_versions" do
    field(:version, :integer, default: 1)
  end
end
