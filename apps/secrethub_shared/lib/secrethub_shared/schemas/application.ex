defmodule SecretHub.Shared.Schemas.Application do
  @moduledoc """
  Ecto schema for applications that connect to SecretHub Agents.

  Applications authenticate via mTLS using certificates issued by Core PKI.
  Each application belongs to an agent and has associated policies for access control.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "applications" do
    field(:name, :string)
    field(:description, :string)
    field(:status, :string, default: "active")
    field(:policies, {:array, :string}, default: [])
    field(:metadata, :map, default: %{})

    belongs_to(:agent, SecretHub.Shared.Schemas.Agent, type: :binary_id)

    has_many(:bootstrap_tokens, SecretHub.Shared.Schemas.AppBootstrapToken, foreign_key: :app_id)
    has_many(:app_certificates, SecretHub.Shared.Schemas.AppCertificate, foreign_key: :app_id)

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating an application.

  ## Required fields
    - name: Unique application name (used in certificate CN)
    - agent_id: Agent this app connects to

  ## Optional fields
    - description: Human-readable description
    - status: active, suspended, revoked
    - policies: List of policy names
    - metadata: Additional key-value data
  """
  def changeset(application, attrs) do
    application
    |> cast(attrs, [:name, :description, :agent_id, :status, :policies, :metadata])
    |> validate_required([:name, :agent_id])
    |> validate_length(:name, min: 3, max: 100)
    |> validate_format(:name, ~r/^[a-z0-9][a-z0-9\-]*[a-z0-9]$/,
      message: "must be lowercase alphanumeric with hyphens, start and end with alphanumeric"
    )
    |> validate_inclusion(:status, ["active", "suspended", "revoked"])
    |> unique_constraint(:name)
    |> foreign_key_constraint(:agent_id)
  end
end
