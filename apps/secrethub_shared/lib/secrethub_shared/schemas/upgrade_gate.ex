defmodule SecretHub.Shared.Schemas.UpgradeGate do
  @moduledoc """
  Durable evidence that a named upgrade preflight reached zero findings.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @gate_names ~w(
    app_certificate_v2
    typed_runtime_authorization
    dynamic_secure_storage
    agent_certificate_bindings
  )
  @report_format "secrethub.upgrade-gate-report.v1"
  @sha256_hex ~r/\A[0-9a-f]{64}\z/

  @type t :: %__MODULE__{}

  schema "upgrade_gates" do
    field(:name, :string)
    field(:report_format, :string)
    field(:report_hash, :string)
    field(:preflight_version, :string)
    field(:verified_at, :utc_datetime)
    field(:verified_by, :string)
    field(:verification_generation, :integer)

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(gate, attrs) do
    gate
    |> cast(attrs, [
      :name,
      :report_format,
      :report_hash,
      :preflight_version,
      :verified_at,
      :verified_by,
      :verification_generation
    ])
    |> validate_required([
      :name,
      :report_format,
      :report_hash,
      :preflight_version,
      :verified_at,
      :verified_by,
      :verification_generation
    ])
    |> validate_inclusion(:name, @gate_names)
    |> validate_inclusion(:report_format, [@report_format])
    |> validate_inclusion(:preflight_version, ["1"])
    |> validate_format(:report_hash, @sha256_hex)
    |> validate_length(:verified_by, min: 1, max: 255)
    |> validate_number(:verification_generation, greater_than: 0)
    |> unique_constraint(:name)
  end
end
