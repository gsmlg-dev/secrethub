defmodule SecretHub.Shared.Schemas.DNSProvider do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "acme_dns_providers" do
    field(:name, :string)
    field(:provider, :string)
    field(:credential_mode, :string, default: "secret")
    field(:credential_secret_id, :binary_id)
    field(:zones, {:array, :map}, default: [])
    field(:enabled, :boolean, default: true)
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [:name, :provider, :credential_mode, :credential_secret_id, :zones, :enabled])
    |> validate_required([:name, :provider, :credential_mode, :zones])
    |> validate_inclusion(:provider, ["cloudflare", "route53"])
    |> validate_inclusion(:credential_mode, ["secret", "aws_environment"])
    |> foreign_key_constraint(:credential_secret_id)
  end
end
