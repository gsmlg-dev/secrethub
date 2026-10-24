defmodule SecretHub.Shared.Schemas.ManagedCertificate do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "managed_certificates" do
    field(:name, :string)
    field(:slug, :string)
    field(:account_id, :binary_id)
    field(:identifiers, {:array, :string})
    field(:bindings, {:array, :map})
    field(:key_policy, :string, default: "ec_p256")
    field(:configuration_revision, :integer, default: 1)
    field(:publication_sequence, :integer, default: 0)
    field(:enabled, :boolean, default: true)
    field(:current_version_id, :binary_id)
    field(:output_secret_id, :binary_id)
    field(:next_renewal_at, :utc_datetime)
    field(:last_error, :map, default: %{})
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :name,
      :slug,
      :account_id,
      :identifiers,
      :bindings,
      :key_policy,
      :configuration_revision,
      :publication_sequence,
      :enabled,
      :current_version_id,
      :output_secret_id,
      :next_renewal_at,
      :last_error
    ])
    |> update_change(:name, &trim_name/1)
    |> validate_supplied_name()
    |> validate_length(:name, max: 255, count: :codepoints)
    |> validate_required([:slug, :account_id, :identifiers, :bindings, :key_policy])
    |> validate_format(:slug, ~r/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
    |> validate_length(:slug, max: 80)
    |> validate_inclusion(:key_policy, ["ec_p256", "rsa_2048"])
    |> unique_constraint(:name)
    |> unique_constraint(:slug)
    |> foreign_key_constraint(:account_id)
  end

  defp trim_name(nil), do: nil
  defp trim_name(name), do: String.trim(name)

  defp validate_supplied_name(%{params: %{"name" => _}} = changeset),
    do: validate_required(changeset, [:name])

  defp validate_supplied_name(changeset), do: changeset
end
