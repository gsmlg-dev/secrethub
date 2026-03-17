defmodule SecretHub.Shared.Schemas.VaultConfig do
  @moduledoc """
  Schema for vault seal configuration persistence.

  Stores the encrypted master key and Shamir threshold parameters so the vault
  can detect it has been initialized across restarts. Only one row should ever
  exist in this table.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "vault_config" do
    field(:encrypted_master_key, :binary)
    field(:threshold, :integer)
    field(:total_shares, :integer)
    field(:initialized_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  def changeset(vault_config, attrs) do
    vault_config
    |> cast(attrs, [:encrypted_master_key, :threshold, :total_shares, :initialized_at])
    |> validate_required([:encrypted_master_key, :threshold, :total_shares, :initialized_at])
    |> validate_number(:threshold, greater_than: 0)
    |> validate_number(:total_shares, greater_than: 0)
    |> validate_threshold_lte_total()
  end

  defp validate_threshold_lte_total(changeset) do
    threshold = get_field(changeset, :threshold)
    total = get_field(changeset, :total_shares)

    if threshold && total && threshold > total do
      add_error(changeset, :threshold, "must be less than or equal to total_shares")
    else
      changeset
    end
  end
end
