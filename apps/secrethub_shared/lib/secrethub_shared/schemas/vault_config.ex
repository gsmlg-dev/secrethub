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
    field(:encrypted_master_key, :binary, redact: true)
    field(:envelope_version, :integer)
    field(:share_version, :integer)
    field(:share_set_id, :binary)
    field(:threshold, :integer)
    field(:total_shares, :integer)
    field(:initialized_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  def changeset(vault_config, attrs) do
    vault_config
    |> cast(attrs, [
      :encrypted_master_key,
      :threshold,
      :total_shares,
      :initialized_at,
      :envelope_version,
      :share_version,
      :share_set_id
    ])
    |> validate_required([
      :encrypted_master_key,
      :threshold,
      :total_shares,
      :initialized_at,
      :envelope_version,
      :share_version,
      :share_set_id
    ])
    |> validate_number(:threshold, greater_than: 0)
    |> validate_number(:total_shares, greater_than: 0, less_than_or_equal_to: 251)
    |> validate_threshold_lte_total()
    |> unique_constraint(:id, name: :vault_config_singleton)
    |> check_constraint(:threshold, name: :vault_config_parameters)
    |> check_constraint(:envelope_version, name: :vault_config_envelope)
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
