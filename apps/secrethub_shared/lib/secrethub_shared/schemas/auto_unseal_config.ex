defmodule SecretHub.Shared.Schemas.AutoUnsealConfig do
  @moduledoc """
  Schema for auto-unseal configuration.

  Stores encrypted unseal keys and KMS provider configuration for
  automatic vault unsealing on startup.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "auto_unseal_configs" do
    field(:provider, :string)
    field(:kms_key_id, :string)
    field(:region, :string)
    field(:encrypted_unseal_keys, {:array, :string})
    field(:active, :boolean, default: true)
    field(:max_retries, :integer, default: 3)
    field(:retry_delay_ms, :integer, default: 5000)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(config, attrs) do
    config
    |> cast(attrs, [
      :provider,
      :kms_key_id,
      :region,
      :encrypted_unseal_keys,
      :active,
      :max_retries,
      :retry_delay_ms,
      :metadata
    ])
    |> validate_required([:provider, :kms_key_id, :encrypted_unseal_keys])
    |> validate_inclusion(:provider, ["aws_kms", "gcp_kms", "azure_kv"])
    |> validate_number(:max_retries, greater_than_or_equal_to: 0, less_than_or_equal_to: 10)
    |> validate_number(:retry_delay_ms, greater_than: 0)
  end
end
