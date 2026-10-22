defmodule SecretHub.Shared.Schemas.AcmeAccount do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "acme_accounts" do
    field(:name, :string)
    field(:environment, :string)
    field(:directory_url, :string)
    field(:contact, {:array, :string}, default: [])
    field(:terms_url, :string)
    field(:terms_accepted_at, :utc_datetime)
    field(:encrypted_key, :binary, redact: true)
    field(:account_url, :string)
    field(:status, :string, default: "pending")
    field(:enabled, :boolean, default: true)
    field(:last_error, :map, default: %{})
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :name,
      :environment,
      :directory_url,
      :contact,
      :terms_url,
      :terms_accepted_at,
      :encrypted_key,
      :account_url,
      :status,
      :enabled,
      :last_error
    ])
    |> validate_required([
      :name,
      :environment,
      :directory_url,
      :terms_url,
      :terms_accepted_at,
      :encrypted_key
    ])
    |> validate_inclusion(:environment, ["production", "staging"])
  end
end
