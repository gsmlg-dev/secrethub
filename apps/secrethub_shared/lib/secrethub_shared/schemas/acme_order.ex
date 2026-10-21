defmodule SecretHub.Shared.Schemas.AcmeOrder do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "acme_orders" do
    field(:managed_certificate_id, :binary_id)
    field(:request_id, :string)
    field(:request_digest, :string)
    field(:configuration_revision, :integer)
    field(:expected_prior_version_id, :binary_id)
    field(:state, :string, default: "queued")
    field(:phase, :string, default: "prepare")
    field(:identifiers, {:array, :string})
    field(:bindings, {:array, :map})
    field(:account_snapshot, :map)
    field(:directory, :map, default: %{})
    field(:remote_url, :string)
    field(:finalize_url, :string)
    field(:certificate_url, :string)
    field(:authorization_urls, {:array, :string}, default: [])
    field(:remote_status, :string)
    field(:encrypted_pending_key, :binary, redact: true)
    field(:csr, :binary)
    field(:csr_digest, :string)
    field(:downloaded_chain, :string)
    field(:claim_token, :binary_id)
    field(:claim_expires_at, :utc_datetime)
    field(:remote_started_at, :utc_datetime)
    field(:next_attempt_at, :utc_datetime)
    field(:deadline_at, :utc_datetime)
    field(:attempts, :integer, default: 0)
    field(:uncertain_creates, :integer, default: 0)
    field(:last_error, :map, default: %{})
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :managed_certificate_id,
      :request_id,
      :request_digest,
      :configuration_revision,
      :expected_prior_version_id,
      :state,
      :phase,
      :identifiers,
      :bindings,
      :account_snapshot,
      :directory,
      :remote_url,
      :finalize_url,
      :certificate_url,
      :authorization_urls,
      :remote_status,
      :encrypted_pending_key,
      :csr,
      :csr_digest,
      :downloaded_chain,
      :claim_token,
      :claim_expires_at,
      :remote_started_at,
      :next_attempt_at,
      :deadline_at,
      :attempts,
      :uncertain_creates,
      :last_error
    ])
    |> validate_required([
      :managed_certificate_id,
      :request_id,
      :request_digest,
      :configuration_revision,
      :identifiers,
      :bindings,
      :account_snapshot,
      :deadline_at
    ])
    |> validate_length(:request_id, min: 1, max: 160)
    |> unique_constraint([:managed_certificate_id, :request_id])
    |> unique_constraint(:managed_certificate_id, name: :acme_orders_one_active)
  end
end
