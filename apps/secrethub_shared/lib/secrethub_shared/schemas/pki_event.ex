defmodule SecretHub.Shared.Schemas.PKIEvent do
  @moduledoc """
  Immutable PKI lifecycle event stored in PostgreSQL.

  PKI events complement certificate records with an append-only history for CA
  creation, certificate issuance/revocation, CRL generation, and validation
  activity.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @event_types [
    :ca_initialized,
    :certificate_issued,
    :certificate_revoked,
    :certificate_renewed,
    :crl_generated,
    :certificate_validated
  ]

  @metadata_atom_keys MapSet.new([
                        "aki",
                        "auto_renew",
                        "ca_id",
                        "certificate_der",
                        "certificate_pem",
                        "certificate_type",
                        "cert_id",
                        "common_name",
                        "crl_number",
                        "crl_pem",
                        "crl_size_bytes",
                        "csr_fingerprint",
                        "fingerprint",
                        "hash",
                        "invalidity_date",
                        "issuer_ca_id",
                        "issuer_subject",
                        "key_info",
                        "key_size",
                        "key_type",
                        "not_after",
                        "not_before",
                        "old_serial",
                        "organization",
                        "public_key_der",
                        "reason",
                        "revocation_date",
                        "revoked_count",
                        "serial",
                        "ski",
                        "subject",
                        "subject_alternative_names",
                        "template",
                        "this_update",
                        "next_update",
                        "validity_days"
                      ])

  @primary_key {:id, :string, autogenerate: false}
  schema "pki_events" do
    field(:event_type, Ecto.Enum, values: @event_types)
    field(:timestamp, :utc_datetime_usec)
    field(:sequence, :integer)
    field(:ca_id, :string)
    field(:metadata, :map, default: %{})
    field(:actor, :string)
    field(:correlation_id, :string)
    field(:inserted_at, :utc_datetime_usec, default: nil)
  end

  def event_types, do: @event_types

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :id,
      :event_type,
      :timestamp,
      :sequence,
      :ca_id,
      :metadata,
      :actor,
      :correlation_id
    ])
    |> validate_required([:id, :event_type, :timestamp, :sequence, :ca_id])
    |> validate_number(:sequence, greater_than: 0)
    |> unique_constraint([:ca_id, :sequence], name: :pki_events_ca_sequence_unique)
  end

  def from_pki_event(event) when is_map(event) do
    %__MODULE__{
      id: event.id,
      event_type: event.event_type,
      timestamp: event.timestamp,
      sequence: event.sequence,
      ca_id: event.ca_id,
      metadata: Map.get(event, :metadata, %{}),
      actor: Map.get(event, :actor),
      correlation_id: Map.get(event, :correlation_id)
    }
  end

  def to_pki_event(%__MODULE__{} = event) do
    %{
      id: event.id,
      type: :pki_event,
      event_type: event.event_type,
      timestamp: event.timestamp,
      sequence: event.sequence,
      ca_id: event.ca_id,
      metadata: atomize_known_metadata_keys(event.metadata || %{}),
      actor: event.actor,
      correlation_id: event.correlation_id
    }
  end

  defp atomize_known_metadata_keys(metadata) when is_map(metadata) do
    Map.new(metadata, fn
      {key, value} when is_binary(key) ->
        if MapSet.member?(@metadata_atom_keys, key) do
          {String.to_existing_atom(key), value}
        else
          {key, value}
        end

      {key, value} ->
        {key, value}
    end)
  end

  defp atomize_known_metadata_keys(metadata), do: metadata
end
