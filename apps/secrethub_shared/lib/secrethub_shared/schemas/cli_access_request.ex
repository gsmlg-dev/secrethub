defmodule SecretHub.Shared.Schemas.CliAccessRequest do
  @moduledoc """
  Pending CLI access request for browser-approved CLI login.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses [:pending, :approved, :rejected, :consumed, :expired, :revoked]

  @type t :: %__MODULE__{}

  schema "cli_access_requests" do
    field(:request_id, :binary_id)
    field(:user_code, :string)
    field(:status, Ecto.Enum, values: @statuses, default: :pending)
    field(:role_id, :binary_id)

    field(:source_ip, :string)
    field(:metadata, :map, default: %{})

    field(:approved_by, :string)
    field(:approved_at, :utc_datetime)
    field(:rejected_by, :string)
    field(:rejected_at, :utc_datetime)
    field(:revoked_by, :string)
    field(:revoked_at, :utc_datetime)
    field(:consumed_at, :utc_datetime)
    field(:expires_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  def statuses, do: @statuses

  def changeset(request, attrs) do
    request
    |> cast(attrs, [
      :request_id,
      :user_code,
      :status,
      :role_id,
      :source_ip,
      :metadata,
      :approved_by,
      :approved_at,
      :rejected_by,
      :rejected_at,
      :revoked_by,
      :revoked_at,
      :consumed_at,
      :expires_at
    ])
    |> validate_required([:request_id, :user_code, :status, :expires_at])
    |> validate_length(:user_code, is: 6)
    |> unique_constraint(:request_id)
    |> unique_constraint(:user_code)
  end
end
