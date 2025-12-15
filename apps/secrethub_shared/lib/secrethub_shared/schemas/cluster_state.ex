defmodule SecretHub.Shared.Schemas.ClusterState do
  @moduledoc """
  Schema for global cluster state.

  Stores cluster-wide metadata such as initialization status, configuration,
  and other shared state. There should be only one record in this table.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "cluster_state" do
    field(:initialized, :boolean, default: false)
    field(:init_time, :utc_datetime)
    field(:threshold, :integer)
    field(:shares, :integer)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(state, attrs) do
    state
    |> cast(attrs, [:initialized, :init_time, :threshold, :shares, :metadata])
    |> validate_required([:initialized])
    |> validate_number(:threshold, greater_than: 0)
    |> validate_number(:shares, greater_than_or_equal_to: 1)
  end
end
