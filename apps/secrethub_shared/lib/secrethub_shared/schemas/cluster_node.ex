defmodule SecretHub.Shared.Schemas.ClusterNode do
  @moduledoc """
  Schema for tracking individual nodes in a SecretHub cluster.

  In HA deployments, multiple SecretHub Core nodes run simultaneously.
  This schema tracks the state of each node for coordination and monitoring.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "cluster_nodes" do
    field(:node_id, :string)
    field(:hostname, :string)
    field(:status, :string, default: "starting")
    field(:leader, :boolean, default: false)
    field(:last_seen_at, :utc_datetime)
    field(:started_at, :utc_datetime)
    field(:sealed, :boolean, default: true)
    field(:initialized, :boolean, default: false)
    field(:version, :string)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(node, attrs) do
    node
    |> cast(attrs, [
      :node_id,
      :hostname,
      :status,
      :leader,
      :last_seen_at,
      :started_at,
      :sealed,
      :initialized,
      :version,
      :metadata
    ])
    |> validate_required([:node_id, :hostname, :status, :last_seen_at, :started_at])
    |> validate_inclusion(:status, [
      "starting",
      "initializing",
      "sealed",
      "unsealed",
      "shutdown"
    ])
    |> unique_constraint(:node_id)
  end
end
