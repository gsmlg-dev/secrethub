defmodule SecretHub.Core.Secrets do
  @moduledoc """
  Core service for secret management operations.

  Provides CRUD operations for secrets with encryption, policy-based access control,
  and rotation scheduling.
  """

  require Logger
  import Ecto.Query

  alias Ecto.{Changeset, Multi}
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Secret, Policy, AuditLog}

  @doc """
  Create a new secret.
  """
  def create_secret(attrs) do
    %Secret{}
    |> Secret.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an existing secret.
  """
  def update_secret(secret_id, attrs) do
    case Repo.get(Secret, secret_id) do
      nil ->
        {:error, "Secret not found"}

      secret ->
        secret
        |> Secret.changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Delete a secret.
  """
  def delete_secret(secret_id) do
    case Repo.get(Secret, secret_id) do
      nil ->
        {:error, "Secret not found"}

      secret ->
        Repo.delete(secret)
    end
  end

  @doc """
  Get a secret by ID.
  """
  def get_secret(secret_id) do
    case Repo.get(Secret, secret_id) do
      nil -> {:error, "Secret not found"}
      secret -> {:ok, secret}
    end
  end

  @doc """
  List all secrets with optional filtering.
  """
  def list_secrets(filters \\ %{}) do
    query = from(s in Secret, preload: [:policies])

    query =
      Enum.reduce(filters, query, fn
        {:secret_type, type}, q -> where(q, [s], s.secret_type == ^type)
        {:engine_type, engine}, q -> where(q, [s], s.engine_type == ^engine)
        {:search, term}, q ->
          search_term = "%#{term}%"
          where(q, [s], ilike(s.name, ^search_term) or ilike(s.secret_path, ^search_term))
        _, q -> q
      end)

    Repo.all(query)
  end

  @doc """
  Get secret statistics.
  """
  def get_secret_stats do
    %{
      total: Repo.aggregate(Secret, :count, :id),
      static: Repo.aggregate(from(s in Secret, where: s.secret_type == :static), :count, :id),
      dynamic: Repo.aggregate(from(s in Secret, where: s.secret_type == :dynamic), :count, :id)
    }
  end
end