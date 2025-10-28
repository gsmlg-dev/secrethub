defmodule SecretHub.Core.Templates do
  @moduledoc """
  Context for managing templates and sinks.

  Provides CRUD operations and business logic for:
  - Template definitions
  - Sink configurations
  - Sink write history
  """

  import Ecto.Query, warn: false
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Template, Sink, SinkWriteHistory}

  ## Template Functions

  @doc """
  List all templates, optionally filtered by agent_id or status.
  """
  def list_templates(opts \\ []) do
    query = from(t in Template, order_by: [desc: t.inserted_at])

    query =
      case Keyword.get(opts, :agent_id) do
        nil -> query
        agent_id -> from(t in query, where: t.agent_id == ^agent_id)
      end

    query =
      case Keyword.get(opts, :status) do
        nil -> query
        status -> from(t in query, where: t.status == ^status)
      end

    query =
      if Keyword.get(opts, :preload_sinks), do: from(t in query, preload: [:sinks]), else: query

    Repo.all(query)
  end

  @doc """
  Get a single template by ID.
  """
  def get_template(id, opts \\ []) do
    query = from(t in Template, where: t.id == ^id)

    query =
      if Keyword.get(opts, :preload_sinks), do: from(t in query, preload: [:sinks]), else: query

    Repo.one(query)
  end

  @doc """
  Get a template by name.
  """
  def get_template_by_name(name) do
    Repo.get_by(Template, name: name)
  end

  @doc """
  Create a new template.
  """
  def create_template(attrs) do
    %Template{}
    |> Template.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a template.
  """
  def update_template(%Template{} = template, attrs) do
    template
    |> Template.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a template (also deletes associated sinks due to cascade).
  """
  def delete_template(%Template{} = template) do
    Repo.delete(template)
  end

  @doc """
  Archive a template (soft delete).
  """
  def archive_template(%Template{} = template) do
    update_template(template, %{status: "archived"})
  end

  ## Sink Functions

  @doc """
  List all sinks, optionally filtered by template_id or status.
  """
  def list_sinks(opts \\ []) do
    query = from(s in Sink, order_by: [desc: s.inserted_at])

    query =
      case Keyword.get(opts, :template_id) do
        nil -> query
        template_id -> from(s in query, where: s.template_id == ^template_id)
      end

    query =
      case Keyword.get(opts, :status) do
        nil -> query
        status -> from(s in query, where: s.status == ^status)
      end

    query =
      if Keyword.get(opts, :preload_template),
        do: from(s in query, preload: [:template]),
        else: query

    Repo.all(query)
  end

  @doc """
  Get a single sink by ID.
  """
  def get_sink(id, opts \\ []) do
    query = from(s in Sink, where: s.id == ^id)

    query =
      if Keyword.get(opts, :preload_template),
        do: from(s in query, preload: [:template]),
        else: query

    Repo.one(query)
  end

  @doc """
  Create a new sink.
  """
  def create_sink(attrs) do
    %Sink{}
    |> Sink.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a sink.
  """
  def update_sink(%Sink{} = sink, attrs) do
    sink
    |> Sink.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a sink.
  """
  def delete_sink(%Sink{} = sink) do
    Repo.delete(sink)
  end

  @doc """
  Update sink write status after a write operation.
  """
  def update_sink_write_status(%Sink{} = sink, status, error \\ nil) do
    attrs = %{
      last_write_at: DateTime.utc_now(),
      last_write_status: status,
      last_write_error: error
    }

    update_sink(sink, attrs)
  end

  ## Sink Write History Functions

  @doc """
  List write history for a sink.
  """
  def list_sink_write_history(sink_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(h in SinkWriteHistory,
      where: h.sink_id == ^sink_id,
      order_by: [desc: h.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Create a write history entry.
  """
  def create_write_history(attrs) do
    %SinkWriteHistory{}
    |> SinkWriteHistory.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get statistics for a template (number of sinks, last write times, etc.).
  """
  def get_template_stats(template_id) do
    sinks = list_sinks(template_id: template_id)

    %{
      total_sinks: length(sinks),
      active_sinks: Enum.count(sinks, &(&1.status == "active")),
      last_write: get_most_recent_write(sinks),
      success_rate: calculate_success_rate(sinks)
    }
  end

  defp get_most_recent_write(sinks) do
    sinks
    |> Enum.map(& &1.last_write_at)
    |> Enum.reject(&is_nil/1)
    |> Enum.max(DateTime, fn -> nil end)
  end

  defp calculate_success_rate(sinks) do
    total = length(sinks)

    if total == 0 do
      0.0
    else
      successful = Enum.count(sinks, &(&1.last_write_status == "success"))
      Float.round(successful / total * 100, 2)
    end
  end
end
