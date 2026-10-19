defmodule SecretHub.Agent.SSH.Supervisor do
  @moduledoc "Opt-in independent public lookup and signing listeners."
  use Supervisor
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(opts) do
    tasks = SecretHub.Agent.SSH.Tasks

    children =
      [{Task.Supervisor, name: tasks, max_children: 40}] ++
        Enum.flat_map([:lookup, :signing], &listener(&1, opts, tasks))

    Supervisor.init(children, strategy: :one_for_all)
  end

  defp listener(kind, opts, tasks) do
    {enabled, path, group} = settings(kind)

    if Keyword.get(opts, enabled, false) do
      [
        {SecretHub.Agent.SSH.Server,
         kind: kind,
         path: Keyword.fetch!(opts, path),
         group: Keyword.fetch!(opts, group),
         task_supervisor: tasks}
      ]
    else
      []
    end
  end

  defp settings(:lookup),
    do: {:ssh_lookup_enabled, :ssh_lookup_socket_path, :ssh_lookup_socket_group}

  defp settings(:signing),
    do: {:ssh_signing_enabled, :ssh_signing_socket_path, :ssh_signing_socket_group}
end
