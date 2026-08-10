defmodule SecretHub.Human.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    Supervisor.start_link(children(), strategy: :one_for_one, name: SecretHub.Human.Supervisor)
  end

  @doc false
  def children(opts \\ []) do
    if Keyword.get(opts, :enabled, Application.get_env(:secrethub_human, :enabled, true)) do
      [
        SecretHub.Human.Repo,
        {Phoenix.PubSub, name: SecretHub.Human.PubSub},
        SecretHub.HumanWeb.Endpoint
      ]
    else
      []
    end
  end

  @impl true
  def config_change(changed, _new, removed) do
    SecretHub.HumanWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
