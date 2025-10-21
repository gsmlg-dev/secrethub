defmodule SecretHub.Agent.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # WebSocket connection to Core service
      {SecretHub.Agent.Connection,
       agent_id: Application.get_env(:secrethub_agent, :agent_id, "agent-dev-01"),
       core_url: Application.get_env(:secrethub_agent, :core_url, "ws://localhost:4000"),
       cert_path: Application.get_env(:secrethub_agent, :cert_path),
       key_path: Application.get_env(:secrethub_agent, :key_path),
       ca_path: Application.get_env(:secrethub_agent, :ca_path)}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: SecretHub.Agent.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
