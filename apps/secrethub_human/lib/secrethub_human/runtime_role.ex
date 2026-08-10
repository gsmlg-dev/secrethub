defmodule SecretHub.Human.RuntimeRole do
  @moduledoc false

  @roles %{
    "all" => :all,
    "core" => :core,
    "human" => :human,
    "agent" => :agent
  }

  def resolve!(nil, :prod), do: :core
  def resolve!(nil, _env), do: :all

  def resolve!(role, _env) do
    Map.get(@roles, role) ||
      raise ArgumentError,
            "invalid SECRETHUB_ROLE #{inspect(role)}; expected all, core, human, or agent"
  end
end
