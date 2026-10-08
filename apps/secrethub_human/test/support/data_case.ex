defmodule SecretHub.Human.DataCase do
  alias Ecto.Adapters.SQL.Sandbox
  @moduledoc false
  use ExUnit.CaseTemplate

  using do
    quote do
      alias SecretHub.Human.Repo
      import Ecto.Query
    end
  end

  setup tags do
    owner = Sandbox.start_owner!(SecretHub.Human.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(owner) end)
    :ok
  end
end
