defmodule SecretHub.HumanWeb.ConnCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint SecretHub.HumanWeb.Endpoint

      import Phoenix.ConnTest
      import Plug.Conn
    end
  end

  setup do
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end
end
