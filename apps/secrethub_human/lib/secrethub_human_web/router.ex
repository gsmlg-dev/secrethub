defmodule SecretHub.HumanWeb.Router do
  use SecretHub.HumanWeb, :router

  pipeline :api do
    plug(:accepts, ["json"])
  end

  scope "/", SecretHub.HumanWeb do
    pipe_through(:api)

    get("/", PageController, :index)
    get("/health", HealthController, :show)
  end
end
