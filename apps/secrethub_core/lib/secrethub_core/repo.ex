defmodule SecretHub.Core.Repo do
  use Ecto.Repo,
    otp_app: :secrethub_core,
    adapter: Ecto.Adapters.Postgres
end
