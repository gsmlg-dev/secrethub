defmodule SecretHub.Human.Repo do
  use Ecto.Repo,
    otp_app: :secrethub_human,
    adapter: Ecto.Adapters.Postgres
end
