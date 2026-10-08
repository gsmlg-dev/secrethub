defmodule SecretHub.HumanWeb.Bitwarden.ConfigController do
  alias SecretHub.HumanWeb.Endpoint
  use SecretHub.HumanWeb, :controller

  def show(conn, _) do
    base = Endpoint.url()

    json(conn, %{
      object: "config",
      version: "2026.9.1",
      server: %{name: "SecretHub", url: base},
      environment: %{
        vault: base,
        api: base <> "/api",
        identity: base <> "/identity",
        notifications: base <> "/notifications"
      },
      featureStates: %{},
      push: %{pushTechnology: 0, vapidPublicKey: nil},
      settings: %{
        disableUserRegistration:
          not Application.get_env(:secrethub_human, :signup_enabled, false),
        suppressOnboardingInterstitials: true,
        enableEmailVerification: false
      },
      communication: %{bootstrap: %{type: nil}}
    })
  end
end
