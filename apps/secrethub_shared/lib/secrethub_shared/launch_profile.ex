defmodule SecretHub.Shared.LaunchProfile do
  @moduledoc "Runtime availability of the supported single-operator launch features."

  def enabled?(feature, app \\ :secrethub_core) do
    features = Application.get_env(app, :enabled_features, [:static_secrets, :client_auth_pki])

    Application.get_env(app, :launch_profile) != :single_operator or
      (is_list(features) and feature in features)
  end

  def check(feature, app \\ :secrethub_core) do
    if enabled?(feature, app), do: :ok, else: {:error, :feature_unavailable}
  end
end
