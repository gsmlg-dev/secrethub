import Config

# Runtime config for the standalone agent release. The core release keeps
# config/runtime.exs because it needs database and Phoenix endpoint secrets.
core_url =
  case System.get_env("SECRET_HUB_AGENT_CORE_URL") do
    value when is_binary(value) and value != "" ->
      value

    _missing ->
      raise """
      environment variable SECRET_HUB_AGENT_CORE_URL is missing.
      For example: https://secrethub.example.com
      """
  end

config :secrethub_agent, core_url: core_url
