import Config

# Dedicated runtime config for standalone Agent releases. Packaged Core uses
# config/core_runtime.exs for DB/Phoenix secrets; config/runtime.exs is the source-execution compatibility entrypoint.
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
