defmodule SecretHub.Human.RuntimeConfig do
  alias SecretHub.Shared.RuntimeConfig
  @moduledoc "Strict configuration for explicit co-hosted Human deployment."
  def enabled?, do: boolean!("HUMAN_ENABLED", false)

  def boolean!(name, default) do
    case System.get_env(name) do
      nil -> default
      "true" -> true
      "false" -> false
      _ -> raise ArgumentError, "#{name}: invalid_boolean"
    end
  end

  def bounded!(name, default, range) do
    case Integer.parse(System.get_env(name) || to_string(default)) do
      {value, ""} ->
        if value in range, do: value, else: raise(ArgumentError, "#{name}: out_of_range")

      _ ->
        raise ArgumentError, "#{name}: invalid_integer"
    end
  end

  def database!(human_url, core_url) do
    human =
      Ecto.Repo.Supervisor.parse_url(RuntimeConfig.database_url!(human_url))

    core = Ecto.Repo.Supervisor.parse_url(core_url)

    if human[:database] == core[:database] or human[:username] == core[:username],
      do:
        raise(ArgumentError, "HUMAN_DATABASE_URL: independent_database_and_credentials_required")

    human_url
  end

  def key!(human, core) do
    if byte_size(human) < 64 or human == core or String.starts_with?(human, "build-only"),
      do: raise(ArgumentError, "HUMAN_SECRET_KEY_BASE: independent_key_required")

    human
  end
end
