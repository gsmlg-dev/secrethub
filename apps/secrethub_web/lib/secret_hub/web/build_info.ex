defmodule SecretHub.Web.BuildInfo do
  @moduledoc "Build provenance captured at compilation, available in packaged releases."

  @build_info Application.compile_env(:secrethub_web, :build_info)
  @built_at (if @build_info.built_at || @build_info.source_date do
               @build_info.built_at
             else
               DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
             end)

  @doc "Returns the application version, environment, revision, and build/source timestamps."
  def info do
    @build_info
    |> Map.put(:built_at, @built_at)
    |> Map.put(:version, to_string(Application.spec(:secrethub_web, :vsn)))
  end
end
