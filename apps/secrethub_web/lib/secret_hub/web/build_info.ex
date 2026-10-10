defmodule SecretHub.Web.BuildInfo do
  @moduledoc "Build provenance captured at compilation, available in packaged releases."

  @build_info Application.get_all_env(:secrethub_web) |> Keyword.fetch!(:build_info)
  @built_at (if @build_info.built_at || @build_info.source_date do
               @build_info.built_at
             else
               DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
             end)

  # Git and build variables can change without a configuration file changing.
  @doc false
  def __mix_recompile__? do
    @build_info != Application.get_env(:secrethub_web, :build_info)
  end

  @doc "Returns the application version, environment, revision, and build/source timestamps."
  def info do
    @build_info
    |> Map.put(:built_at, @built_at)
    |> Map.put(:version, to_string(Application.spec(:secrethub_web, :vsn)))
  end
end
