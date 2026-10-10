import Config

# Capture provenance while building, before a release loses access to Git.
project_root = Path.expand("..", __DIR__)
git = System.find_executable("git")

nonempty = fn
  nil -> nil
  value -> if String.trim(value) == "", do: nil, else: String.trim(value)
end

git_value = fn args ->
  if git && File.exists?(Path.join(project_root, ".git")) do
    case System.cmd(git, args, cd: project_root, stderr_to_stdout: true) do
      {value, 0} -> nonempty.(value)
      {_error, _status} -> nil
    end
  end
end

git_sha = nonempty.(System.get_env("SECRET_HUB_GIT_SHA")) || git_value.(["rev-parse", "HEAD"])

git_ref =
  nonempty.(System.get_env("SECRET_HUB_GIT_REF")) ||
    git_value.(["symbolic-ref", "--quiet", "--short", "HEAD"]) ||
    git_value.(["describe", "--tags", "--exact-match", "HEAD"]) || git_sha

# Development shells may provide Nix's generic reproducibility epoch.
source_date =
  with true <- config_env() != :dev,
       epoch when is_binary(epoch) <- System.get_env("SOURCE_DATE_EPOCH"),
       {seconds, ""} <- Integer.parse(epoch),
       {:ok, datetime} <- DateTime.from_unix(seconds) do
    DateTime.to_iso8601(datetime)
  else
    _ -> nil
  end

config :secrethub_web, :build_info, %{
  environment: config_env(),
  git_ref: git_ref,
  git_sha: git_sha,
  built_at: nonempty.(System.get_env("SECRET_HUB_BUILD_TIME")),
  source_date: source_date
}
