fail = fn message ->
  IO.puts(:stderr, message)
  System.halt(1)
end

[release_directory, expected_version] =
  case System.argv() do
    [directory, version] ->
      [directory, version]

    _ ->
      fail.(
        "Usage: elixir scripts/verify_release_versions.exs RELEASE_DIRECTORY EXPECTED_VERSION"
      )
  end

apps = Path.wildcard(Path.join(release_directory, "lib/secrethub_*/ebin/secrethub_*.app"))

if apps == [], do: fail.("No SecretHub applications found in #{release_directory}")

Enum.each(apps, fn path ->
  version =
    case :file.consult(String.to_charlist(path)) do
      {:ok, [{:application, _name, properties}]} when is_list(properties) ->
        properties |> Keyword.get(:vsn) |> to_string()

      result ->
        fail.("Cannot read application specification #{path}: #{inspect(result)}")
    end

  if version != expected_version do
    fail.(
      "Version mismatch in #{path}: found #{inspect(version)}, expected #{inspect(expected_version)}"
    )
  end
end)

IO.puts(
  "Verified #{length(apps)} SecretHub applications at #{expected_version} in #{release_directory}"
)
