# Ensure test-only dependencies are in the code path (needed for umbrella test runs)
case Code.ensure_loaded(Mox) do
  {:module, Mox} -> :ok
  {:error, _reason} ->
    build_root = Mix.Project.build_path() |> Path.dirname()
    test_lib = Path.join([build_root, "test", "lib"])
    if File.dir?(test_lib) do
      test_lib
      |> File.ls!()
      |> Enum.each(fn lib ->
        ebin = Path.join([test_lib, lib, "ebin"])
        if File.dir?(ebin), do: Code.prepend_path(ebin)
      end)
      Code.ensure_loaded!(Mox)
    end
end

# Start Mox server for mock support
Application.ensure_all_started(:mox)

# Define Mox mocks for HTTP client
# TODO: Implement HTTPClientBehaviour and enable mocking
# Mox.defmock(SecretHub.CLI.HTTPClientMock, for: SecretHub.CLI.HTTPClientBehaviour)

# Enable test mode to prevent System.halt from killing the VM
Application.put_env(:secrethub_cli, :test_mode, true)

# Start ExUnit
ExUnit.start()
