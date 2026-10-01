defmodule SecretHub.Agent.Preflight do
  @moduledoc "Redacted checks run as the real Agent service UID. No Core DB inputs are read."

  import Bitwise
  alias SecretHub.Agent.{HostKey, IdentityStore}

  def checks do
    config = Application.get_all_env(:secrethub_agent)
    paths = Keyword.get(Keyword.get(config, :enrollment_opts, []), :paths, [])
    state_dir = Keyword.get(config, :state_dir)

    %{
      role: Keyword.get(config, :launch_profile) == :single_operator,
      host_key: secure_host_key?(paths),
      state_directory: writable_directory?(state_dir),
      socket_directory: writable_directory?(directory(Keyword.get(config, :socket_path))),
      bundle_directory: writable_directory?(Keyword.get(config, :client_auth_bundle_dir)),
      identity: valid_identity?(state_dir)
    }
  end

  def startup_validate do
    if Application.get_env(:secrethub_agent, :launch_profile) == :single_operator do
      if Enum.all?(checks(), fn {_, passed} -> passed end),
        do: :ok,
        else: {:error, :agent_preflight_failed}
    else
      :ok
    end
  end

  def run do
    Application.load(:secrethub_agent)
    checks = checks()
    passed = Enum.all?(checks, fn {_, passed} -> passed end)
    IO.puts(Jason.encode!(%{role: "agent", passed: passed, checks: checks}))
    if passed, do: :ok, else: System.stop(1)
  end

  defp secure_host_key?(paths) do
    Enum.all?(paths, fn {_algorithm, path} ->
      case File.stat(path) do
        {:ok, %{type: :regular, mode: mode}} -> (mode &&& 0o007) == 0
        _ -> false
      end
    end) and match?({:ok, _}, HostKey.discover(paths: paths))
  end

  defp writable_directory?(nil), do: false

  defp writable_directory?(path) do
    if String.starts_with?(Path.expand(path), "/nix/store/") do
      false
    else
      probe =
        Path.join(
          path,
          ".preflight-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
        )

      case File.open(probe, [:write, :exclusive]) do
        {:ok, file} ->
          File.close(file)
          File.rm(probe)
          true

        _ ->
          false
      end
    end
  end

  defp directory(nil), do: nil
  defp directory(path), do: Path.dirname(path)
  defp valid_identity?(nil), do: false

  defp valid_identity?(path) do
    # A completely fresh directory may enroll. Any partially existing identity is blocking.
    case IdentityStore.load(path) do
      {:ok, _} ->
        true

      {:error, :missing_trusted_material} ->
        Enum.all?(
          ~w(agent-cert.pem agent-key.pem ca-chain.pem connect-info.json identity.json),
          fn name ->
            not File.exists?(Path.join(path, name))
          end
        )

      _ ->
        false
    end
  end
end
