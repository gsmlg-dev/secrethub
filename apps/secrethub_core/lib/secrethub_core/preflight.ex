defmodule SecretHub.Core.Preflight do
  @moduledoc "Read-only, redacted release checks. Migrations remain a separate explicit step."

  alias SecretHub.Core.{Audit.SigningKeys, Repo}

  def run do
    Application.load(:secrethub_core)
    Application.load(:secrethub_web)

    schema =
      try do
        case Ecto.Migrator.with_repo(Repo, fn repo -> schema_supported?(repo) end) do
          {:ok, result, _} -> result
          _ -> false
        end
      rescue
        _ -> false
      catch
        _, _ -> false
      end

    checks = Map.put(runtime_checks(), :database_schema, schema)
    passed = Enum.all?(checks, fn {_, passed} -> passed end)
    IO.puts(Jason.encode!(%{role: "core", passed: passed, checks: checks}))
    if passed, do: :ok, else: System.stop(1)
  end

  def runtime_checks do
    config = Application.get_all_env(:secrethub_core)
    endpoint = Application.get_env(:secrethub_web, SecretHub.Web.Endpoint, [])
    machine = Application.get_env(:secrethub_web, SecretHub.Web.MachineEndpoint, [])
    agent = Application.get_env(:secrethub_web, SecretHub.Web.AgentEndpoint, [])

    %{
      role: Keyword.get(config, :launch_profile) == :single_operator,
      audit_signing_key: match?({:ok, %{version: 2}}, SigningKeys.active(config)),
      database_input:
        is_binary(Keyword.get(Application.get_env(:secrethub_core, Repo, []), :url)),
      management_origin: endpoint[:url][:scheme] == "https",
      management_transport:
        endpoint[:http][:ip] != {0, 0, 0, 0} and endpoint[:trusted_proxy_ips] not in [nil, []],
      machine_listener: machine[:server] == true,
      agent_mtls: agent[:server] == true and tls_files_readable?(agent[:https]),
      human_disabled: not Application.get_env(:secrethub_human, :enabled, false),
      features: Keyword.get(config, :enabled_features) == [:static_secrets, :client_auth_pki],
      temporary_directory: writable_tmp?()
    }
  rescue
    _ -> %{runtime_configuration: false}
  end

  def schema_supported?(repo \\ Repo) do
    expected =
      :secrethub_core
      |> Application.app_dir("priv/repo/migrations")
      |> Path.join("*.exs")
      |> Path.wildcard()
      |> Enum.map(fn path ->
        path |> Path.basename() |> String.split("_", parts: 2) |> hd() |> String.to_integer()
      end)
      |> MapSet.new()

    case repo.query("SELECT version FROM schema_migrations", [], timeout: 5000) do
      {:ok, %{rows: rows}} -> MapSet.new(List.flatten(rows)) == expected
      _ -> false
    end
  rescue
    _ -> false
  end

  defp tls_files_readable?(https) when is_list(https) do
    transport = get_in(https, [:thousand_island_options, :transport_options]) || []

    paths = [https[:certfile], https[:keyfile], transport[:cacertfile]]

    Enum.all?(paths, fn path ->
      case path && File.open(path, [:read]) do
        {:ok, file} ->
          File.close(file)
          true

        _ ->
          false
      end
    end) and transport[:verify] == :verify_peer and transport[:fail_if_no_peer_cert] == true
  end

  defp tls_files_readable?(_), do: false

  defp writable_tmp? do
    case System.tmp_dir() do
      nil ->
        false

      path ->
        probe = Path.join(path, ".secrethub-preflight-" <> Ecto.UUID.generate())

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
end
