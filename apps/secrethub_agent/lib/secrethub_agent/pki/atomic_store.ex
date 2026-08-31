defmodule SecretHub.Agent.PKI.AtomicStore do
  @moduledoc """
  Manages atomic directory structure and symlink rotation for trust bundles.

  Directory layout:
  <base_dir>/
    generations/
      <gen>/
        ca.crt
        crl.pem
        manifest.json
    current -> generations/<gen>
  """

  require Logger

  @generations_to_keep 4

  @doc """
  Atomically writes a validated trust bundle to disk and updates the `current` symlink.
  """
  @spec write_bundle(Path.t(), map(), keyword()) ::
          {:ok, %{current_path: Path.t(), generation: pos_integer(), manifest: map()}}
          | {:error, term()}
  def write_bundle(base_dir, bundle, opts \\ []) when is_map(bundle) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    generation = bundle["generation"] || bundle[:generation]
    generations_dir = Path.join(base_dir, "generations")
    gen_dir = Path.join(generations_dir, to_string(generation))

    with :ok <- File.mkdir_p(gen_dir),
         :ok <-
           write_file(
             Path.join(gen_dir, "ca.crt"),
             bundle["ca_bundle_pem"] || bundle[:ca_bundle_pem]
           ),
         :ok <- write_file(Path.join(gen_dir, "crl.pem"), bundle["crl_pem"] || bundle[:crl_pem]),
         {:ok, manifest} <- write_manifest(gen_dir, bundle, now),
         :ok <- switch_symlink(base_dir, generation),
         :ok <- prune_old_generations(base_dir, generations_dir) do
      {:ok,
       %{
         current_path: Path.join(base_dir, "current"),
         generation: generation,
         manifest: manifest
       }}
    end
  end

  @doc """
  Reads the current manifest from `<base_dir>/current/manifest.json`.
  """
  @spec read_current_manifest(Path.t()) :: {:ok, map()} | {:error, :not_found | term()}
  def read_current_manifest(base_dir) do
    manifest_path = Path.join([base_dir, "current", "manifest.json"])

    case File.read(manifest_path) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, manifest} -> {:ok, manifest}
          {:error, reason} -> {:error, {:invalid_manifest_json, reason}}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Helpers

  defp write_file(path, content) when is_binary(content) do
    with :ok <- File.write(path, content) do
      File.chmod(path, 0o644)
    end
  end

  defp write_manifest(gen_dir, bundle, now) do
    manifest = %{
      "schema_version" => bundle["schema_version"] || bundle[:schema_version] || 1,
      "authority" => bundle["authority"] || bundle[:authority] || "client-auth",
      "generation" => bundle["generation"] || bundle[:generation],
      "crl_number" => bundle["crl_number"] || bundle[:crl_number],
      "ca_fingerprint" => bundle["ca_fingerprint"] || bundle[:ca_fingerprint],
      "crl_der_sha256" => bundle["crl_der_sha256"] || bundle[:crl_der_sha256],
      "bundle_sha256" => bundle["bundle_sha256"] || bundle[:bundle_sha256],
      "this_update" => bundle["this_update"] || bundle[:this_update],
      "next_update" => bundle["next_update"] || bundle[:next_update],
      "applied_at" => DateTime.to_iso8601(now)
    }

    manifest_path = Path.join(gen_dir, "manifest.json")

    case Jason.encode(manifest, pretty: true) do
      {:ok, json} ->
        with :ok <- File.write(manifest_path, json),
             :ok <- File.chmod(manifest_path, 0o644) do
          {:ok, manifest}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp switch_symlink(base_dir, generation) do
    target = Path.join("generations", to_string(generation))
    tmp_symlink = Path.join(base_dir, "current.tmp")
    current_symlink = Path.join(base_dir, "current")

    # Clean up any leftover temporary symlink
    File.rm(tmp_symlink)

    with :ok <- File.ln_s(target, tmp_symlink),
         :ok <- File.rename(tmp_symlink, current_symlink) do
      :ok
    else
      {:error, reason} ->
        File.rm(tmp_symlink)
        {:error, reason}
    end
  end

  defp prune_old_generations(base_dir, generations_dir) do
    current_symlink = Path.join(base_dir, "current")

    current_target_entry =
      case File.read_link(current_symlink) do
        {:ok, target} -> Path.basename(target)
        _ -> nil
      end

    case File.ls(generations_dir) do
      {:ok, entries} ->
        sorted_generations =
          entries
          |> Enum.flat_map(fn entry ->
            case Integer.parse(entry) do
              {gen, ""} -> [{gen, entry}]
              _ -> []
            end
          end)
          |> Enum.sort_by(fn {gen, _} -> gen end, :desc)

        # Keep top @generations_to_keep AND ensure current_target_entry is never pruned
        to_prune =
          sorted_generations
          |> Enum.drop(@generations_to_keep)
          |> Enum.reject(fn {_gen, entry} -> entry == current_target_entry end)

        for {_gen, entry} <- to_prune do
          path = Path.join(generations_dir, entry)
          File.rm_rf(path)
        end

        :ok

      {:error, :enoent} ->
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end
end
