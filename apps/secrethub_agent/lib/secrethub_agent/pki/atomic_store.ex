defmodule SecretHub.Agent.PKI.AtomicStore do
  @moduledoc """
  Manages atomic directory structure and symlink rotation for trust bundles.

  Publication sequence:
  1. generations/.tmp-<uuid>/
       ca.crt
       crl.pem
       manifest.json
         ↓ validate written bytes
         ↓ fsync files and temporary directory
  2. rename .tmp-<uuid> → generations/<generation> (or reuse existing immutable match)
         ↓ fsync generations/
  3. create current.tmp symlink
  4. rename current.tmp → current
         ↓ fsync base directory
  5. best-effort pruning
  """

  require Logger

  @generations_to_keep 4

  @doc """
  Atomically writes a validated trust bundle to disk following the strict publication sequence.
  """
  @spec write_bundle(Path.t(), map(), keyword()) ::
          {:ok, %{current_path: Path.t(), generation: pos_integer(), manifest: map()}}
          | {:error, term()}
  def write_bundle(base_dir, bundle, opts \\ []) when is_map(bundle) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    generation = bundle["generation"] || bundle[:generation]
    generations_dir = Path.join(base_dir, "generations")
    gen_dir = Path.join(generations_dir, to_string(generation))

    ca_pem = bundle["ca_bundle_pem"] || bundle[:ca_bundle_pem]
    crl_pem = bundle["crl_pem"] || bundle[:crl_pem]

    tmp_id = ".tmp-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    tmp_dir = Path.join(generations_dir, tmp_id)

    with :ok <- File.mkdir_p(generations_dir),
         :ok <- File.mkdir_p(tmp_dir),
         :ok <- write_and_fsync_file(Path.join(tmp_dir, "ca.crt"), ca_pem),
         :ok <- write_and_fsync_file(Path.join(tmp_dir, "crl.pem"), crl_pem),
         {:ok, manifest} <- write_and_fsync_manifest(tmp_dir, bundle, now),
         :ok <- fsync_dir(tmp_dir),
         :ok <- publish_generation_dir(tmp_dir, gen_dir, manifest),
         :ok <- fsync_dir(generations_dir),
         :ok <- switch_symlink(base_dir, generation),
         :ok <- write_and_fsync_watermark(base_dir, manifest),
         :ok <- fsync_dir(base_dir) do
      # Best effort pruning: log warning on error but do not fail published bundle
      _ = prune_old_generations(base_dir, generations_dir)

      {:ok,
       %{
         current_path: Path.join(base_dir, "current"),
         generation: generation,
         manifest: manifest
       }}
    else
      {:error, reason} ->
        File.rm_rf(tmp_dir)
        {:error, reason}
    end
  end

  @doc """
  Reads the persistent watermark from `<base_dir>/watermark.json`.
  """
  @spec read_persistent_watermark(Path.t()) :: {:ok, map()} | {:error, :not_found | term()}
  def read_persistent_watermark(base_dir) do
    wm_path = Path.join(base_dir, "watermark.json")

    case File.read(wm_path) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, wm} -> {:ok, wm}
          {:error, reason} -> {:error, {:invalid_watermark_json, reason}}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
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

  defp write_and_fsync_watermark(base_dir, manifest) do
    watermark = %{
      "highest_seen_generation" => manifest["generation"],
      "highest_seen_crl_number" => manifest["crl_number"],
      "pinned_ca_fingerprint" => manifest["ca_fingerprint"],
      "last_bundle_sha256" => manifest["bundle_sha256"],
      "updated_at" => manifest["applied_at"]
    }

    tmp_id = ".watermark.tmp-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    tmp_path = Path.join(base_dir, tmp_id)
    target_path = Path.join(base_dir, "watermark.json")

    case Jason.encode(watermark, pretty: true) do
      {:ok, json} ->
        with :ok <- write_and_fsync_file(tmp_path, json),
             :ok <- File.rename(tmp_path, target_path) do
          :ok
        else
          {:error, reason} ->
            File.rm(tmp_path)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp write_and_fsync_file(path, content) when is_binary(content) do
    with :ok <- File.write(path, content),
         :ok <- File.chmod(path, 0o644),
         {:ok, read_content} when read_content == content <- File.read(path),
         :ok <- fsync_file(path) do
      :ok
    else
      {:ok, _mismatch} -> {:error, {:file_content_mismatch, path}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp write_and_fsync_manifest(gen_dir, bundle, now) do
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
        with :ok <- write_and_fsync_file(manifest_path, json) do
          {:ok, manifest}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp publish_generation_dir(tmp_dir, gen_dir, manifest) do
    if File.exists?(gen_dir) do
      # If gen_dir already exists, thoroughly verify stored ca.crt, crl.pem and manifest
      mf_path = Path.join(gen_dir, "manifest.json")

      with {:ok, mf_json} <- File.read(mf_path),
           {:ok, existing_manifest} <- Jason.decode(mf_json),
           true <- existing_manifest["bundle_sha256"] == manifest["bundle_sha256"],
           {:ok, _validated} <- SecretHub.Agent.PKI.BundleValidator.validate_disk_bundle(gen_dir) do
        File.rm_rf(tmp_dir)
        :ok
      else
        _ ->
          File.rm_rf(tmp_dir)
          {:error, :corrupted_existing_generation}
      end
    else
      case File.rename(tmp_dir, gen_dir) do
        :ok ->
          :ok

        {:error, reason} ->
          File.rm_rf(tmp_dir)
          {:error, reason}
      end
    end
  end

  defp switch_symlink(base_dir, generation) do
    target = Path.join("generations", to_string(generation))
    tmp_symlink = Path.join(base_dir, "current.tmp")
    current_symlink = Path.join(base_dir, "current")

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

  defp fsync_file(path) do
    case :file.open(to_charlist(path), [:read, :write, :raw]) do
      {:ok, fd} ->
        res = :file.sync(fd)
        :file.close(fd)
        res

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fsync_dir(dir_path) do
    case :file.open(to_charlist(dir_path), [:read, :raw]) do
      {:ok, fd} ->
        res = :file.sync(fd)
        :file.close(fd)
        res

      {:error, _} ->
        # Directory fsync may be unsupported on some OS/filesystems, safe fallback
        :ok
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
