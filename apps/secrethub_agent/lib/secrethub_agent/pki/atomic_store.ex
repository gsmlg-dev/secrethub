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

    with :ok <- ensure_secure_directory(base_dir),
         :ok <- ensure_secure_directory(generations_dir),
         :ok <- ensure_secure_directory(tmp_dir),
         :ok <- write_and_fsync_file(Path.join(tmp_dir, "ca.crt"), ca_pem),
         :ok <- write_and_fsync_file(Path.join(tmp_dir, "crl.pem"), crl_pem),
         {:ok, manifest} <- write_and_fsync_manifest(tmp_dir, bundle, now),
         :ok <- fsync_dir(tmp_dir),
         :ok <- publish_generation_dir(tmp_dir, gen_dir, manifest),
         :ok <- fsync_dir(generations_dir) do
      case write_and_fsync_watermark(base_dir, manifest, opts) do
        :ok ->
          case switch_symlink(base_dir, generation) do
            :ok ->
              sync_res =
                case Keyword.get(opts, :inject_base_dir_fsync_error) do
                  nil -> fsync_dir(base_dir)
                  injected_err -> {:error, injected_err}
                end

              case sync_res do
                :ok ->
                  # Best effort pruning: log warning on error but do not fail published bundle
                  _ = prune_old_generations(base_dir, generations_dir)

                  {:ok,
                   %{
                     current_path: Path.join(base_dir, "current"),
                     generation: generation,
                     manifest: manifest
                   }}

                {:error, reason} ->
                  {:error, {:after_current_switched, reason}}
              end

            {:error, reason} ->
              {:error, {:after_watermark_committed, reason}}
          end

        {:error, reason} ->
          File.rm_rf(tmp_dir)
          {:error, {:watermark_commit_failed, reason}}
      end
    else
      {:error, reason} ->
        File.rm_rf(tmp_dir)
        {:error, reason}
    end
  end

  @doc """
  Ensures that the directory and all ancestor path components exist,
  are genuine directories (never symlinks), and have permissions 0o750.
  """
  @spec ensure_secure_directory(Path.t()) :: :ok | {:error, term()}
  def ensure_secure_directory(dir_path) do
    normalized = normalize_system_path(dir_path)
    parts = Path.split(normalized)

    Enum.reduce_while(parts, {:ok, "/"}, fn
      "/", {:ok, _acc} ->
        {:cont, {:ok, "/"}}

      part, {:ok, current} ->
        next_path = Path.join(current, part)
        is_target? = next_path == normalized

        case File.lstat(next_path) do
          {:ok, %File.Stat{type: :symlink}} ->
            {:halt, {:error, {:symlink_directory_disallowed, next_path}}}

          {:ok, %File.Stat{type: :directory}} ->
            if is_target? do
              case set_directory_permissions(next_path) do
                :ok -> {:cont, {:ok, next_path}}
                {:error, reason} -> {:halt, {:error, reason}}
              end
            else
              {:cont, {:ok, next_path}}
            end

          {:ok, %File.Stat{type: _other}} ->
            {:halt, {:error, {:not_a_directory, next_path}}}

          {:error, :enoent} ->
            with :ok <- File.mkdir(next_path),
                 :ok <- set_directory_permissions(next_path) do
              {:cont, {:ok, next_path}}
            else
              {:error, reason} -> {:halt, {:error, reason}}
            end

          {:error, reason} ->
            {:halt, {:error, reason}}
        end
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Normalizes system paths (such as macOS /var and /tmp symlinks to /private).
  """
  @spec normalize_system_path(Path.t()) :: Path.t()
  def normalize_system_path(path) do
    abs_path = Path.expand(path)

    case :os.type() do
      {:unix, :darwin} ->
        cond do
          String.starts_with?(abs_path, "/var/") ->
            "/private" <> abs_path

          abs_path == "/var" ->
            "/private/var"

          String.starts_with?(abs_path, "/tmp/") ->
            "/private" <> abs_path

          abs_path == "/tmp" ->
            "/private/tmp"

          String.starts_with?(abs_path, "/etc/") ->
            "/private" <> abs_path

          abs_path == "/etc" ->
            "/private/etc"

          true ->
            abs_path
        end

      _ ->
        abs_path
    end
  end

  defp set_directory_permissions(dir_path) do
    case File.lstat(dir_path) do
      {:ok, %File.Stat{mode: current_mode}} ->
        setgid_bit = Bitwise.band(current_mode, 0o2000)
        target_mode = Bitwise.bor(0o750, setgid_bit)
        File.chmod(dir_path, target_mode)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @sha256_hex ~r/\A[0-9a-f]{64}\z/

  @doc """
  Decodes JSON string and strictly asserts that the root value is a map/object.
  Returns `{:ok, map}`, `{:error, :not_a_json_object}`, or `{:error, {:invalid_json, reason}}`.
  """
  @spec decode_json_object(binary()) ::
          {:ok, map()} | {:error, :not_a_json_object | {:invalid_json, term()}}
  def decode_json_object(content) when is_binary(content) do
    case Jason.decode(content) do
      {:ok, %{} = map} -> {:ok, map}
      {:ok, _other} -> {:error, :not_a_json_object}
      {:error, reason} -> {:error, {:invalid_json, reason}}
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
        with {:ok, wm} <- decode_json_object(content),
             :ok <- validate_watermark_schema(wm) do
          {:ok, wm}
        else
          {:error, :not_a_json_object} ->
            {:error, :invalid_watermark_schema}

          {:error, {:invalid_json, reason}} ->
            {:error, {:invalid_watermark_json, reason}}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_watermark_schema(wm) do
    gen = wm["highest_seen_generation"]
    crl_num = wm["highest_seen_crl_number"]
    fp = wm["pinned_ca_fingerprint"]
    hash = wm["last_bundle_sha256"]
    updated_at = wm["updated_at"]

    cond do
      not is_integer(gen) or gen < 0 ->
        {:error, :invalid_watermark_schema}

      not is_integer(crl_num) or crl_num < 0 ->
        {:error, :invalid_watermark_schema}

      not is_binary(fp) or not Regex.match?(@sha256_hex, fp) ->
        {:error, :invalid_watermark_schema}

      not is_binary(hash) or not Regex.match?(@sha256_hex, hash) ->
        {:error, :invalid_watermark_schema}

      not is_binary(updated_at) or updated_at == "" ->
        {:error, :invalid_watermark_schema}

      true ->
        :ok
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
        case decode_json_object(content) do
          {:ok, manifest} -> {:ok, manifest}
          {:error, :not_a_json_object} -> {:error, :invalid_manifest_format}
          {:error, {:invalid_json, reason}} -> {:error, {:invalid_manifest_json, reason}}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Writes or repairs the persistent watermark from validated bundle metadata.
  """
  @spec write_watermark(Path.t(), map(), keyword()) :: :ok | {:error, term()}
  def write_watermark(base_dir, validated, opts \\ []) when is_map(validated) do
    manifest = %{
      "generation" => Map.get(validated, :generation) || Map.get(validated, "generation"),
      "crl_number" => Map.get(validated, :crl_number) || Map.get(validated, "crl_number"),
      "ca_fingerprint" =>
        Map.get(validated, :ca_fingerprint) || Map.get(validated, "ca_fingerprint"),
      "bundle_sha256" =>
        Map.get(validated, :bundle_sha256) || Map.get(validated, "bundle_sha256"),
      "applied_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }

    write_and_fsync_watermark(base_dir, manifest, opts)
  end

  @doc """
  Reads the persisted observation sequence for the trust bundle from `<base_dir>/observation_sequence.json`.
  Returns `{:ok, seq}` (integer >= 0) or `{:ok, 0}` if not found.
  """
  @spec read_observation_sequence(Path.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def read_observation_sequence(base_dir) do
    path = Path.join(base_dir, "observation_sequence.json")

    case File.read(path) do
      {:ok, content} ->
        case decode_json_object(content) do
          {:ok, %{"observation_sequence" => seq}} when is_integer(seq) and seq >= 0 ->
            {:ok, seq}

          {:ok, _} ->
            {:error, :invalid_observation_sequence_schema}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :enoent} ->
        {:ok, 0}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Durably writes the observation sequence to `<base_dir>/observation_sequence.json`
  using atomic rename and directory fsync.
  """
  @spec persist_observation_sequence(Path.t(), non_neg_integer(), keyword()) ::
          :ok | {:error, term()}
  def persist_observation_sequence(base_dir, seq, _opts \\ [])
      when is_integer(seq) and seq >= 0 do
    data = %{
      "observation_sequence" => seq,
      "updated_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }

    tmp_id = ".sequence.tmp-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    tmp_path = Path.join(base_dir, tmp_id)
    target_path = Path.join(base_dir, "observation_sequence.json")

    case Jason.encode(data, pretty: true) do
      {:ok, json} ->
        with :ok <- ensure_secure_directory(base_dir),
             :ok <- write_and_fsync_file(tmp_path, json),
             :ok <- File.rename(tmp_path, target_path),
             :ok <- fsync_dir(base_dir) do
          :ok
        else
          {:error, reason} ->
            _ = File.rm(tmp_path)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Helpers

  defp write_and_fsync_watermark(base_dir, manifest, opts) do
    # Enforce monotonicity at persistence boundary before replacing watermark
    case read_persistent_watermark(base_dir) do
      {:ok, wm} ->
        wm_gen = wm["highest_seen_generation"] || 0
        wm_crl = wm["highest_seen_crl_number"] || 0
        wm_fp = wm["pinned_ca_fingerprint"]
        wm_hash = wm["last_bundle_sha256"]

        manifest_gen = manifest["generation"] || 0
        manifest_crl = manifest["crl_number"] || 0
        manifest_fp = manifest["ca_fingerprint"]
        manifest_hash = manifest["bundle_sha256"]

        cond do
          manifest_gen < wm_gen ->
            {:error, :watermark_generation_downgrade}

          manifest_gen == wm_gen and wm_hash != nil and manifest_hash != nil and
              String.downcase(to_string(manifest_hash)) != String.downcase(to_string(wm_hash)) ->
            {:error, :watermark_equivocation}

          wm_fp != nil and manifest_fp != nil and
              String.downcase(to_string(manifest_fp)) != String.downcase(to_string(wm_fp)) ->
            {:error, :ca_fingerprint_mismatch}

          manifest_gen >= wm_gen and manifest_crl < wm_crl ->
            {:error, :crl_number_downgrade}

          true ->
            do_write_and_fsync_watermark(base_dir, manifest, opts)
        end

      {:error, :not_found} ->
        do_write_and_fsync_watermark(base_dir, manifest, opts)

      {:error, _corrupted_or_invalid} ->
        # Existing watermark on disk is corrupted; check if disk has surviving valid bundle
        case SecretHub.Agent.PKI.BundleValidator.find_surviving_disk_bundle(base_dir) do
          {:ok, surviving} ->
            manifest_gen = manifest["generation"] || 0

            if manifest_gen < surviving.generation do
              {:error, :watermark_generation_downgrade}
            else
              do_write_and_fsync_watermark(base_dir, manifest, opts)
            end

          _ ->
            do_write_and_fsync_watermark(base_dir, manifest, opts)
        end
    end
  end

  defp do_write_and_fsync_watermark(base_dir, manifest, opts) do
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
        with :ok <- ensure_secure_directory(base_dir),
             :ok <- write_and_fsync_file(tmp_path, json),
             :ok <- File.rename(tmp_path, target_path),
             :ok <- sync_watermark_dir(base_dir, opts) do
          :ok
        else
          {:error, reason} ->
            _ = File.rm(tmp_path)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sync_watermark_dir(base_dir, opts) do
    case Keyword.get(opts, :inject_watermark_fsync_error) do
      nil -> fsync_dir(base_dir)
      injected_err -> {:error, {:dir_sync_failed, injected_err}}
    end
  end

  defp write_and_fsync_file(path, content, mode \\ 0o640) when is_binary(content) do
    File.rm(path)
    char_path = to_charlist(path)

    case :file.open(char_path, [:write, :exclusive, :binary, :raw]) do
      {:ok, fd} ->
        with :ok <- :file.write(fd, content),
             :ok <- :file.sync(fd),
             :ok <- :file.close(fd),
             :ok <- File.chmod(path, mode) do
          :ok
        else
          {:error, reason} ->
            :file.close(fd)
            File.rm(path)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
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
    case File.lstat(gen_dir) do
      {:ok, %File.Stat{type: :symlink}} ->
        File.rm_rf(tmp_dir)
        {:error, {:symlink_directory_disallowed, gen_dir}}

      {:ok, %File.Stat{type: :directory}} ->
        # If gen_dir already exists as a real directory, verify stored content
        mf_path = Path.join(gen_dir, "manifest.json")

        with {:ok, mf_json} <- File.read(mf_path),
             {:ok, existing_manifest} <- Jason.decode(mf_json),
             true <- existing_manifest["bundle_sha256"] == manifest["bundle_sha256"],
             {:ok, _validated} <-
               SecretHub.Agent.PKI.BundleValidator.validate_disk_bundle(gen_dir) do
          File.rm_rf(tmp_dir)
          :ok
        else
          _ ->
            File.rm_rf(tmp_dir)
            {:error, :corrupted_existing_generation}
        end

      {:ok, %File.Stat{type: _other}} ->
        File.rm_rf(tmp_dir)
        {:error, {:not_a_directory, gen_dir}}

      {:error, :enoent} ->
        case File.rename(tmp_dir, gen_dir) do
          :ok ->
            :ok

          {:error, reason} ->
            File.rm_rf(tmp_dir)
            {:error, reason}
        end

      {:error, reason} ->
        File.rm_rf(tmp_dir)
        {:error, reason}
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

  defp fsync_dir(dir_path) do
    case :file.open(to_charlist(dir_path), [:read, :raw, :directory]) do
      {:ok, fd} ->
        try do
          case :file.sync(fd) do
            :ok -> :ok
            {:error, reason} when reason in [:einval, :enotsup] -> :ok
            {:error, reason} -> {:error, {:dir_sync_failed, reason}}
          end
        after
          :file.close(fd)
        end

      {:error, reason} when reason in [:einval, :enotsup] ->
        :ok

      {:error, reason} ->
        {:error, {:dir_open_failed, reason}}
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
