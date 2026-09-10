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
         :ok <- publish_generation_dir(tmp_dir, gen_dir, manifest, opts),
         :ok <- fsync_dir(generations_dir) do
      notify_fs_op(opts, {:fsync_generations_dir, generations_dir})

      case write_and_fsync_watermark(base_dir, manifest, opts) do
        :ok ->
          case switch_symlink(base_dir, generation, opts) do
            :ok ->
              sync_res =
                case Keyword.get(opts, :inject_base_dir_fsync_error) do
                  nil ->
                    res = fsync_dir(base_dir)
                    notify_fs_op(opts, {:fsync_base_dir, base_dir})
                    res

                  injected_err ->
                    {:error, injected_err}
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
  Reads the persisted observation sequence and durable outbox from `<base_dir>/observation_sequence.json`.
  Returns `{:ok, %{highest_sequence: non_neg_integer(), outbox: [map()]}}` or `{:error, term()}`.
  """
  @spec read_outbox(Path.t()) ::
          {:ok, %{highest_sequence: non_neg_integer(), outbox: [map()]}}
          | {:error, term()}
  def read_outbox(base_dir) do
    path = Path.join(base_dir, "observation_sequence.json")

    case File.read(path) do
      {:ok, content} ->
        case decode_json_object(content) do
          {:ok, %{"observation_sequence" => seq} = data}
          when is_integer(seq) and seq >= 0 ->
            with {:ok, outbox} <- validate_and_extract_outbox(data, seq) do
              {:ok, %{highest_sequence: seq, outbox: outbox}}
            else
              {:error, reason} ->
                {:error, {:corrupted_outbox, reason}}
            end

          {:ok, _} ->
            {:error, {:corrupted_outbox, :invalid_observation_sequence_schema}}

          {:error, reason} ->
            {:error, {:corrupted_outbox, reason}}
        end

      {:error, :enoent} ->
        {:ok, %{highest_sequence: 0, outbox: []}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_and_extract_outbox(data, highest_seq) do
    cond do
      is_list(data["outbox"]) ->
        validate_outbox_entries(data["outbox"], highest_seq)

      is_map(data["pending_receipt"]) ->
        # Legacy pending_receipt compatibility
        pending = data["pending_receipt"]
        p_seq = pending["observation_sequence"] || highest_seq

        pending =
          if Map.has_key?(pending, "applied_at") do
            pending
          else
            Map.put(pending, "applied_at", data["updated_at"] || "")
          end

        entry = %{
          "sequence" => p_seq,
          "receipt" => pending,
          "enqueued_at" => data["updated_at"] || ""
        }

        validate_outbox_entries([entry], highest_seq)

      data["outbox"] == nil and data["pending_receipt"] == nil ->
        {:ok, []}

      true ->
        {:error, :invalid_outbox_format}
    end
  end

  defp validate_outbox_entries(entries, highest_seq) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case validate_outbox_entry(entry, highest_seq) do
        {:ok, validated} -> {:cont, {:ok, [validated | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, list} ->
        # Check for duplicate sequences in the outbox
        reversed = Enum.reverse(list)
        seqs = Enum.map(reversed, & &1["sequence"])

        if length(seqs) == length(Enum.uniq(seqs)) do
          {:ok, reversed}
        else
          {:error, :duplicate_sequence_in_outbox}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_outbox_entry(entry, highest_seq) do
    cond do
      not is_map(entry) ->
        {:error, :entry_not_a_map}

      not is_integer(entry["sequence"]) or entry["sequence"] <= 0 ->
        {:error, {:invalid_entry_sequence, entry["sequence"]}}

      entry["sequence"] > highest_seq ->
        {:error, {:entry_sequence_ahead_of_watermark, entry["sequence"], highest_seq}}

      not is_map(entry["receipt"]) ->
        {:error, {:entry_missing_receipt_map, entry["sequence"]}}

      entry["receipt"]["observation_sequence"] != entry["sequence"] ->
        {:error,
         {:receipt_sequence_mismatch, entry["receipt"]["observation_sequence"], entry["sequence"]}}

      not is_binary(entry["receipt"]["agent_id"]) or entry["receipt"]["agent_id"] == "" ->
        {:error, {:missing_receipt_field, "agent_id", entry["sequence"]}}

      not is_binary(entry["receipt"]["status"]) or entry["receipt"]["status"] == "" ->
        {:error, {:missing_receipt_field, "status", entry["sequence"]}}

      not is_binary(entry["receipt"]["applied_at"]) or entry["receipt"]["applied_at"] == "" ->
        {:error, {:missing_receipt_field, "applied_at", entry["sequence"]}}

      true ->
        {:ok, entry}
    end
  end

  @doc """
  Repairs outbox entries on disk by backfilling missing or blank receipt metadata
  (e.g. `agent_id` or `applied_at`) without modifying sequence numbers, watermarks, or CA pins.
  Preserves original file evidence to `.pre_repair_bak` before applying repairs.
  Returns `:ok` or `{:error, reason}`.
  """
  @spec repair_outbox_metadata(Path.t(), map(), keyword()) :: :ok | {:error, term()}
  def repair_outbox_metadata(base_dir, metadata, opts \\ []) when is_map(metadata) do
    path = Path.join(base_dir, "observation_sequence.json")

    case File.read(path) do
      {:ok, content} ->
        case decode_json_object(content) do
          {:ok, %{"observation_sequence" => seq, "outbox" => entries} = data}
          when is_integer(seq) and seq >= 0 and is_list(entries) ->
            target_agent_id =
              metadata[:agent_id] || metadata["agent_id"]

            if not (is_binary(target_agent_id) and target_agent_id != "") do
              {:error, :missing_target_agent_id}
            else
              # Check for conflicting nonempty agent_id in existing entries
              conflicting_entry =
                Enum.find(entries, fn entry ->
                  is_map(entry) and is_map(entry["receipt"]) and
                    is_binary(entry["receipt"]["agent_id"]) and
                    entry["receipt"]["agent_id"] != "" and
                    entry["receipt"]["agent_id"] != target_agent_id
                end)

              if conflicting_entry do
                existing_id = conflicting_entry["receipt"]["agent_id"]
                {:error, {:conflicting_outbox_identity, existing_id, target_agent_id}}
              else
                now_iso =
                  DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

                needs_modification? =
                  Enum.any?(entries, fn entry ->
                    is_map(entry) and is_map(entry["receipt"]) and
                      (is_nil(entry["receipt"]["agent_id"]) or entry["receipt"]["agent_id"] == "" or
                         (is_nil(entry["receipt"]["applied_at"]) or
                            entry["receipt"]["applied_at"] == ""))
                  end)

                if needs_modification? do
                  repaired_entries =
                    Enum.map(entries, fn entry ->
                      if is_map(entry) and is_map(entry["receipt"]) do
                        receipt = entry["receipt"]

                        receipt =
                          if is_nil(receipt["agent_id"]) or receipt["agent_id"] == "" do
                            Map.put(receipt, "agent_id", target_agent_id)
                          else
                            receipt
                          end

                        receipt =
                          if is_nil(receipt["applied_at"]) or receipt["applied_at"] == "" do
                            Map.put(receipt, "applied_at", entry["enqueued_at"] || now_iso)
                          else
                            receipt
                          end

                        %{entry | "receipt" => receipt}
                      else
                        entry
                      end
                    end)

                  case validate_outbox_entries(repaired_entries, seq) do
                    {:ok, validated} ->
                      case create_durable_outbox_backup(base_dir, content, opts) do
                        {:ok, backup_path} ->
                          updated_data = %{
                            data
                            | "outbox" => validated,
                              "updated_at" => now_iso
                          }

                          case write_and_fsync_sequence_data(base_dir, updated_data, opts) do
                            :ok ->
                              notify_fs_op(opts, {:repair_outbox_metadata, backup_path})
                              :ok

                            {:error, reason} ->
                              {:error, {:repair_persistence_failed, reason}}
                          end

                        {:error, reason} ->
                          {:error, {:backup_failed, reason}}
                      end

                    {:error, reason} ->
                      {:error, {:repair_failed, reason}}
                  end
                else
                  # Already valid and no repair needed
                  :ok
                end
              end
            end

          {:ok, _} ->
            {:error, :invalid_observation_sequence_schema}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :enoent} ->
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Creates an exclusive, immutable durable backup of outbox content before repair.
  Ensures that existing files, symlinks, or directories at the backup target are never overwritten.
  Fsyncs the backup file and directory before returning.
  """
  @spec create_durable_outbox_backup(Path.t(), binary(), keyword()) ::
          {:ok, Path.t()} | {:error, term()}
  def create_durable_outbox_backup(base_dir, content, opts \\ []) when is_binary(content) do
    content_sha256 = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)

    backup_path =
      opts[:backup_path] ||
        Path.join(
          base_dir,
          opts[:backup_name] || "observation_sequence.json.bak-" <> content_sha256
        )

    case File.lstat(backup_path) do
      {:ok, %File.Stat{type: :symlink}} ->
        {:error, {:symlink_detected, backup_path}}

      {:ok, %File.Stat{type: :directory}} ->
        {:error, {:is_directory, backup_path}}

      {:ok, %File.Stat{type: :regular}} ->
        validate_and_reuse_existing_backup(base_dir, backup_path, content, content_sha256)

      {:ok, %File.Stat{type: other}} ->
        {:error, {:unexpected_file_type, other, backup_path}}

      {:error, :enoent} ->
        with :ok <- ensure_secure_directory(base_dir),
             {:ok, fd} <- open_exclusive_file(backup_path),
             :ok <- check_injected_backup_write_error(opts, fd, backup_path),
             :ok <- write_backup_fd(fd, content, backup_path),
             :ok <- check_injected_backup_sync_error(opts, fd, backup_path),
             :ok <- sync_and_close_backup_fd(fd),
             :ok <- File.chmod(backup_path, 0o600),
             :ok <- fsync_dir(base_dir) do
          {:ok, backup_path}
        else
          {:error, {:backup_already_exists, ^backup_path}} ->
            validate_and_reuse_existing_backup(base_dir, backup_path, content, content_sha256)

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_and_reuse_existing_backup(base_dir, backup_path, content, expected_sha256) do
    case File.lstat(backup_path) do
      {:ok, %File.Stat{type: :regular}} ->
        case File.read(backup_path) do
          {:ok, existing_content} when existing_content === content ->
            existing_sha256 =
              :crypto.hash(:sha256, existing_content) |> Base.encode16(case: :lower)

            if existing_sha256 === expected_sha256 do
              with :ok <- File.chmod(backup_path, 0o600),
                   :ok <- fsync_dir(base_dir) do
                {:ok, backup_path}
              else
                {:error, reason} -> {:error, reason}
              end
            else
              {:error, {:backup_already_exists, backup_path}}
            end

          {:ok, _mismatch_or_incomplete} ->
            {:error, {:backup_already_exists, backup_path}}

          {:error, reason} ->
            {:error, reason}
        end

      {:ok, %File.Stat{type: :symlink}} ->
        {:error, {:symlink_detected, backup_path}}

      {:ok, %File.Stat{type: :directory}} ->
        {:error, {:is_directory, backup_path}}

      {:ok, %File.Stat{type: other}} ->
        {:error, {:unexpected_file_type, other, backup_path}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp open_exclusive_file(path) do
    case :file.open(String.to_charlist(path), [:write, :exclusive, :binary, :raw]) do
      {:ok, fd} ->
        {:ok, fd}

      {:error, :eexist} ->
        {:error, {:backup_already_exists, path}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_injected_backup_write_error(opts, fd, path) do
    case check_injected_opt(opts, :inject_backup_write_error) do
      :ok ->
        :ok

      {:error, reason} ->
        _ = :file.close(fd)
        _ = File.rm(path)
        {:error, reason}
    end
  end

  defp write_backup_fd(fd, content, path) do
    case :file.write(fd, content) do
      :ok ->
        :ok

      {:error, reason} ->
        _ = :file.close(fd)
        _ = File.rm(path)
        {:error, reason}
    end
  end

  defp check_injected_backup_sync_error(opts, fd, path) do
    case check_injected_opt(opts, :inject_backup_sync_error) do
      :ok ->
        :ok

      {:error, reason} ->
        _ = :file.close(fd)
        _ = File.rm(path)
        {:error, reason}
    end
  end

  defp sync_and_close_backup_fd(fd) do
    with :ok <- :file.sync(fd),
         :ok <- :file.close(fd) do
      :ok
    else
      {:error, reason} ->
        _ = :file.close(fd)
        {:error, reason}
    end
  end

  @doc """
  Reads the persisted observation sequence for the trust bundle from `<base_dir>/observation_sequence.json`.
  Returns `{:ok, seq}` (integer >= 0) or `{:ok, 0}` if not found.
  """
  @spec read_observation_sequence(Path.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def read_observation_sequence(base_dir) do
    case read_outbox(base_dir) do
      {:ok, %{highest_sequence: seq}} -> {:ok, seq}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Reads any pending unacknowledged observation payload persisted alongside sequence.
  Returns `{:ok, map() | nil}` or `{:error, term()}`.
  """
  @spec read_pending_observation(Path.t()) :: {:ok, map() | nil} | {:error, term()}
  def read_pending_observation(base_dir) do
    case read_outbox(base_dir) do
      {:ok, %{outbox: [%{"receipt" => receipt} | _]}} -> {:ok, receipt}
      {:ok, %{outbox: []}} -> {:ok, nil}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Durably enqueues an observation receipt into `<base_dir>/observation_sequence.json`.
  Allocates the next monotonic sequence number, attaches it to the receipt, records it
  in the outbox, and syncs to disk before returning `{:ok, seq, receipt_with_seq}`.
  """
  @spec enqueue_observation(Path.t(), map(), keyword()) ::
          {:ok, non_neg_integer(), map()} | {:error, term()}
  def enqueue_observation(base_dir, raw_receipt, opts \\ []) when is_map(raw_receipt) do
    case Keyword.get(opts, :inject_sequence_persistence_error) do
      nil ->
        case read_outbox(base_dir) do
          {:ok, %{highest_sequence: current_highest, outbox: current_outbox}} ->
            core_seq = Keyword.get(opts, :core_seq, 0) || 0
            base_seq = max(current_highest, core_seq)
            next_seq = base_seq + 1

            if Enum.any?(current_outbox, &(&1["sequence"] == next_seq)) do
              {:error, {:sequence_persistence_failed, {:sequence_collision, next_seq}}}
            else
              receipt = Map.put(raw_receipt, "observation_sequence", next_seq)
              now_iso = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

              entry = %{
                "sequence" => next_seq,
                "receipt" => receipt,
                "enqueued_at" => now_iso
              }

              with {:ok, _validated_entry} <- validate_outbox_entry(entry, next_seq) do
                updated_outbox = current_outbox ++ [entry]

                data = %{
                  "observation_sequence" => next_seq,
                  "outbox" => updated_outbox,
                  "updated_at" => now_iso
                }

                case write_and_fsync_sequence_data(base_dir, data, opts) do
                  :ok ->
                    notify_fs_op(opts, {:enqueue_observation, next_seq})
                    {:ok, next_seq, receipt}

                  {:error, reason} ->
                    {:error, {:sequence_persistence_failed, reason}}
                end
              else
                {:error, reason} ->
                  {:error, {:sequence_persistence_failed, {:invalid_outbox_entry, reason}}}
              end
            end

          {:error, reason} ->
            {:error, {:sequence_persistence_failed, reason}}
        end

      err ->
        {:error, {:sequence_persistence_failed, err}}
    end
  end

  @doc """
  Durably acknowledges and removes an observation receipt from the outbox.
  """
  @spec acknowledge_observation(Path.t(), non_neg_integer(), keyword()) ::
          :ok | {:error, term()}
  def acknowledge_observation(base_dir, seq, opts \\ [])
      when is_integer(seq) and seq >= 0 do
    case read_outbox(base_dir) do
      {:ok, %{highest_sequence: highest_seq, outbox: current_outbox}} ->
        updated_outbox = Enum.reject(current_outbox, &(&1["sequence"] == seq))
        now_iso = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

        data = %{
          "observation_sequence" => highest_seq,
          "outbox" => updated_outbox,
          "updated_at" => now_iso
        }

        case write_and_fsync_sequence_data(base_dir, data, opts) do
          :ok ->
            notify_fs_op(opts, {:acknowledge_observation, seq})
            :ok

          {:error, reason} ->
            {:error, {:sequence_persistence_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:sequence_persistence_failed, reason}}
    end
  end

  @doc """
  Durably writes a rejected observation receipt into the dead letter file
  `<base_dir>/dead_letter_observations.json` and removes it from `<base_dir>/observation_sequence.json`.
  """
  @spec record_rejected_observation(Path.t(), map(), atom(), String.t(), keyword()) ::
          :ok | {:error, term()}
  def record_rejected_observation(base_dir, entry, error_code, error_reason, opts \\ [])
      when is_map(entry) and is_atom(error_code) do
    dead_letter_entry = %{
      "sequence" => entry["sequence"],
      "receipt" => entry["receipt"],
      "enqueued_at" => entry["enqueued_at"],
      "rejected_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
      "rejection_code" => to_string(error_code),
      "rejection_reason" => error_reason
    }

    # 1. Append to dead-letter storage
    case append_dead_letter_observation(base_dir, dead_letter_entry, opts) do
      :ok ->
        # 2. Acknowledge and remove from active outbox
        acknowledge_observation(base_dir, entry["sequence"], opts)

      {:error, reason} ->
        {:error, {:dead_letter_persistence_failed, reason}}
    end
  end

  @doc """
  Reads dead letter observations from `<base_dir>/dead_letter_observations.json`.
  Returns `{:ok, [map()]}` or `{:error, term()}`.
  """
  @spec read_dead_letter_observations(Path.t()) :: {:ok, [map()]} | {:error, term()}
  def read_dead_letter_observations(base_dir) do
    path = Path.join(base_dir, "dead_letter_observations.json")

    case File.read(path) do
      {:ok, content} ->
        case decode_json_object(content) do
          {:ok, %{"rejected_observations" => list}} when is_list(list) ->
            validate_dead_letter_entries(list)

          {:ok, _} ->
            {:error, {:corrupted_dead_letter_archive, :invalid_dead_letter_schema}}

          {:error, reason} ->
            {:error, {:corrupted_dead_letter_archive, {:invalid_json, reason}}}
        end

      {:error, :enoent} ->
        {:ok, []}

      {:error, reason} ->
        {:error, {:corrupted_dead_letter_archive, {:read_failed, reason}}}
    end
  end

  defp validate_dead_letter_entries(list) when is_list(list) do
    Enum.reduce_while(list, {:ok, []}, fn entry, {:ok, acc} ->
      case validate_dead_letter_entry(entry) do
        {:ok, validated} ->
          {:cont, {:ok, [validated | acc]}}

        {:error, reason} ->
          {:halt, {:error, {:corrupted_dead_letter_archive, reason}}}
      end
    end)
    |> case do
      {:ok, rev} -> {:ok, Enum.reverse(rev)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_dead_letter_entry(entry) do
    if not is_map(entry) do
      {:error, {:invalid_entry_shape, entry}}
    else
      seq = entry["sequence"]
      receipt = entry["receipt"]
      stored_digest = entry["receipt_digest"]

      cond do
        not (is_integer(seq) and seq >= 0) ->
          {:error, {:invalid_sequence, seq}}

        not is_map(receipt) ->
          {:error, {:invalid_receipt_shape, receipt}}

        not (is_binary(receipt["agent_id"]) and receipt["agent_id"] != "") ->
          {:error, {:missing_agent_id, receipt}}

        is_integer(receipt["observation_sequence"]) and
            receipt["observation_sequence"] != seq ->
          {:error, {:inconsistent_sequence, seq, receipt["observation_sequence"]}}

        is_binary(stored_digest) and stored_digest != "" ->
          if not Regex.match?(@sha256_hex, stored_digest) do
            {:error, {:invalid_stored_digest_format, stored_digest}}
          else
            computed = receipt_payload_digest(receipt)

            if stored_digest != computed do
              {:error, {:digest_mismatch, stored: stored_digest, computed: computed}}
            else
              {:ok, entry}
            end
          end

        is_nil(stored_digest) or stored_digest == "" ->
          # Valid legacy record without a digest: attach computed digest for downstream idempotency
          computed = receipt_payload_digest(receipt)
          {:ok, Map.put(entry, "receipt_digest", computed)}

        true ->
          {:error, {:invalid_stored_digest_format, stored_digest}}
      end
    end
  end

  @doc false
  def receipt_payload_digest(receipt) when is_map(receipt) do
    canonical = sort_canonical_map(receipt)
    :crypto.hash(:sha256, Jason.encode!(canonical)) |> Base.encode16(case: :lower)
  end

  def receipt_payload_digest(_), do: ""

  defp sort_canonical_map(%{__struct__: _} = struct) do
    struct |> Map.from_struct() |> sort_canonical_map()
  end

  defp sort_canonical_map(map) when is_map(map) do
    pairs =
      map
      |> Enum.map(fn {k, v} -> {to_string(k), sort_canonical_map(v)} end)
      |> Enum.sort_by(fn {k, _v} -> k end)

    Jason.OrderedObject.new(pairs)
  end

  defp sort_canonical_map(list) when is_list(list) do
    Enum.map(list, &sort_canonical_map/1)
  end

  defp sort_canonical_map(other), do: other

  defp append_dead_letter_observation(base_dir, dead_letter_entry, opts) do
    if not is_map(dead_letter_entry) do
      {:error, :invalid_dead_letter_entry}
    else
      target_seq = dead_letter_entry["sequence"]
      target_receipt = dead_letter_entry["receipt"]

      if not (is_integer(target_seq) and is_map(target_receipt)) do
        {:error, :invalid_dead_letter_entry}
      else
        target_digest = receipt_payload_digest(target_receipt)

        case read_dead_letter_observations(base_dir) do
          {:ok, existing_entries} ->
            case check_dead_letter_idempotency(
                   existing_entries,
                   target_seq,
                   target_receipt,
                   target_digest
                 ) do
              :replay ->
                # Replay of the same observation: do not append another logical rejection;
                # complete any outstanding outbox removal.
                :ok

              {:conflict, conflicting_agent} ->
                # Different payload under the same observation identity: return a conflict
                # and preserve both the existing evidence and pending observation.
                {:error, {:conflicting_observation_payload, target_seq, conflicting_agent}}

              :not_found ->
                # Entry not yet recorded: append new logical rejection record
                entry_to_record = Map.put(dead_letter_entry, "receipt_digest", target_digest)
                updated_entries = existing_entries ++ [entry_to_record]

                data = %{
                  "rejected_observations" => updated_entries,
                  "updated_at" =>
                    DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
                }

                tmp_id =
                  ".dead_letter.tmp-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

                tmp_path = Path.join(base_dir, tmp_id)
                target_path = Path.join(base_dir, "dead_letter_observations.json")

                case Jason.encode(data, pretty: true) do
                  {:ok, json} ->
                    with :ok <- ensure_secure_directory(base_dir),
                         :ok <- check_injected_dead_letter_write_error(opts),
                         :ok <- write_and_fsync_file(tmp_path, json),
                         :ok <- check_injected_dead_letter_sync_error(opts),
                         :ok <- check_injected_dead_letter_error(opts),
                         :ok <- File.rename(tmp_path, target_path),
                         :ok <- fsync_dir(base_dir) do
                      notify_fs_op(
                        opts,
                        {:record_rejected_observation, dead_letter_entry["sequence"]}
                      )

                      :ok
                    else
                      {:error, reason} ->
                        _ = File.rm(tmp_path)
                        {:error, reason}
                    end

                  {:error, reason} ->
                    {:error, reason}
                end

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end
      end
    end
  end

  defp check_dead_letter_idempotency(existing_entries, target_seq, target_receipt, target_digest) do
    target_agent =
      if is_map(target_receipt),
        do: target_receipt["agent_id"] || target_receipt[:agent_id],
        else: nil

    cond do
      not is_map(target_receipt) ->
        {:error, :invalid_target_receipt}

      not (is_integer(target_seq) and target_seq >= 0) ->
        {:error, :invalid_target_sequence}

      not (is_binary(target_agent) and target_agent != "") ->
        {:error, :missing_target_agent_id}

      true ->
        matching_entry =
          Enum.find(existing_entries, fn ex ->
            if is_map(ex) and is_map(ex["receipt"]) do
              ex_seq = ex["sequence"]
              ex_receipt = ex["receipt"]
              ex_agent = ex_receipt["agent_id"] || ex_receipt[:agent_id]

              ex_seq == target_seq and ex_agent == target_agent
            else
              false
            end
          end)

        case matching_entry do
          nil ->
            :not_found

          ex ->
            ex_receipt = ex["receipt"] || %{}
            ex_digest = ex["receipt_digest"] || receipt_payload_digest(ex_receipt)

            if ex_digest == target_digest do
              :replay
            else
              {:conflict, target_agent}
            end
        end
    end
  end

  defp check_injected_dead_letter_write_error(opts) do
    check_injected_opt(opts, :inject_dead_letter_write_error)
  end

  defp check_injected_dead_letter_sync_error(opts) do
    check_injected_opt(opts, :inject_dead_letter_sync_error)
  end

  defp check_injected_dead_letter_error(opts) do
    case check_injected_opt(opts, :inject_dead_letter_persistence_error) do
      :ok -> check_injected_opt(opts, :inject_dead_letter_rename_error)
      err -> err
    end
  end

  defp check_injected_opt(opts, key) do
    case Keyword.get(opts, key) do
      nil ->
        :ok

      fun when is_function(fun, 0) ->
        case fun.() do
          nil -> :ok
          err -> {:error, err}
        end

      err ->
        {:error, err}
    end
  end

  @doc """
  Durably writes the observation sequence to `<base_dir>/observation_sequence.json`
  using atomic rename and directory fsync.
  """
  @spec persist_observation_sequence(Path.t(), non_neg_integer(), keyword()) ::
          :ok | {:error, term()}
  def persist_observation_sequence(base_dir, seq, opts \\ [])
      when is_integer(seq) and seq >= 0 do
    case Keyword.get(opts, :inject_sequence_persistence_error) do
      nil ->
        now_iso = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

        current_outbox =
          case read_outbox(base_dir) do
            {:ok, %{outbox: ob}} -> ob
            _ -> []
          end

        outbox_res =
          case Keyword.get(opts, :pending_receipt) do
            nil ->
              {:ok, current_outbox}

            receipt when is_map(receipt) ->
              p_seq = receipt["observation_sequence"] || seq

              receipt =
                if Map.has_key?(receipt, "applied_at") do
                  receipt
                else
                  Map.put(receipt, "applied_at", now_iso)
                end

              entry = %{
                "sequence" => p_seq,
                "receipt" => receipt,
                "enqueued_at" => now_iso
              }

              case validate_outbox_entry(entry, max(seq, p_seq)) do
                {:ok, _validated} ->
                  {:ok, Enum.reject(current_outbox, &(&1["sequence"] == p_seq)) ++ [entry]}

                {:error, reason} ->
                  {:error, {:sequence_persistence_failed, {:invalid_outbox_entry, reason}}}
              end
          end

        case outbox_res do
          {:ok, outbox} ->
            data = %{
              "observation_sequence" => seq,
              "outbox" => outbox,
              "updated_at" => now_iso
            }

            write_and_fsync_sequence_data(base_dir, data, opts)

          {:error, _} = err ->
            err
        end

      err ->
        {:error, {:sequence_persistence_failed, err}}
    end
  end

  defp write_and_fsync_sequence_data(base_dir, data, opts) do
    tmp_id = ".sequence.tmp-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    tmp_path = Path.join(base_dir, tmp_id)
    target_path = Path.join(base_dir, "observation_sequence.json")

    case Jason.encode(data, pretty: true) do
      {:ok, json} ->
        with :ok <- ensure_secure_directory(base_dir),
             :ok <- write_and_fsync_file(tmp_path, json),
             :ok <- check_injected_sequence_rename_error(opts),
             :ok <- File.rename(tmp_path, target_path),
             :ok <- fsync_dir(base_dir) do
          notify_fs_op(opts, {:persist_observation_sequence, data["observation_sequence"]})
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

  defp check_injected_sequence_rename_error(opts) do
    injected =
      Keyword.get(opts, :inject_sequence_rename_error) ||
        Keyword.get(opts, :inject_sequence_persistence_error)

    err =
      case injected do
        fun when is_function(fun, 0) -> fun.()
        val -> val
      end

    case err do
      nil -> :ok
      injected_err -> {:error, injected_err}
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
             :ok <- notify_fs_op(opts, {:rename_watermark, target_path}),
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
    notify_fs_op(opts, {:fsync_watermark_dir, base_dir})

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

  defp publish_generation_dir(tmp_dir, gen_dir, manifest, opts) do
    case File.lstat(gen_dir) do
      {:ok, %File.Stat{type: :symlink}} ->
        File.rm_rf(tmp_dir)
        {:error, {:symlink_directory_disallowed, gen_dir}}

      {:ok, %File.Stat{type: :directory}} ->
        # If gen_dir already exists as a real directory, verify stored content
        mf_path = Path.join(gen_dir, "manifest.json")

        with {:ok, mf_json} <- File.read(mf_path),
             {:ok, %{} = existing_manifest} <- decode_json_object(mf_json),
             true <- is_binary(existing_manifest["bundle_sha256"]),
             true <- existing_manifest["bundle_sha256"] == manifest["bundle_sha256"],
             {:ok, _validated} <-
               SecretHub.Agent.PKI.BundleValidator.validate_disk_bundle(gen_dir) do
          File.rm_rf(tmp_dir)
          notify_fs_op(opts, {:reused_generation, gen_dir})
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
            notify_fs_op(opts, {:rename_generation, gen_dir})
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

  defp switch_symlink(base_dir, generation, opts) do
    target = Path.join("generations", to_string(generation))
    tmp_symlink = Path.join(base_dir, "current.tmp")
    current_symlink = Path.join(base_dir, "current")

    File.rm(tmp_symlink)

    with :ok <- File.ln_s(target, tmp_symlink),
         :ok <- File.rename(tmp_symlink, current_symlink) do
      notify_fs_op(opts, {:switch_symlink, generation})
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

  defp notify_fs_op(opts, op) when is_list(opts) do
    case Keyword.get(opts, :record_operations_to) do
      pid when is_pid(pid) ->
        send(pid, {:atomic_store_op, op})
        :ok

      _ ->
        :ok
    end
  end
end
