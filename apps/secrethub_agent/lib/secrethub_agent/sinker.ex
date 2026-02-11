defmodule SecretHub.Agent.Sinker do
  @moduledoc """
  Atomic file writer for SecretHub Agent templates.

  Provides safe, atomic file writing with:
  - Write-then-rename atomicity (no partial writes visible)
  - File permission management (owner, group, mode)
  - Multiple sink targets support
  - Backup and rollback capability
  - Change detection and notification
  - Post-write hooks (application reload triggers)

  ## Sink Configuration

  A sink defines where and how to write rendered template output:

  ```elixir
  %{
    name: "database_config",
    path: "/etc/myapp/database.conf",
    template: "DB_HOST=<%= db.host %>\\nDB_PASS=<%= db.password %>",
    permissions: %{
      mode: 0o600,
      owner: "myapp",
      group: "myapp"
    },
    reload_trigger: %{
      type: :signal,
      value: "HUP",
      target: "myapp"
    }
  }
  ```

  ## Atomicity Guarantee

  Files are written atomically using write-then-rename:
  1. Write content to temporary file (path.tmp)
  2. Set permissions on temporary file
  3. Rename temporary file to final path (atomic operation)
  4. Trigger reload if configured

  This ensures applications never see partial/corrupt files.

  ## Usage

  ```elixir
  # Single sink write
  sink = %{
    path: "/etc/app/config.conf",
    permissions: %{mode: 0o600}
  }

  case Sinker.write(sink, rendered_content) do
    :ok -> :ok
    {:error, reason} -> {:error, reason}
  end

  # Multiple sinks
  Sinker.write_multiple(sinks, contents)
  ```
  """

  require Logger

  @type sink_config :: %{
          required(:name) => String.t(),
          required(:path) => String.t(),
          optional(:permissions) => permissions(),
          optional(:reload_trigger) => reload_trigger(),
          optional(:backup) => boolean()
        }

  @type permissions :: %{
          optional(:mode) => integer(),
          optional(:owner) => String.t(),
          optional(:group) => String.t()
        }

  @type reload_trigger :: %{
          type: :signal | :http | :script,
          value: String.t(),
          target: String.t()
        }

  @type write_result :: :ok | {:error, term()}

  @default_permissions %{mode: 0o644}
  @temp_suffix ".tmp"

  @doc """
  Write content to a sink atomically.

  Uses write-then-rename to ensure atomicity.

  ## Parameters

    - `sink` - Sink configuration
    - `content` - Rendered content to write

  ## Returns

    - `:ok` - Successfully written
    - `{:error, reason}` - Write failed

  ## Examples

      iex> sink = %{path: "/tmp/test.conf", permissions: %{mode: 0o600}}
      iex> Sinker.write(sink, "DB_PASS=secret")
      :ok
  """
  @spec write(sink_config(), String.t()) :: write_result()
  def write(sink, content) when is_map(sink) and is_binary(content) do
    path = Map.fetch!(sink, :path)
    permissions = Map.get(sink, :permissions, @default_permissions)
    backup = Map.get(sink, :backup, false)
    reload_trigger = Map.get(sink, :reload_trigger)

    Logger.info("Writing sink", path: path, size: byte_size(content))

    with :ok <- maybe_backup(path, backup),
         :ok <- write_atomic(path, content, permissions),
         :ok <- maybe_trigger_reload(reload_trigger) do
      Logger.info("Sink written successfully", path: path)
      :ok
    else
      {:error, reason} = error ->
        Logger.error("Failed to write sink",
          path: path,
          error: inspect(reason)
        )

        error
    end
  rescue
    e ->
      Logger.error("Exception writing sink",
        path: Map.get(sink, :path),
        error: inspect(e),
        stacktrace: Exception.format_stacktrace(__STACKTRACE__)
      )

      {:error, {:exception, Exception.message(e)}}
  end

  @doc """
  Write content to multiple sinks.

  Writes are independent - one failure doesn't prevent others.

  ## Parameters

    - `sinks` - List of sink configurations
    - `contents` - Map of sink names to rendered content

  ## Returns

    - `{:ok, results}` - Map of sink names to write results
    - `{:error, reason}` - Failed to process sinks

  ## Examples

      iex> sinks = [%{name: "config", path: "/tmp/config.conf"}]
      iex> contents = %{"config" => "KEY=value"}
      iex> Sinker.write_multiple(sinks, contents)
      {:ok, %{"config" => :ok}}
  """
  @spec write_multiple([sink_config()], %{String.t() => String.t()}) ::
          {:ok, %{String.t() => write_result()}} | {:error, term()}
  def write_multiple(sinks, contents) when is_list(sinks) and is_map(contents) do
    results =
      sinks
      |> Enum.map(fn sink ->
        sink_name = Map.fetch!(sink, :name)
        content = Map.get(contents, sink_name, "")

        result = write(sink, content)
        {sink_name, result}
      end)
      |> Map.new()

    {:ok, results}
  rescue
    e ->
      {:error, {:exception, Exception.message(e)}}
  end

  @doc """
  Check if content has changed compared to existing file.

  Returns true if file doesn't exist or content differs.

  ## Parameters

    - `path` - File path to check
    - `content` - New content to compare

  ## Returns

    - `true` - Content changed or file doesn't exist
    - `false` - Content is identical
  """
  @spec changed?(String.t(), String.t()) :: boolean()
  def changed?(path, content) do
    case File.read(path) do
      {:ok, existing_content} ->
        existing_content != content

      {:error, _} ->
        # File doesn't exist, consider it changed
        true
    end
  end

  @doc """
  Validate sink configuration.

  Checks that required fields are present and path is writable.

  ## Parameters

    - `sink` - Sink configuration to validate

  ## Returns

    - `:ok` - Sink configuration is valid
    - `{:error, reason}` - Invalid configuration
  """
  @spec validate(sink_config()) :: :ok | {:error, term()}
  def validate(sink) when is_map(sink) do
    with :ok <- validate_required_fields(sink),
         :ok <- validate_path(Map.fetch!(sink, :path)) do
      validate_permissions(Map.get(sink, :permissions))
    end
  end

  ## Private Functions

  defp write_atomic(path, content, permissions) do
    temp_path = path <> @temp_suffix

    with :ok <- ensure_parent_directory(path),
         :ok <- write_temp_file(temp_path, content),
         :ok <- set_permissions(temp_path, permissions),
         :ok <- atomic_rename(temp_path, path) do
      :ok
    else
      {:error, _reason} = error ->
        # Clean up temp file on error
        File.rm(temp_path)
        error
    end
  end

  defp write_temp_file(temp_path, content) do
    case File.write(temp_path, content) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:write_failed, reason}}
    end
  end

  defp atomic_rename(temp_path, final_path) do
    case File.rename(temp_path, final_path) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:rename_failed, reason}}
    end
  end

  defp ensure_parent_directory(path) do
    parent_dir = Path.dirname(path)

    case File.mkdir_p(parent_dir) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:mkdir_failed, reason}}
    end
  end

  defp set_permissions(path, permissions) do
    with :ok <- set_mode(path, Map.get(permissions, :mode)),
         :ok <- set_owner(path, Map.get(permissions, :owner)) do
      set_group(path, Map.get(permissions, :group))
    end
  end

  defp set_mode(_path, nil), do: :ok

  defp set_mode(path, mode) when is_integer(mode) do
    case File.chmod(path, mode) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:chmod_failed, reason}}
    end
  end

  defp set_owner(_path, nil), do: :ok

  defp set_owner(path, owner) when is_binary(owner) do
    # Use chown system call via Port
    case System.cmd("chown", [owner, path], stderr_to_stdout: true) do
      {_, 0} ->
        :ok

      {output, exit_code} ->
        Logger.warning("chown failed",
          path: path,
          owner: owner,
          exit_code: exit_code,
          output: output
        )

        {:error, {:chown_failed, exit_code}}
    end
  rescue
    e ->
      {:error, {:chown_exception, Exception.message(e)}}
  end

  defp set_group(_path, nil), do: :ok

  defp set_group(path, group) when is_binary(group) do
    # Use chgrp system call via Port
    case System.cmd("chgrp", [group, path], stderr_to_stdout: true) do
      {_, 0} ->
        :ok

      {output, exit_code} ->
        Logger.warning("chgrp failed",
          path: path,
          group: group,
          exit_code: exit_code,
          output: output
        )

        {:error, {:chgrp_failed, exit_code}}
    end
  rescue
    e ->
      {:error, {:chgrp_exception, Exception.message(e)}}
  end

  defp maybe_backup(_path, false), do: :ok

  defp maybe_backup(path, true) do
    backup_path = path <> ".bak"

    case File.exists?(path) do
      true ->
        case File.copy(path, backup_path) do
          {:ok, _bytes} ->
            Logger.debug("Created backup", path: backup_path)
            :ok

          {:error, reason} ->
            {:error, {:backup_failed, reason}}
        end

      false ->
        :ok
    end
  end

  defp maybe_trigger_reload(nil), do: :ok

  defp maybe_trigger_reload(trigger) when is_map(trigger) do
    case Map.get(trigger, :type) do
      :signal ->
        trigger_signal(trigger)

      :http ->
        trigger_http(trigger)

      :script ->
        trigger_script(trigger)

      nil ->
        :ok

      unknown ->
        Logger.warning("Unknown reload trigger type", type: unknown)
        :ok
    end
  end

  defp trigger_signal(trigger) do
    signal = Map.fetch!(trigger, :value)
    target = Map.fetch!(trigger, :target)

    Logger.info("Triggering reload via signal",
      signal: signal,
      target: target
    )

    case System.cmd("pkill", ["-#{signal}", target], stderr_to_stdout: true) do
      {_, 0} ->
        :ok

      {output, exit_code} ->
        Logger.warning("Signal trigger failed",
          signal: signal,
          target: target,
          exit_code: exit_code,
          output: output
        )

        {:error, {:signal_failed, exit_code}}
    end
  rescue
    e ->
      {:error, {:signal_exception, Exception.message(e)}}
  end

  defp trigger_http(trigger) do
    url = Map.fetch!(trigger, :value)

    Logger.info("Triggering reload via HTTP", url: url)

    # Simple HTTP POST using curl
    case System.cmd("curl", ["-X", "POST", url, "-m", "5"], stderr_to_stdout: true) do
      {_, 0} ->
        :ok

      {output, exit_code} ->
        Logger.warning("HTTP trigger failed",
          url: url,
          exit_code: exit_code,
          output: output
        )

        {:error, {:http_failed, exit_code}}
    end
  rescue
    e ->
      {:error, {:http_exception, Exception.message(e)}}
  end

  defp trigger_script(trigger) do
    script = Map.fetch!(trigger, :value)

    Logger.info("Triggering reload via script", script: script)

    case System.cmd("sh", ["-c", script], stderr_to_stdout: true) do
      {_, 0} ->
        :ok

      {output, exit_code} ->
        Logger.warning("Script trigger failed",
          script: script,
          exit_code: exit_code,
          output: output
        )

        {:error, {:script_failed, exit_code}}
    end
  rescue
    e ->
      {:error, {:script_exception, Exception.message(e)}}
  end

  defp validate_required_fields(sink) do
    required_fields = [:name, :path]

    missing_fields =
      required_fields
      |> Enum.reject(&Map.has_key?(sink, &1))

    if Enum.empty?(missing_fields) do
      :ok
    else
      {:error, {:missing_fields, missing_fields}}
    end
  end

  defp validate_path(path) when is_binary(path) do
    parent_dir = Path.dirname(path)

    cond do
      File.exists?(path) and not File.regular?(path) ->
        {:error, {:invalid_path, "path exists but is not a regular file"}}

      File.exists?(parent_dir) and not File.dir?(parent_dir) ->
        {:error, {:invalid_path, "parent exists but is not a directory"}}

      true ->
        :ok
    end
  end

  defp validate_permissions(nil), do: :ok

  defp validate_permissions(permissions) when is_map(permissions) do
    mode = Map.get(permissions, :mode)

    if mode && (not is_integer(mode) or mode < 0 or mode > 0o777) do
      {:error, {:invalid_permissions, "mode must be integer between 0 and 0o777"}}
    else
      :ok
    end
  end
end
