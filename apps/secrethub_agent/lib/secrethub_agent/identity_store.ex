defmodule SecretHub.Agent.IdentityStore do
  @moduledoc """
  Persists and loads trusted Agent runtime identity material.
  """

  @derive {Inspect, except: [:private_key_pem]}
  defstruct [
    :agent_id,
    :certificate_pem,
    :private_key_pem,
    :ca_chain_pem,
    :connect_info,
    :identity
  ]

  @type t :: %__MODULE__{
          agent_id: binary(),
          certificate_pem: binary(),
          private_key_pem: binary(),
          ca_chain_pem: binary(),
          connect_info: map(),
          identity: map()
        }

  @trusted_files %{
    certificate_pem: {"agent-cert.pem", 0o644},
    private_key_pem: {"agent-key.pem", 0o600},
    ca_chain_pem: {"ca-chain.pem", 0o644},
    connect_info: {"connect-info.json", 0o644},
    identity: {"identity.json", 0o644}
  }

  @doc """
  Writes trusted runtime material into the Agent state directory.
  """
  @spec write(Path.t(), map()) :: :ok | {:error, term()}
  def write(state_dir, material) when is_map(material) do
    :global.trans({{__MODULE__, Path.expand(state_dir)}, self()}, fn ->
      do_write(state_dir, material)
    end)
  end

  defp do_write(state_dir, material) do
    with {:ok, material} <- preserve_auth_floor(state_dir, material),
         {:ok, values} <- trusted_material(material),
         :ok <- File.mkdir_p(state_dir),
         :ok <- File.chmod(state_dir, 0o700),
         :ok <- write_text(state_dir, :certificate_pem, values.certificate_pem),
         :ok <- write_text(state_dir, :private_key_pem, values.private_key_pem),
         :ok <- write_text(state_dir, :ca_chain_pem, values.ca_chain_pem),
         :ok <- write_text(state_dir, :connect_info, values.encoded_connect_info) do
      atomic_identity_write(state_dir, values.encoded_identity)
    end
  end

  @doc """
  Loads trusted runtime material from the Agent state directory.
  """
  @spec load(Path.t()) :: {:ok, t()} | {:error, :missing_trusted_material | term()}
  def load(state_dir) do
    with :ok <- ensure_trusted_files(state_dir),
         :ok <- ensure_secure_permissions(state_dir),
         {:ok, certificate_pem} <- read_text(state_dir, :certificate_pem),
         {:ok, private_key_pem} <- read_text(state_dir, :private_key_pem),
         {:ok, ca_chain_pem} <- read_text(state_dir, :ca_chain_pem),
         {:ok, connect_info} <- read_json(state_dir, :connect_info),
         {:ok, identity} <- read_json(state_dir, :identity),
         {:ok, agent_id} <- fetch_agent_id(identity),
         :ok <- validate_auth_floor(identity) do
      {:ok,
       %__MODULE__{
         agent_id: agent_id,
         certificate_pem: certificate_pem,
         private_key_pem: private_key_pem,
         ca_chain_pem: ca_chain_pem,
         connect_info: connect_info,
         identity: identity
       }}
    end
  end

  @doc """
  Deletes trusted runtime material from the Agent state directory.
  """
  @spec delete_trusted_material(Path.t()) :: :ok | {:error, term()}
  def delete_trusted_material(state_dir) do
    Enum.reduce_while(@trusted_files, :ok, fn {_key, {file, _mode}}, :ok ->
      path = Path.join(state_dir, file)

      case File.rm(path) do
        :ok -> {:cont, :ok}
        {:error, :enoent} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {:delete_failed, path, reason}}}
      end
    end)
  end

  def persist_minimum_uds_auth_version(state_dir, floor) when floor in [1, 2] do
    :global.trans({{__MODULE__, Path.expand(state_dir)}, self()}, fn ->
      with {:ok, material} <- load(state_dir),
           current = Map.get(material.identity, "minimum_uds_auth_version", 1),
           next = max(current, floor),
           {:ok, encoded} <-
             Jason.encode(Map.put(material.identity, "minimum_uds_auth_version", next)),
           :ok <- atomic_identity_write(state_dir, encoded) do
        {:ok, next}
      end
    end)
  end

  def persist_minimum_uds_auth_version(_, _), do: {:error, :invalid_auth_floor}

  defp preserve_auth_floor(state_dir, material) do
    case read_json(state_dir, :identity) do
      {:ok, identity} ->
        with :ok <- validate_auth_floor(identity),
             {:ok, incoming} <- fetch_map(material, :identity),
             :ok <- validate_auth_floor(incoming) do
          merge_auth_floor(material, identity, incoming)
        end

      {:error, :enoent} ->
        {:ok, material}

      _ ->
        {:error, :invalid_trusted_material}
    end
  end

  defp merge_auth_floor(material, identity, incoming) do
    if Map.has_key?(identity, "minimum_uds_auth_version") do
      floor =
        max(
          identity["minimum_uds_auth_version"],
          Map.get(incoming, "minimum_uds_auth_version", 1)
        )

      {:ok, Map.put(material, :identity, Map.put(incoming, "minimum_uds_auth_version", floor))}
    else
      {:ok, material}
    end
  end

  defp validate_auth_floor(identity) when is_map(identity) do
    if Map.get(identity, "minimum_uds_auth_version", 1) in [1, 2],
      do: :ok,
      else: {:error, :invalid_auth_floor}
  end

  defp validate_auth_floor(_), do: {:error, :invalid_auth_floor}

  defp atomic_identity_write(state_dir, encoded) do
    path = Path.join(state_dir, "identity.json")
    temporary = path <> "." <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    try do
      with {:ok, fd} <- :file.open(to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
        result =
          try do
            with :ok <- :file.write(fd, encoded), do: :file.sync(fd)
          after
            :file.close(fd)
          end

        with :ok <- result,
             :ok <- File.chmod(temporary, 0o644),
             :ok <- File.rename(temporary, path),
             {:ok, directory} <- :file.open(to_charlist(state_dir), [:read, :raw, :directory]) do
          try do
            :file.sync(directory)
          after
            :file.close(directory)
          end
        end
      end
    after
      File.rm(temporary)
    end
  end

  defp trusted_material(material) do
    with {:ok, agent_id} <- fetch_binary(material, :agent_id),
         {:ok, certificate_pem} <- fetch_binary(material, :certificate_pem),
         {:ok, private_key_pem} <- fetch_binary(material, :private_key_pem),
         {:ok, ca_chain_pem} <- fetch_binary(material, :ca_chain_pem),
         {:ok, connect_info} <- fetch_map(material, :connect_info),
         {:ok, identity} <- fetch_map(material, :identity),
         identity <- Map.put_new(identity, "agent_id", agent_id),
         {:ok, encoded_connect_info} <- encode_json(:connect_info, connect_info),
         {:ok, encoded_identity} <- encode_json(:identity, identity) do
      {:ok,
       %{
         certificate_pem: certificate_pem,
         private_key_pem: private_key_pem,
         ca_chain_pem: ca_chain_pem,
         encoded_connect_info: encoded_connect_info,
         encoded_identity: encoded_identity
       }}
    end
  end

  defp fetch_binary(material, key) do
    case fetch_value(material, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      value when is_nil(value) or value == "" -> {:error, :missing_trusted_material}
      _invalid -> {:error, :invalid_trusted_material}
    end
  end

  defp fetch_map(material, key) do
    case fetch_value(material, key) do
      value when is_map(value) -> {:ok, value}
      nil -> {:error, :missing_trusted_material}
      _invalid -> {:error, :invalid_trusted_material}
    end
  end

  defp fetch_value(material, key) do
    case Map.fetch(material, key) do
      {:ok, value} -> value
      :error -> Map.get(material, Atom.to_string(key))
    end
  end

  defp encode_json(field, value) do
    case Jason.encode(value) do
      {:ok, encoded} -> {:ok, encoded}
      {:error, _reason} -> {:error, {:invalid_json, field}}
    end
  rescue
    _error -> {:error, {:invalid_json, field}}
  end

  defp fetch_agent_id(%{"agent_id" => agent_id}) when is_binary(agent_id) and agent_id != "" do
    {:ok, agent_id}
  end

  defp fetch_agent_id(%{agent_id: agent_id}) when is_binary(agent_id) and agent_id != "" do
    {:ok, agent_id}
  end

  defp fetch_agent_id(_identity), do: {:error, :missing_trusted_material}

  defp ensure_trusted_files(state_dir) do
    if Enum.all?(@trusted_files, fn {_key, {file, _mode}} ->
         File.regular?(Path.join(state_dir, file))
       end) do
      :ok
    else
      {:error, :missing_trusted_material}
    end
  end

  defp ensure_secure_permissions(state_dir) do
    with :ok <- verify_owner_only_mode(state_dir, 0o700, :state_dir) do
      {private_key_file, _mode} = Map.fetch!(@trusted_files, :private_key_pem)
      verify_owner_only_mode(Path.join(state_dir, private_key_file), 0o600, :private_key_pem)
    end
  end

  defp verify_owner_only_mode(path, expected_mode, key) do
    case File.stat(path) do
      {:ok, %{mode: mode}} ->
        actual_mode = Bitwise.band(mode, 0o777)

        if actual_mode == expected_mode do
          :ok
        else
          {:error, {:insecure_permissions, key}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp write_text(state_dir, key, value) do
    with {file, mode} <- Map.fetch!(@trusted_files, key),
         path <- Path.join(state_dir, file),
         :ok <- File.write(path, value) do
      File.chmod(path, mode)
    end
  end

  defp read_text(state_dir, key) do
    {file, _mode} = Map.fetch!(@trusted_files, key)
    File.read(Path.join(state_dir, file))
  end

  defp read_json(state_dir, key) do
    with {:ok, body} <- read_text(state_dir, key) do
      Jason.decode(body)
    end
  end
end
