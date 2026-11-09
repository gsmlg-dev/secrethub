defmodule SecretHub.Shared.HostCredentials do
  @moduledoc """
  Bounded wire contract for Agent-scoped host credentials (`host_credentials_v1`).

  Adapters (Git, Docker, generic keyring) normalize their own protocol input
  into these lookup fields. This module only validates shape and size; it never
  interprets URLs or applies adapter-specific aliases. Lookup fields are data:
  they never become policy paths. Entries are authorized through opaque
  resources derived from the authenticated Agent UUID and the entry UUID.
  """

  @capability "host_credentials_v1"
  @namespaces ~w(git docker generic)
  @operations ~w(credential_read credential_write credential_delete credential_list)
  @actions %{
    "credential_get" => "credential_read",
    "credential_put" => "credential_write",
    "credential_delete" => "credential_delete",
    "credential_list" => "credential_list"
  }
  @resource_root "host-credentials"
  @max_value_bytes 16_384
  @max_list_limit 100
  @limits %{
    "service" => 255,
    "authority" => 255,
    "context" => 1024,
    "account" => 512,
    "username" => 512
  }
  @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  def capability, do: @capability
  def namespaces, do: @namespaces
  def operations, do: @operations
  def actions, do: Map.keys(@actions)
  def operation(action), do: Map.fetch(@actions, action)
  def max_value_bytes, do: @max_value_bytes
  def max_list_limit, do: @max_list_limit
  def resource_root, do: @resource_root

  @doc "Collection resource used for creation and initial listing authorization."
  def collection_resource(agent_uuid, namespace)
      when is_binary(agent_uuid) and namespace in @namespaces,
      do: Enum.join([@resource_root, agent_uuid, namespace], ".")

  @doc "Opaque per-entry resource; never derived from caller lookup fields."
  def entry_resource(agent_uuid, namespace, entry_id)
      when is_binary(agent_uuid) and namespace in @namespaces and is_binary(entry_id),
      do: Enum.join([@resource_root, agent_uuid, namespace, entry_id], ".")

  @doc "True for resources reserved to credential operations."
  def reserved_path?(path) when is_binary(path),
    do: path == @resource_root or String.starts_with?(path, @resource_root <> ".")

  def reserved_path?(_), do: false

  @doc """
  Validates a credential request. Lookup requests contain either an `entry_id`
  or a complete namespace selector. `account` may be `nil` for Git lookups to
  request a unique match; it is never broadened beyond its namespace.
  """
  def validate(action, params)

  def validate("credential_get", params) when is_map(params) do
    allowed = ~w(namespace service authority context account entry_id)

    with {:ok, lookup} <- validate_lookup(Map.delete(params, "known"), allowed),
         {:ok, known} <- known(params["known"]) do
      {:ok, Map.put(lookup, "known", known)}
    end
  end

  def validate("credential_delete", params) when is_map(params) do
    allowed = ~w(namespace service authority context account entry_id expected_value)

    with {:ok, lookup} <- validate_lookup(Map.delete(params, "expected_value"), allowed),
         {:ok, expected} <- optional_value(params["expected_value"]) do
      {:ok, Map.put(lookup, "expected_value", expected)}
    end
  end

  def validate("credential_put", params) when is_map(params) do
    allowed = ~w(namespace service authority context account username value)

    with :ok <- only(params, allowed),
         {:ok, selector} <- selector(params, :store),
         {:ok, username} <- username(selector, params["username"]),
         {:ok, value} <- value(params["value"]) do
      {:ok, Map.merge(selector, %{"username" => username, "value" => value})}
    end
  end

  def validate("credential_list", params) when is_map(params) do
    with :ok <- only(params, ~w(namespace cursor limit)),
         namespace when namespace in @namespaces <- params["namespace"],
         {:ok, cursor} <- optional_uuid(params["cursor"]),
         {:ok, limit} <- limit(Map.get(params, "limit")) do
      {:ok, %{"namespace" => namespace, "cursor" => cursor, "limit" => limit}}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_request}
    end
  end

  def validate(_, _), do: {:error, :invalid_request}

  def uuid?(value), do: is_binary(value) and Regex.match?(@uuid, value)

  defp validate_lookup(%{"entry_id" => id} = params, allowed) do
    with :ok <- only(params, allowed),
         true <- map_size(Map.delete(params, "entry_id")) == 0 and uuid?(id) do
      {:ok, %{"entry_id" => id}}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_request}
    end
  end

  defp validate_lookup(params, allowed) do
    with :ok <- only(params, List.delete(allowed, "entry_id")), do: selector(params, :lookup)
  end

  defp selector(params, mode) do
    with namespace when namespace in @namespaces <- params["namespace"],
         {:ok, fields} <- fields(params),
         :ok <- namespace_rules(namespace, fields, mode) do
      {:ok, Map.put(fields, "namespace", namespace)}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_request}
    end
  end

  defp fields(params) do
    ~w(service authority context account)
    |> Enum.reduce_while({:ok, %{}}, fn key, {:ok, acc} ->
      case field(key, Map.get(params, key, default(key))) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
        :error -> {:halt, {:error, :invalid_request}}
      end
    end)
  end

  defp default("account"), do: nil
  defp default(_), do: ""

  defp field("account", nil), do: {:ok, nil}

  defp field(key, value) when is_binary(value) do
    if byte_size(value) <= @limits[key] and text?(value), do: {:ok, value}, else: :error
  end

  defp field(_, _), do: :error

  # Git: protocol and host (with port) are required; path is preserved exactly.
  defp namespace_rules("git", fields, mode) do
    ok =
      Regex.match?(~r/\A[a-z][a-z0-9+.-]{0,31}\z/, fields["service"]) and
        fields["authority"] != "" and (mode == :lookup or is_binary(fields["account"]))

    if ok, do: :ok, else: {:error, :invalid_request}
  end

  # Docker: one active credential per normalized registry key.
  defp namespace_rules("docker", fields, _mode) do
    ok =
      fields["service"] != "" and fields["authority"] == "" and fields["context"] == "" and
        fields["account"] in [nil, ""]

    if ok, do: :ok, else: {:error, :invalid_request}
  end

  # Generic keyring: exact service and username, no URL normalization. A
  # lookup without a username (keyring `get_credential(service, None)`) must
  # resolve to a unique entry; stores always name the username.
  defp namespace_rules("generic", fields, mode) do
    ok =
      fields["service"] != "" and fields["authority"] == "" and fields["context"] == "" and
        (mode == :lookup or is_binary(fields["account"]))

    if ok, do: :ok, else: {:error, :invalid_request}
  end

  defp username(%{"namespace" => "docker"}, username) when is_binary(username) do
    if byte_size(username) <= @limits["username"] and text?(username),
      do: {:ok, username},
      else: {:error, :invalid_request}
  end

  defp username(%{"namespace" => "docker"}, _), do: {:error, :invalid_request}
  defp username(%{"account" => account}, nil), do: {:ok, account}
  defp username(%{"account" => account}, account), do: {:ok, account}
  defp username(_, _), do: {:error, :invalid_request}

  @doc "Values are exact UTF-8 strings; empty is a value, not a deletion request."
  def value(value) when is_binary(value) and byte_size(value) <= @max_value_bytes do
    if String.valid?(value), do: {:ok, value}, else: {:error, :invalid_request}
  end

  def value(_), do: {:error, :invalid_request}

  # Exact cached revisions; Core still authorizes before acknowledging them.
  defp known(nil), do: {:ok, nil}

  defp known(
         %{"entry_id" => id, "binding_revision" => binding, "source_revision" => source} = map
       )
       when map_size(map) == 3 and is_integer(binding) and binding > 0 and is_integer(source) and
              source > 0 do
    if uuid?(id), do: {:ok, map}, else: {:error, :invalid_request}
  end

  defp known(_), do: {:error, :invalid_request}

  defp optional_value(nil), do: {:ok, nil}
  defp optional_value(value), do: value(value)

  defp optional_uuid(nil), do: {:ok, nil}
  defp optional_uuid(value), do: if(uuid?(value), do: {:ok, value}, else: :error)

  defp limit(nil), do: {:ok, @max_list_limit}
  defp limit(value) when is_integer(value) and value in 1..@max_list_limit, do: {:ok, value}
  defp limit(_), do: :error

  defp only(params, allowed) do
    if Enum.all?(Map.keys(params), &(&1 in allowed)),
      do: :ok,
      else: {:error, :invalid_request}
  end

  # Lookup fields are printable text: no NUL or other C0 control characters.
  defp text?(value),
    do: String.valid?(value) and not String.match?(value, ~r/[\x00-\x1f\x7f]/u)
end
