defmodule SecretHub.CLI.Commands.CredentialCommands do
  @moduledoc """
  `secrethub credential get|put|delete|list`: Agent-scoped host credentials.

  Values are read from stdin for `put` and are never accepted as arguments.
  Output is machine-readable JSON; `get --field value|username` prints that
  field's exact bytes. Errors return the Agent error code without values.
  """
  alias SecretHub.CLI.AgentClient

  @switches [
    namespace: :string,
    service: :string,
    authority: :string,
    account: :string,
    context: :string,
    entry_id: :string,
    username: :string,
    field: :string,
    cursor: :string,
    limit: :integer,
    agent_socket: :string,
    format: :string
  ]

  @doc "Returns `{stdout, exit_status, diagnostics}`."
  def run(args, stdin_reader \\ fn -> IO.read(:stdio, :eof) end, opts \\ []) do
    client = Keyword.get(opts, :client, &AgentClient.credential/3)

    case OptionParser.parse(args, strict: @switches) do
      {parsed, [action], []} when action in ~w(get put delete list) ->
        client_opts =
          if parsed[:agent_socket], do: [socket_path: parsed[:agent_socket]], else: []

        execute(action, parsed, stdin_reader, fn agent_action, params ->
          client.(agent_action, params, client_opts)
        end)

      {_, _, invalid} when invalid != [] ->
        usage("invalid options: #{Enum.map_join(invalid, ", ", &elem(&1, 0))}")

      _ ->
        usage("expected get, put, delete or list")
    end
  end

  defp execute("get", parsed, _stdin, call) do
    with {:ok, params} <- lookup(parsed) do
      case {call.("credential_get", params), parsed[:field]} do
        {{:ok, data}, nil} -> {Jason.encode!(data) <> "\n", 0, []}
        {{:ok, data}, field} when field in ~w(value username) -> {data[field], 0, []}
        {{:ok, _}, _} -> usage("--field must be value or username")
        {{:error, code}, _} -> fail(code)
      end
    end
  end

  defp execute("put", parsed, stdin, call) do
    with {:ok, params} <- lookup(parsed),
         :ok <- if(params["entry_id"], do: {:error, "put requires a selector"}, else: :ok),
         value when is_binary(value) <- stdin.() do
      params =
        params
        |> Map.put("value", value)
        |> then(&if(parsed[:username], do: Map.put(&1, "username", parsed[:username]), else: &1))

      result(call.("credential_put", params))
    else
      {:error, message} -> usage(message)
      {_stdout, _status, _diagnostics} = usage -> usage
      _ -> usage("value must be supplied on stdin")
    end
  end

  defp execute("delete", parsed, _stdin, call) do
    with {:ok, params} <- lookup(parsed), do: result(call.("credential_delete", params))
  end

  defp execute("list", parsed, _stdin, call) do
    params =
      %{"namespace" => parsed[:namespace] || "generic"}
      |> maybe_put("cursor", parsed[:cursor])
      |> maybe_put("limit", parsed[:limit])

    result(call.("credential_list", params))
  end

  defp lookup(parsed) do
    cond do
      parsed[:entry_id] ->
        {:ok, %{"entry_id" => parsed[:entry_id]}}

      parsed[:namespace] && parsed[:service] ->
        {:ok,
         %{"namespace" => parsed[:namespace], "service" => parsed[:service]}
         |> maybe_put("authority", parsed[:authority])
         |> maybe_put("context", parsed[:context])
         |> maybe_put("account", parsed[:account])}

      true ->
        usage("--entry-id or --namespace and --service are required")
    end
  end

  defp result({:ok, data}), do: {Jason.encode!(data) <> "\n", 0, []}
  defp result({:error, code}), do: fail(code)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp fail(code), do: {"", 1, ["secrethub: credential operation failed: #{code}"]}
  defp usage(message), do: {"", 2, ["secrethub credential: " <> message]}
end
