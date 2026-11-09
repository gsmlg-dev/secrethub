defmodule SecretHub.CLI.GitCredential do
  @moduledoc """
  `git-credential-secrethub`: Git credential helper protocol (gitcredentials(7)).

  `run/3` is a pure adapter from Git's line protocol to the Agent's
  `credential_*` actions. It returns `{stdout, exit_status, diagnostics}`:
  stdout carries only protocol output, diagnostics go to stderr.

  * A genuine miss or an ambiguous account is an ordinary helper miss: empty
    stdout, status 0.
  * An unavailable or denying Agent is a hard failure: `quit=true` for `get`
    and a non-zero status, so Git does not fall through as if it were a miss.
  * The path is used only when Git supplies it (`credential.useHttpPath`).
  """
  alias SecretHub.CLI.AgentClient

  @miss ~w(NOT_FOUND AMBIGUOUS)

  def run(operation, input, opts \\ [])

  def run(operation, input, opts) when operation in ~w(get store erase) do
    client = Keyword.get(opts, :client, &AgentClient.credential/3)

    with {:ok, fields} <- parse(input),
         {:ok, fields} <- expand_url(fields),
         {:ok, selector} <- selector(fields) do
      apply_operation(operation, fields, selector, client, opts)
    else
      {:error, message} -> failure(operation, message)
    end
  end

  # Git ignores unknown future operations; so does this helper.
  def run(_operation, _input, _opts), do: {"", 0, []}

  defp apply_operation("get", _fields, selector, client, opts) do
    case client.("credential_get", selector, opts) do
      {:ok, %{"username" => username, "value" => value}} ->
        if line_safe?(username) and line_safe?(value),
          do: {"username=#{username}\npassword=#{value}\n", 0, []},
          else: failure("get", "credential cannot be represented in Git's line protocol")

      {:error, code} when code in @miss ->
        {"", 0, []}

      {:error, code} ->
        failure("get", "credential lookup failed: #{code}")

      _ ->
        failure("get", "credential lookup failed: invalid Agent response")
    end
  end

  defp apply_operation("store", fields, selector, client, opts) do
    with username when is_binary(username) <- fields["username"],
         password when is_binary(password) <- fields["password"] do
      params = selector |> Map.put("account", username) |> Map.put("value", password)

      case client.("credential_put", params, opts) do
        {:ok, _} -> {"", 0, []}
        {:error, code} -> failure("store", "credential store failed: #{code}")
      end
    else
      _ -> {"", 0, []}
    end
  end

  # Erase honors every supplied constraint: account, path and password. A
  # stale password never erases a newer value; several accounts are refused.
  defp apply_operation("erase", fields, selector, client, opts) do
    params =
      case fields["password"] do
        nil -> selector
        password -> Map.put(selector, "expected_value", password)
      end

    case client.("credential_delete", params, opts) do
      {:ok, _} -> {"", 0, []}
      {:error, code} -> failure("erase", "credential erase failed: #{code}")
    end
  end

  defp selector(%{"protocol" => protocol, "host" => host} = fields) do
    {:ok,
     %{
       "namespace" => "git",
       "service" => protocol,
       "authority" => host,
       "context" => Map.get(fields, "path", ""),
       "account" => fields["username"]
     }}
  end

  defp selector(_), do: {:error, "protocol and host are required"}

  @doc false
  def parse(input) when is_binary(input) do
    input
    |> String.split("\n")
    |> Enum.take_while(&(&1 != ""))
    |> Enum.reduce_while({:ok, %{}}, fn line, {:ok, fields} ->
      line
      |> String.trim_trailing("\r")
      |> String.split("=", parts: 2)
      |> field(fields)
    end)
  end

  def parse(_), do: {:error, "unreadable input"}

  defp field([key, value], fields) do
    cond do
      String.contains?(key <> value, <<0>>) -> {:halt, {:error, "NUL in credential field"}}
      not String.valid?(value) -> {:halt, {:error, "credential field is not UTF-8"}}
      # Multi-valued attributes (capability[], wwwauth[]) are ignored.
      String.ends_with?(key, "[]") -> {:cont, {:ok, fields}}
      Map.has_key?(fields, key) -> {:cont, {:ok, fields}}
      true -> {:cont, {:ok, Map.put(fields, key, value)}}
    end
  end

  defp field(_line, _fields), do: {:halt, {:error, "malformed credential line"}}

  # Git sends components to helpers, but a `url=` attribute is accepted too.
  defp expand_url(%{"url" => url} = fields) when not is_map_key(fields, "protocol") do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host} = uri} when is_binary(scheme) and is_binary(host) ->
        authority =
          if uri.port && uri.port != URI.default_port(scheme),
            do: "#{host}:#{uri.port}",
            else: host

        path = uri.path |> to_string() |> String.trim_leading("/")

        {:ok,
         fields
         |> Map.put("protocol", scheme)
         |> Map.put("host", authority)
         |> Map.put_new("username", uri.userinfo && hd(String.split(uri.userinfo, ":")))
         |> then(&if(path == "", do: &1, else: Map.put_new(&1, "path", path)))
         |> Map.reject(fn {_k, v} -> is_nil(v) end)}

      _ ->
        {:error, "invalid credential url"}
    end
  end

  defp expand_url(fields), do: {:ok, fields}

  defp line_safe?(value), do: not String.contains?(value, ["\n", <<0>>])

  defp failure("get", message), do: {"quit=true\n", 1, ["secrethub: " <> message]}
  defp failure(_operation, message), do: {"", 1, ["secrethub: " <> message]}
end
