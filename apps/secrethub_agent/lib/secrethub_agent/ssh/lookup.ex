defmodule SecretHub.Agent.SSH.Lookup do
  @moduledoc "Strict public lookup requests and OpenSSH output validation."
  alias SecretHub.Agent.SSH.Identity
  alias SecretHub.Shared.SSH.Key

  def request(input, uid, request, timeout \\ 2000)

  def request(
        %{"operation" => "authorized_keys", "username" => user, "key" => key} = input,
        _uid,
        request,
        _timeout
      )
      when map_size(input) == 3 and is_binary(key) do
    with true <- Identity.username?(user),
         {:ok, public} <- Key.decode_public(key),
         {:ok, reply} <-
           request.("authorized_keys", %{"username" => user, "key" => public.encoded}) do
      validate_lines("authorized_keys", value(reply, "lines"))
    else
      _ -> {:error, :lookup_failed}
    end
  end

  def request(
        %{"operation" => "known_hosts", "reason" => reason, "host" => host, "port" => port} =
          input,
        uid,
        request,
        timeout
      )
      when map_size(input) == 4 do
    with true <- reason in ["ORDER", "HOSTNAME", "ADDRESS"],
         true <- host?(host),
         true <- is_integer(port) and port in 1..65_535,
         {:ok, identity} <- Identity.account(uid, timeout),
         {:ok, reply} <-
           request.("known_hosts", %{
             "uid" => uid,
             "username" => identity.username,
             "reason" => reason,
             "host" => host,
             "port" => port
           }) do
      validate_lines("known_hosts", value(reply, "lines"))
    else
      _ -> {:error, :lookup_failed}
    end
  end

  def request(_, _, _, _), do: {:error, :invalid_request}

  def validate_lines(operation, lines) when is_list(lines) and length(lines) <= 4096 do
    if Enum.all?(lines, &line?(operation, &1)),
      do: {:ok, lines},
      else: {:error, :invalid_response}
  end

  def validate_lines(_, _), do: {:error, :invalid_response}

  defp line?("authorized_keys", line) when is_binary(line) and byte_size(line) <= 16_384 do
    case String.split(line, " ", trim: true) do
      ["no-agent-forwarding", type, key] ->
        match?({:ok, _}, Key.decode_public(type <> " " <> key))

      _ ->
        false
    end
  end

  defp line?("known_hosts", line) when is_binary(line) and byte_size(line) <= 16_384 do
    case String.split(line, " ", trim: true) do
      [host, type, key] -> host?(host) and match?({:ok, _}, Key.decode_public(type <> " " <> key))
      _ -> false
    end
  end

  defp line?(_, _), do: false

  defp host?(host) when is_binary(host),
    do: byte_size(host) in 1..1024 and Regex.match?(~r/\A[A-Za-z0-9_.:\[\]-]+\z/, host)

  defp host?(_), do: false
  def value(map, key), do: Map.get(map, key) || Map.get(map, existing_key(key))
  defp existing_key("lines"), do: :lines
  defp existing_key("identities"), do: :identities
  defp existing_key("public_key"), do: :public_key
  defp existing_key("private_key"), do: :private_key
end
