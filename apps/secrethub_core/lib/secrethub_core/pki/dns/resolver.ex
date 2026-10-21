defmodule SecretHub.Core.PKI.DNS.Resolver do
  @moduledoc "Bounded public DNS discovery and direct authoritative TXT observations."
  alias SecretHub.Core.PKI.DNS.Names
  @timeout 2_000

  def lookup(name, type) when type in [:cname, :ns] do
    case query(name, type, []) do
      {:ok, %{answers: answers}} ->
        {:ok, answers |> Enum.filter(&(&1.type == type)) |> Enum.map(& &1.data)}

      {:error, :nxdomain} ->
        {:ok, []}

      error ->
        error
    end
  end

  def authoritative_txt(owner, opts \\ []) do
    query = Keyword.get(opts, :dns_query, &query/3)

    with {:ok, servers} <- discover(Names.canonical_owner(owner), query, 12),
         true <- length(servers) <= Keyword.get(opts, :max_nameservers, 8) do
      observe_all(servers, owner, query)
    else
      false -> {:error, :too_many_nameservers}
      error -> error
    end
  end

  defp observe_all(servers, owner, query) do
    Enum.reduce_while(servers, {:ok, []}, fn server, {:ok, acc} ->
      case observe_server(server, owner, query) do
        {:ok, observation} -> {:cont, {:ok, [observation | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, observations} -> {:ok, Enum.reverse(observations)}
      error -> error
    end
  end

  defp observe_server(server, owner, query) do
    with {:ok, address} <- public_address(server, query),
         {:ok, response} <- query.(owner, :txt, nameservers: [{address, 53}], recurse: false) do
      values = response.answers |> Enum.filter(&(&1.type == :txt)) |> Enum.map(&join_txt(&1.data))
      {:ok, %{server: server, authoritative: response.authoritative, values: values}}
    end
  end

  defp discover(_, _, 0), do: {:error, :authority_discovery_limit}

  defp discover(owner, query, remaining) do
    case query.(owner, :ns, []) do
      {:ok, %{answers: answers}} ->
        case answers
             |> Enum.filter(&(&1.type == :ns))
             |> Enum.map(&Names.canonical_owner(&1.data))
             |> Enum.uniq() do
          [] -> discover_parent(owner, query, remaining)
          servers -> {:ok, servers}
        end

      {:error, :nxdomain} ->
        discover_parent(owner, query, remaining)

      error ->
        error
    end
  end

  defp discover_parent(owner, query, remaining) do
    case String.split(owner, ".", parts: 2) do
      [_, parent] -> discover(parent, query, remaining - 1)
      [_] -> {:error, :no_authoritative_servers}
    end
  end

  defp public_address(server, query) do
    with {:ok, %{answers: answers}} <- query.(server, :a, []) do
      case Enum.find(answers, &(&1.type == :a and public_address?(&1.data))) do
        %{data: address} -> {:ok, address}
        nil -> public_ipv6(server, query)
      end
    end
  end

  defp public_ipv6(server, query) do
    with {:ok, %{answers: answers}} <- query.(server, :aaaa, []) do
      case Enum.find(answers, &(&1.type == :aaaa and public_address?(&1.data))) do
        %{data: address} -> {:ok, address}
        nil -> {:error, :no_public_nameserver_address}
      end
    end
  end

  defp public_address?({a, _, _, _}) when a in [0, 10, 127] or a >= 224, do: false
  defp public_address?({100, b, _, _}) when b in 64..127, do: false
  defp public_address?({169, 254, _, _}), do: false
  defp public_address?({172, b, _, _}) when b in 16..31, do: false
  defp public_address?({192, 168, _, _}), do: false
  defp public_address?({192, 0, c, _}) when c in [0, 2], do: false
  defp public_address?({198, b, _, _}) when b in [18, 19], do: false
  defp public_address?({198, 51, 100, _}), do: false
  defp public_address?({203, 0, 113, _}), do: false
  defp public_address?({_, _, _, _}), do: true
  defp public_address?({first, _, _, _, _, _, _, _}), do: first in 0x2000..0x3FFF
  defp public_address?(_), do: false

  defp join_txt(chunks) when is_list(chunks), do: IO.iodata_to_binary(chunks)
  defp join_txt(value) when is_binary(value), do: value

  defp query(name, type, opts) do
    options = Keyword.merge([timeout: @timeout, retry: 1], opts)

    case :inet_res.resolve(String.to_charlist(name), :in, type, options, @timeout + 500) do
      {:ok, message} ->
        header = :inet_dns.msg(message, :header)

        answers =
          :inet_dns.msg(message, :anlist)
          |> Enum.map(fn rr ->
            %{
              type: :inet_dns.rr(rr, :type),
              data: normalize_data(:inet_dns.rr(rr, :data), :inet_dns.rr(rr, :type))
            }
          end)

        {:ok, %{authoritative: :inet_dns.header(header, :aa) == true, answers: answers}}

      {:error, {:nxdomain, _}} ->
        {:error, :nxdomain}

      {:error, :nxdomain} ->
        {:error, :nxdomain}

      {:error, _} ->
        {:error, :dns_unavailable}
    end
  end

  defp normalize_data(data, type) when type in [:ns, :cname], do: List.to_string(data)
  defp normalize_data(data, _), do: data
end
