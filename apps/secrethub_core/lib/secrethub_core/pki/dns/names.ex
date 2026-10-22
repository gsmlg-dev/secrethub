defmodule SecretHub.Core.PKI.DNS.Names do
  @moduledoc "DNS identifier canonicalization and explicitly scoped challenge bindings."
  alias SecretHub.Core.PKI.DNS.Resolver
  @private_suffixes ~w(local localhost internal invalid onion home lan)

  def normalize_identifiers(names) when is_list(names) and names != [] do
    Enum.reduce_while(names, {:ok, []}, fn name, {:ok, acc} ->
      case normalize_identifier(name) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, normalized |> Enum.uniq() |> Enum.sort()}
      error -> error
    end
  end

  def normalize_identifiers(_), do: {:error, :invalid_identifier}

  def normalize_identifier(value) when is_binary(value) do
    value = value |> String.trim() |> String.trim_trailing(".") |> String.downcase()

    {prefix, domain} =
      if String.starts_with?(value, "*."),
        do: {"*.", String.slice(value, 2..-1//1)},
        else: {"", value}

    with {:ok, ascii} <- ascii(domain),
         true <- valid_domain?(ascii),
         false <- ip_address?(ascii) do
      {:ok, prefix <> ascii}
    else
      _ -> {:error, :invalid_identifier}
    end
  end

  def normalize_identifier(_), do: {:error, :invalid_identifier}

  def challenge_owner(identifier) do
    with {:ok, normalized} <- normalize_identifier(identifier) do
      {:ok, "_acme-challenge." <> String.trim_leading(normalized, "*.")}
    end
  end

  def within_zone?(name, zone) when is_binary(name) and is_binary(zone) do
    name = canonical_owner(name)
    zone = canonical_owner(zone)
    name == zone or String.ends_with?(name, "." <> zone)
  end

  def within_zone?(_, _), do: false

  def bind(identifier, bindings) when is_list(bindings) do
    with {:ok, normalized} <- normalize_identifier(identifier) do
      matches =
        Enum.filter(
          bindings,
          &within_zone?(String.trim_leading(normalized, "*."), &1["suffix"] || &1["zone_name"])
        )

      select_binding(matches)
    end
  end

  defp select_binding(matches) do
    case Enum.sort_by(matches, &String.length(&1["suffix"] || &1["zone_name"]), :desc) do
      [] ->
        {:error, :unbound_identifier}

      [binding] ->
        {:ok, binding}

      [first, second | _] ->
        if String.length(first["suffix"] || first["zone_name"]) ==
             String.length(second["suffix"] || second["zone_name"]),
           do: {:error, :ambiguous_binding},
           else: {:ok, first}
    end
  end

  def effective_owner(owner, binding, opts \\ []) do
    resolver = Keyword.get(opts, :resolver, &Resolver.lookup/2)
    original = canonical_owner(owner)
    expected = binding["delegated_owner"] && canonical_owner(binding["delegated_owner"])

    with {:ok, final} <-
           follow(original, resolver, [], Keyword.get(opts, :max_cname_hops, 8)),
         :ok <- delegation_allowed(original, final, expected),
         true <- within_zone?(final, binding["zone_name"]) do
      {:ok, final}
    else
      false -> {:error, :wrong_zone}
      error -> error
    end
  end

  def canonical_owner(owner) when is_binary(owner),
    do: owner |> String.downcase() |> String.trim_trailing(".")

  def canonical_owner(_), do: ""

  defp ascii(domain) do
    {:ok,
     domain |> String.to_charlist() |> :idna.encode([:uts46, :std3_rules]) |> List.to_string()}
  rescue
    _ -> {:error, :invalid_identifier}
  catch
    _, _ -> {:error, :invalid_identifier}
  end

  defp valid_domain?(domain) do
    labels = String.split(domain, ".")

    byte_size(domain) <= 253 and length(labels) >= 2 and
      List.last(labels) not in @private_suffixes and
      Enum.all?(
        labels,
        &(byte_size(&1) in 1..63 and Regex.match?(~r/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, &1))
      ) and
      Regex.match?(~r/[a-z]/, List.last(labels))
  end

  defp ip_address?(domain), do: match?({:ok, _}, :inet.parse_address(String.to_charlist(domain)))

  @spec follow(
          String.t(),
          (String.t(), :cname -> {:ok, [String.t()]} | {:error, term()}),
          [String.t()],
          integer()
        ) :: {:ok, String.t()} | {:error, term()}
  defp follow(_, _, _, remaining) when remaining < 0, do: {:error, :delegation_too_deep}

  defp follow(owner, resolver, seen, remaining) do
    if owner in seen do
      {:error, :delegation_loop}
    else
      case resolver.(owner, :cname) do
        {:ok, []} ->
          {:ok, owner}

        {:ok, [next]} when is_binary(next) ->
          follow(canonical_owner(next), resolver, [owner | seen], remaining - 1)

        {:ok, _} ->
          {:error, :ambiguous_delegation}

        {:error, _} = error ->
          error
      end
    end
  end

  defp delegation_allowed(original, original, nil), do: :ok
  defp delegation_allowed(_, final, final), do: :ok
  defp delegation_allowed(_, _, nil), do: {:error, :unconfigured_delegation}
  defp delegation_allowed(_, _, _), do: {:error, :delegation_mismatch}
end
