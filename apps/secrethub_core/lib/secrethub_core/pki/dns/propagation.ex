defmodule SecretHub.Core.PKI.DNS.Propagation do
  @moduledoc "One bounded authoritative observation; callers durably schedule subsequent checks."
  alias SecretHub.Core.PKI.DNS.Resolver

  def check(owner, values, opts \\ [])

  def check(owner, values, opts) when is_list(values) and values != [] do
    resolver =
      Keyword.get(opts, :authoritative_resolver, fn owner ->
        Resolver.authoritative_txt(owner, opts)
      end)

    with {:ok, observations} <- resolver.(owner) do
      cond do
        observations == [] ->
          {:error, :no_authoritative_servers}

        not Enum.all?(observations, & &1.authoritative) ->
          {:error, :not_authoritative}

        Enum.all?(observations, fn observation ->
          Enum.all?(values, &(&1 in observation.values))
        end) ->
          {:ok, :propagated}

        true ->
          {:error, :not_propagated}
      end
    end
  end

  def check(_, _, _), do: {:error, :invalid_challenge_values}
end
