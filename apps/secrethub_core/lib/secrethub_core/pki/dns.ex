defmodule SecretHub.Core.PKI.DNS do
  @moduledoc "Scoped DNS-01 adapter entry points. Persistence and mutation claims belong to the coordinator."
  alias SecretHub.Core.PKI.DNS.{Cloudflare, Names, Propagation, Route53}

  defdelegate normalize_identifier(value), to: Names
  defdelegate normalize_identifiers(values), to: Names
  defdelegate challenge_owner(identifier), to: Names
  defdelegate bind(identifier, bindings), to: Names
  def effective_owner(owner, binding, opts \\ []), do: Names.effective_owner(owner, binding, opts)
  def propagated?(owner, values, opts \\ []), do: Propagation.check(owner, values, opts)

  def validate_zone(config, credentials, opts \\ []),
    do: dispatch(config, :validate_zone, [config, credentials, opts])

  def observe(config, credentials, owner, opts \\ []),
    do: dispatch(config, :observe, [config, credentials, owner, opts])

  def prepare(config, credentials, intent, opts \\ []) do
    case adapter(config) do
      {:ok, Route53} -> Route53.prepare(config, credentials, intent, opts)
      {:ok, Cloudflare} -> {:ok, intent}
      error -> error
    end
  end

  def present(config, credentials, intent, opts \\ []),
    do: dispatch(config, :present, [config, credentials, intent, opts])

  def reconcile(config, credentials, intent, opts \\ []),
    do: dispatch(config, :reconcile, [config, credentials, intent, opts])

  def cleanup(config, credentials, receipt, opts \\ []),
    do: dispatch(config, :cleanup, [config, credentials, receipt, opts])

  def poll_change(config, credentials, receipt, opts \\ []) do
    case adapter(config) do
      {:ok, Route53} -> Route53.poll_change(config, credentials, receipt, opts)
      {:ok, Cloudflare} -> {:ok, receipt}
      error -> error
    end
  end

  defp dispatch(config, function, args) do
    with {:ok, module} <- adapter(config), do: apply(module, function, args)
  end

  defp adapter(%{"provider" => "cloudflare"}), do: {:ok, Cloudflare}
  defp adapter(%{"provider" => "route53"}), do: {:ok, Route53}
  defp adapter(_), do: {:error, :unsupported_provider}
end
