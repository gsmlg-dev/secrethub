defmodule SecretHub.Core.Engines.Dynamic.TestEngine do
  @moduledoc """
  A stub dynamic engine for testing purposes.

  Always succeeds for renew and revoke operations without connecting to any external system.
  """

  def renew_lease(_lease_id, opts) do
    increment = Keyword.get(opts, :increment, 3600)
    current_ttl = Keyword.get(opts, :current_ttl, 0)
    config = Keyword.get(opts, :config, %{})
    max_ttl = config["max_ttl"] || 86_400
    new_ttl = min(current_ttl + increment, max_ttl)
    {:ok, %{ttl: new_ttl}}
  end

  def revoke_credentials(_lease_id, _credentials) do
    :ok
  end

  def generate_credentials(_role_name, _opts) do
    {:ok,
     %{
       username: "v_test_#{:rand.uniform(10_000)}",
       password: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower),
       ttl: 3600,
       metadata: %{host: "localhost", database: "testdb"}
     }}
  end

  def validate_config(_config), do: :ok
end
