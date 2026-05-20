defmodule SecretHub.Core.Engines.Dynamic.AWSSTS do
  @moduledoc """
  AWS STS dynamic secret engine placeholder.

  AWS integration is intentionally disabled in this build because the ExAws
  dependency tree is not included.
  """

  @behaviour SecretHub.Core.Engines.Dynamic

  alias SecretHub.Core.Engines.Dynamic

  @impl Dynamic
  def generate_credentials(_role_name, _opts), do: {:error, :aws_sts_engine_not_available}

  @impl Dynamic
  def revoke_credentials(_lease_id, _credentials), do: :ok

  @impl Dynamic
  def renew_lease(_lease_id, _opts), do: {:error, :not_renewable}

  @impl Dynamic
  def validate_config(_config), do: {:error, ["AWS STS engine is not available in this build"]}
end
