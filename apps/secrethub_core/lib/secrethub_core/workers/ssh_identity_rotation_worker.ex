defmodule SecretHub.Core.Workers.SSHIdentityRotationWorker do
  @moduledoc "Hourly SSH identity rotation: requests Agent rotations, flags due external keys, prunes old keys."
  use Styx.Worker,
    queue: :ssh,
    max_attempts: 3,
    unique: [period: 3000, states: [:available, :scheduled, :executing, :retryable]]

  require Logger

  @impl true
  def perform(_) do
    case SecretHub.Core.SSH.rotate_due() do
      {:ok, _events} ->
        :ok

      {:error, :sealed} ->
        :ok

      {:error, reason} ->
        Logger.warning("SSH identity rotation failed", reason: inspect(reason))
        {:error, reason}
    end
  end
end
