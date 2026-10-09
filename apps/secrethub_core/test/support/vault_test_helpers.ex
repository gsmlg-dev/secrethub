defmodule SecretHub.Core.VaultTestHelpers do
  @moduledoc false

  import ExUnit.Assertions
  alias SecretHub.Core.Vault.SealState

  def await_vault_state(expected, timeout_ms \\ 2_000) do
    await_state(expected, System.monotonic_time(:millisecond) + timeout_ms)
  end

  defp await_state(expected, deadline) do
    status = SealState.status()

    cond do
      status.state == expected ->
        :ok

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("Expected Vault state #{inspect(expected)}, got #{inspect(status)}")

      true ->
        Process.sleep(10)
        await_state(expected, deadline)
    end
  end
end
