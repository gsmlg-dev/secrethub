defmodule SecretHub.Shared.AccessAudit.TelemetryTest do
  use ExUnit.Case, async: false
  alias SecretHub.Shared.AccessAudit.Telemetry

  setup_all do
    {:ok, _} = Application.ensure_all_started(:telemetry)
    :ok
  end

  test "exports only bounded labels and numeric measurements" do
    id = "access-audit-test-#{System.unique_integer([:positive])}"
    event = [:secrethub, :access_audit, :request, :start]
    :telemetry.attach(id, event, &__MODULE__.forward/4, self())
    on_exit(fn -> :telemetry.detach(id) end)

    Telemetry.emit(:request_start, %{count: 1, raw_body: "secret-canary"}, %{
      source: "agent",
      operation: "read",
      reason_code: "allowed",
      request_id: Ecto.UUID.generate(),
      secret_path: "secret-canary",
      token: "token-canary"
    })

    assert_receive {:event, ^event, %{count: 1} = measurements, metadata}
    refute inspect(measurements) =~ "canary"
    refute inspect(metadata) =~ "canary"
    assert metadata == %{source: "agent", operation: "read", reason_code: "allowed"}
  end

  test "a detached failing exporter cannot fail the explicit durable operation" do
    id = "access-audit-failure-test-#{System.unique_integer([:positive])}"
    event = [:secrethub, :access_audit, :journal, :append_failure]
    :telemetry.attach(id, event, &__MODULE__.crash/4, nil)
    on_exit(fn -> :telemetry.detach(id) end)

    assert :ok = Telemetry.emit(:journal_append_failure, %{count: 1}, %{source: "agent"})
    refute Enum.any?(:telemetry.list_handlers(event), &(&1.id == id))
    assert :ok = Telemetry.emit(:journal_append_failure, %{count: 1}, %{source: "agent"})
  end

  def forward(event, measurements, metadata, pid),
    do: send(pid, {:event, event, measurements, metadata})

  def crash(_, _, _, _), do: raise("exporter failed")
end
