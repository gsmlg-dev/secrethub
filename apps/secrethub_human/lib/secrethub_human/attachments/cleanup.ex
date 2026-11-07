defmodule SecretHub.Human.Attachments.Cleanup do
  alias SecretHub.Human.Attachments
  @moduledoc false
  use Styx.Worker, queue: :human_audit, max_attempts: 5
  @impl Styx.Worker
  def perform(%Styx.Job{}), do: Attachments.cleanup()
end
