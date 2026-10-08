defmodule SecretHub.Human.Attachments.Cleanup do
  alias SecretHub.Human.Attachments
  @moduledoc false
  use Oban.Worker, queue: :human_audit, max_attempts: 5
  @impl Oban.Worker
  def perform(%Oban.Job{}), do: Attachments.cleanup()
end
