defmodule SecretHub.Human.Attachments.Usage do
  @moduledoc false
  use Ecto.Schema
  @primary_key {:user_id, :binary_id, autogenerate: false}
  schema "human_attachment_usage" do
    field(:bytes, :integer, default: 0)
  end
end
