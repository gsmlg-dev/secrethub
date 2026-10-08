defmodule SecretHub.Human.Notifications do
  @moduledoc "User-scoped invalidation notifications; no vault contents or credentials are broadcast."
  def changed(actor),
    do: Phoenix.PubSub.broadcast(SecretHub.Human.PubSub, topic(actor.user_id), :vault_changed)

  def topic(user_id), do: "human-vault:" <> user_id
end
