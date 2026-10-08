defmodule SecretHub.Human.CoreIdentity do
  alias SecretHub.Human.Organizations
  alias SecretHub.HumanWeb.Bitwarden.Token

  @moduledoc "Trusted co-hosted identity adapter; Core consumes verified attributes, never caller-supplied principals."
  def verify(token) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, groups} <- groups(actor) do
      {:ok,
       %{
         subject_id: actor.user_id,
         session_id: actor.session_id,
         device_id: actor.device_id,
         groups: groups,
         auth_strength: actor.authentication_level
       }}
    end
  end

  defp groups(actor) do
    if Code.ensure_loaded?(SecretHub.Human.Organizations),
      do: Organizations.memberships(actor),
      else: {:ok, []}
  end
end
