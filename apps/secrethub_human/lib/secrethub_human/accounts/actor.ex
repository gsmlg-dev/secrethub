defmodule SecretHub.Human.Accounts.Actor do
  @moduledoc "Session-derived Human identity. Commands must revalidate its proof."
  @derive {Inspect, except: [:proof]}
  @enforce_keys [:id, :user_id, :session_id, :device_id, :proof]
  defstruct [:id, :user_id, :session_id, :device_id, :proof, authentication_level: :password]
end
