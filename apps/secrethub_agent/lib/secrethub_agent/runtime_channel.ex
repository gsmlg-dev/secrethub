defmodule SecretHub.Agent.RuntimeChannel do
  @moduledoc """
  Preserves runtime push envelopes for the Agent connection while retaining
  the socket client's join and request-reply handling.
  """

  use Phoenix.SocketClient.Channel

  @impl true
  def handle_info(%Message{event: "phx_reply"} = message, state) do
    super(message, state)
  end

  def handle_info(%Message{} = message, state) do
    send(state.caller, message)
    super(message, state)
  end

  @impl true
  def handle_message(_event, _payload, state), do: {:noreply, state}
end
