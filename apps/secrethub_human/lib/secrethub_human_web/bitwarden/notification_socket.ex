defmodule SecretHub.HumanWeb.Bitwarden.NotificationSocket do
  @moduledoc false
  @behaviour WebSock
  alias SecretHub.Human.{Accounts, Notifications}
  alias SecretHub.HumanWeb.Bitwarden.SignalR

  @impl true
  def init(actor) do
    case Accounts.validate_actor(actor) do
      {:ok, _} ->
        Phoenix.PubSub.subscribe(SecretHub.Human.PubSub, Notifications.topic(actor.user_id))
        Process.send_after(self(), :heartbeat, 15_000)
        {:ok, %{actor: actor, protocol: nil}}

      {:error, _} ->
        {:stop, :normal, 1008, %{actor: actor, protocol: nil}}
    end
  end

  @impl true
  def handle_in({data, [opcode: :text]}, %{protocol: nil} = state) do
    case SignalR.handshake(data) do
      {:ok, protocol} -> {:push, {:text, "{}\x1e"}, %{state | protocol: protocol}}
      {:error, _} -> {:stop, :normal, 1002, state}
    end
  end

  def handle_in({<<2, 0x91, 6>>, [opcode: :binary]}, %{protocol: :messagepack} = state),
    do: {:ok, state}

  def handle_in({"{\"type\":6}\x1e", [opcode: :text]}, %{protocol: :json} = state),
    do: {:ok, state}

  def handle_in(_, state), do: {:stop, :normal, 1002, state}

  @impl true
  def handle_info(:heartbeat, %{protocol: nil} = state), do: {:stop, :normal, 1002, state}

  def handle_info(:heartbeat, state) do
    case Accounts.validate_actor(state.actor) do
      {:ok, _} ->
        Process.send_after(self(), :heartbeat, 15_000)
        {:push, SignalR.heartbeat(state.protocol), state}

      {:error, _} ->
        {:stop, :normal, 1008, state}
    end
  end

  def handle_info(:vault_changed, %{protocol: nil} = state), do: {:ok, state}

  def handle_info(:vault_changed, state) do
    case Accounts.validate_actor(state.actor) do
      {:ok, _} -> {:push, SignalR.vault_changed(state.protocol, state.actor.user_id), state}
      {:error, _} -> {:stop, :normal, 1008, state}
    end
  end

  def handle_info(_, state), do: {:ok, state}
end
