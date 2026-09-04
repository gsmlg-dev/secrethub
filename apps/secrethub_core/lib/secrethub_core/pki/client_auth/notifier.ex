defmodule SecretHub.Core.PKI.ClientAuth.Notifier do
  @moduledoc """
  Notifier for Client Auth PKI trust bundle updates.

  Publishes bundle update events via Phoenix PubSub to all nodes in the cluster,
  which in turn push notifications to connected agents.
  """

  require Logger

  @pubsub_topic "pki:client_auth"

  @doc """
  Broadcasts an internal bundle updated event across the cluster.
  """
  @spec notify_bundle_updated(pos_integer(), pos_integer(), String.t()) :: :ok
  def notify_bundle_updated(generation, crl_number, reason \\ "crl_updated") do
    payload = %{
      generation: generation,
      crl_number: crl_number,
      reason: reason
    }

    Phoenix.PubSub.broadcast(
      SecretHub.Web.PubSub,
      @pubsub_topic,
      {:client_auth_bundle_updated, payload}
    )
  rescue
    _ ->
      :ok
  end

  @doc """
  Subscribes the calling process to bundle update notifications.
  """
  def subscribe do
    Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, @pubsub_topic)
  rescue
    _ -> :ok
  end

  @doc """
  Unsubscribes the calling process from bundle update notifications.
  """
  def unsubscribe do
    Phoenix.PubSub.unsubscribe(SecretHub.Web.PubSub, @pubsub_topic)
  rescue
    _ -> :ok
  end
end
