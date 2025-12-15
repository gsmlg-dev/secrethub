defmodule SecretHub.Shared.Schemas.AlertRoutingConfig do
  @moduledoc """
  Schema for alert routing configuration.

  Defines where and how alerts should be sent (email, Slack, etc.)
  including filtering by severity.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @channel_types [:email, :slack, :webhook, :pagerduty, :opsgenie]
  @severities [:critical, :high, :medium, :low, :info]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "alert_routing_configs" do
    field(:name, :string)
    field(:channel_type, Ecto.Enum, values: @channel_types)
    field(:enabled, :boolean, default: true)
    field(:severity_filter, {:array, :string}, default: [])
    field(:config, :map)
    field(:last_used_at, :utc_datetime)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  @doc """
  Creates a changeset for creating a routing configuration.
  """
  def changeset(routing_config, attrs) do
    routing_config
    |> cast(attrs, [
      :name,
      :channel_type,
      :enabled,
      :severity_filter,
      :config,
      :metadata
    ])
    |> validate_required([:name, :channel_type, :config])
    |> validate_inclusion(:channel_type, @channel_types)
    |> validate_severities()
    |> validate_config_for_channel()
    |> unique_constraint(:name)
  end

  @doc """
  Updates a routing configuration.
  """
  def update_changeset(routing_config, attrs) do
    routing_config
    |> cast(attrs, [:enabled, :severity_filter, :config, :metadata])
    |> validate_severities()
    |> validate_config_for_channel()
  end

  @doc """
  Records that this routing was used to send an alert.
  """
  def record_usage(routing_config) do
    change(routing_config, last_used_at: DateTime.utc_now())
  end

  @doc """
  Checks if a given severity should be routed through this config.
  """
  def matches_severity?(routing_config, severity) do
    if Enum.empty?(routing_config.severity_filter) do
      true
    else
      severity in routing_config.severity_filter
    end
  end

  @doc """
  Gets the channel type as an atom.
  """
  def channel_type_atom(routing_config) do
    routing_config.channel_type
  end

  @doc """
  Gets email addresses from config (for email channel).
  """
  def email_recipients(routing_config) do
    case routing_config.config do
      %{"recipients" => recipients} when is_list(recipients) -> recipients
      %{"recipients" => recipient} when is_binary(recipient) -> [recipient]
      _ -> []
    end
  end

  @doc """
  Gets Slack webhook URL from config (for slack channel).
  """
  def slack_webhook_url(routing_config) do
    get_in(routing_config.config, ["webhook_url"])
  end

  @doc """
  Gets webhook URL from config (for webhook channel).
  """
  def webhook_url(routing_config) do
    get_in(routing_config.config, ["url"])
  end

  defp validate_severities(changeset) do
    severity_filter = get_field(changeset, :severity_filter) || []

    if Enum.all?(severity_filter, &(&1 in @severities)) do
      changeset
    else
      add_error(changeset, :severity_filter, "contains invalid severity values")
    end
  end

  defp validate_config_for_channel(changeset) do
    channel_type = get_field(changeset, :channel_type)
    config = get_field(changeset, :config)

    case channel_type do
      :email -> validate_email_config(changeset, config)
      :slack -> validate_slack_config(changeset, config)
      :webhook -> validate_webhook_config(changeset, config)
      :pagerduty -> validate_pagerduty_config(changeset, config)
      :opsgenie -> validate_opsgenie_config(changeset, config)
      _ -> changeset
    end
  end

  defp validate_email_config(changeset, config) when is_map(config) do
    if Map.has_key?(config, "recipients") and
         (is_list(config["recipients"]) or is_binary(config["recipients"])) do
      changeset
    else
      add_error(changeset, :config, "email config must include 'recipients' list or string")
    end
  end

  defp validate_email_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  defp validate_slack_config(changeset, config) when is_map(config) do
    if Map.has_key?(config, "webhook_url") do
      changeset
    else
      add_error(changeset, :config, "Slack config must include 'webhook_url'")
    end
  end

  defp validate_slack_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  defp validate_webhook_config(changeset, config) when is_map(config) do
    if Map.has_key?(config, "url") do
      changeset
    else
      add_error(changeset, :config, "Webhook config must include 'url'")
    end
  end

  defp validate_webhook_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  defp validate_pagerduty_config(changeset, config) when is_map(config) do
    if Map.has_key?(config, "integration_key") do
      changeset
    else
      add_error(changeset, :config, "PagerDuty config must include 'integration_key'")
    end
  end

  defp validate_pagerduty_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  defp validate_opsgenie_config(changeset, config) when is_map(config) do
    if Map.has_key?(config, "api_key") do
      changeset
    else
      add_error(changeset, :config, "Opsgenie config must include 'api_key'")
    end
  end

  defp validate_opsgenie_config(changeset, _config) do
    add_error(changeset, :config, "config must be a map")
  end

  @doc """
  Toggle the enabled status of a routing configuration.
  """
  def toggle(routing_config) do
    changeset(routing_config, %{enabled: !routing_config.enabled})
  end
end
