defmodule SecretHub.Shared.AccessAudit.Event do
  @moduledoc """
  Version 1 secret-free access observations. Producer assertions are validated at
  this boundary; Core supplies receive time and authenticates the producer.
  See ADR 0001 for counting, provenance, limits and phase requirements.
  """

  @required ~w(schema_version event_id producer_id producer_sequence request_id source phase
    observed_at identity_status attribution operation outcome reason_code cache_status)
  @optional ~w(attempt_id agent_id application_id secret_id secret_path secret_version duration_us
    policy_id policy_version core_event_id client_correlation_id)
  @uuid_fields ~w(event_id producer_id request_id attempt_id application_id secret_id policy_id
    core_event_id client_correlation_id)
  @agent_phases ~w(admitted attempt release_intent response_sent response_failed rejected)
  @core_phases @agent_phases ++ ~w(core_decision core_access)
  @attempt_phases ~w(attempt core_decision core_access release_intent response_sent response_failed)
  @reasons ~w(none allowed permission_denied unauthorized invalid_request invalid_identity
    invalid_application invalid_principal invalid_revision invalid_path incompatible_version
    revoked disabled expired not_found secret_not_found core_unavailable authorization_unavailable
    audit_unavailable sealed timeout transport_error response_error internal_error unsupported_schema
    invalid_event event_conflict journal_full journal_corrupt proof_required proof_failed
    certificate_invalid connection_closed rate_limited)
  @max_integer 9_007_199_254_740_991
  @path ~r/\A[a-zA-Z0-9_-]+(?:[.\/][a-zA-Z0-9_-]+)*\z/
  @agent_id ~r/\A[a-zA-Z0-9_.:-]{1,128}\z/

  def max_event_bytes, do: 4096
  def max_batch_events, do: 100
  def max_batch_bytes, do: 131_072
  def reasons, do: @reasons

  @spec validate(term(), keyword()) :: {:ok, map()} | {:error, atom()}
  def validate(input, opts \\ [])

  def validate(input, opts) when is_map(input) and map_size(input) <= 27 do
    with {:ok, event} <- normalize_keys(input),
         true <- Enum.all?(@required, &Map.has_key?(event, &1)),
         true <- event["schema_version"] == 1,
         true <- valid_fields?(event),
         true <- Keyword.get(opts, :source, event["source"]) == event["source"],
         true <- valid_phase?(event),
         true <- valid_identity?(event),
         {:ok, observed, _offset} <- DateTime.from_iso8601(event["observed_at"]) do
      normalized =
        Map.new(@optional, &{&1, nil})
        |> Map.merge(event)
        |> Map.put("observed_at", DateTime.to_iso8601(observed))

      if byte_size(canonical(normalized)) <= max_event_bytes(),
        do: {:ok, normalized},
        else: {:error, :event_too_large}
    else
      _ -> {:error, :invalid_event}
    end
  end

  def validate(_, _), do: {:error, :invalid_event}

  @doc "Deterministic encoding of the flat, validated envelope."
  def canonical(event), do: event |> Enum.sort() |> Jason.OrderedObject.new() |> Jason.encode!()

  @doc "Omit invalid paths rather than copying arbitrary caller input into evidence."
  def safe_path(path) when is_binary(path) and byte_size(path) in 1..512 do
    if String.valid?(path) and Regex.match?(@path, path), do: path
  end

  def safe_path(_), do: nil

  def reason(value) when is_atom(value), do: value |> Atom.to_string() |> reason()
  def reason(value) when value in @reasons, do: value
  def reason(_), do: "internal_error"

  defp normalize_keys(input) do
    Enum.reduce_while(input, {:ok, %{}}, fn {key, value}, {:ok, acc} ->
      normalized = if is_atom(key), do: Atom.to_string(key), else: key

      if normalized in (@required ++ @optional) and not Map.has_key?(acc, normalized) do
        {:cont, {:ok, Map.put(acc, normalized, value)}}
      else
        {:halt, {:error, :invalid_event}}
      end
    end)
  end

  defp valid_fields?(event) do
    Enum.all?(@uuid_fields, &valid_uuid?(event[&1], &1 in ~w(event_id producer_id request_id))) and
      valid_numbers?(event) and valid_resource?(event) and valid_enums?(event) and
      is_binary(event["observed_at"]) and byte_size(event["observed_at"]) <= 40
  end

  defp valid_numbers?(event) do
    positive_integer?(event["producer_sequence"]) and
      optional_integer?(event["secret_version"], 1) and
      optional_integer?(event["policy_version"], 1) and
      optional_integer?(event["duration_us"], 0)
  end

  defp valid_resource?(event) do
    valid_agent_id?(event["agent_id"]) and
      (is_nil(event["secret_path"]) or safe_path(event["secret_path"]) == event["secret_path"])
  end

  defp valid_enums?(event) do
    event["source"] in ~w(agent core) and
      event["identity_status"] in ~w(verified unverified) and
      event["attribution"] in ~w(core_certificate agent_certificate token none) and
      event["operation"] in ~w(read invalid authenticate) and
      event["outcome"] in ~w(success denied error unknown) and
      event["reason_code"] in @reasons and
      event["cache_status"] in ~w(none miss hit validated invalidated)
  end

  defp valid_phase?(%{"source" => source, "phase" => phase} = event) do
    allowed = if source == "agent", do: @agent_phases, else: @core_phases

    phase in allowed and
      (phase not in @attempt_phases or not is_nil(event["attempt_id"])) and
      phase_outcome?(phase, event["outcome"])
  end

  defp phase_outcome?(phase, outcome) when phase in ~w(admitted attempt release_intent),
    do: outcome == "unknown"

  defp phase_outcome?("core_access", outcome), do: outcome == "success"
  defp phase_outcome?("response_failed", outcome), do: outcome == "error"
  defp phase_outcome?("rejected", outcome), do: outcome in ~w(denied error)
  defp phase_outcome?("core_decision", outcome), do: outcome in ~w(success denied error)
  defp phase_outcome?("response_sent", _), do: true

  defp valid_identity?(event) do
    source_allowed =
      case event["source"] do
        "agent" -> event["attribution"] in ~w(agent_certificate none)
        "core" -> event["attribution"] in ~w(core_certificate token none)
      end

    identity_allowed =
      case event["identity_status"] do
        "verified" ->
          not is_nil(event["application_id"]) and
            event["attribution"] in ~w(core_certificate agent_certificate)

        "unverified" ->
          is_nil(event["application_id"]) and event["attribution"] in ~w(token none)
      end

    source_allowed and identity_allowed
  end

  defp valid_uuid?(nil, required), do: not required

  defp valid_uuid?(value, _) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, normalized} -> normalized == value
      :error -> false
    end
  end

  defp valid_uuid?(_, _), do: false
  defp positive_integer?(value), do: is_integer(value) and value in 1..@max_integer
  defp optional_integer?(nil, _), do: true
  defp optional_integer?(value, minimum), do: is_integer(value) and value in minimum..@max_integer
  defp valid_agent_id?(nil), do: true

  defp valid_agent_id?(value) when is_binary(value) and byte_size(value) <= 128,
    do: String.valid?(value) and Regex.match?(@agent_id, value)

  defp valid_agent_id?(_), do: false
end
