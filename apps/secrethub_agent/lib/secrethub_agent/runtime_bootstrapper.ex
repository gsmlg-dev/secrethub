defmodule SecretHub.Agent.RuntimeBootstrapper do
  @moduledoc """
  Boots the trusted Agent runtime connection from stored identity material or
  by completing the pending enrollment workflow first.
  """

  use GenServer

  require Logger

  alias SecretHub.Agent.{
    ConnectionManager,
    EndpointManager,
    Enrollment,
    IdentityStore,
    TrustedConnection
  }

  @default_core_url "https://localhost:4664"
  @default_state_dir "/var/lib/secrethub-agent"
  @default_connect_timeout_ms 10_000
  @finalize_retry_base_ms 1_000
  @finalize_retry_max_ms 60_000
  @allow_insecure_enrollment_default Mix.env() in [:dev, :test]

  defstruct [
    :core_url,
    :core_endpoints,
    :state_dir,
    :enrollment_opts,
    :legacy_connection_opts,
    :runtime_pid,
    :pending_finalization
  ]

  @type state :: %__MODULE__{
          core_url: binary(),
          core_endpoints: [binary()],
          state_dir: Path.t(),
          enrollment_opts: keyword(),
          legacy_connection_opts: keyword(),
          runtime_pid: pid() | nil,
          pending_finalization: map() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  @spec plan_start(Path.t(), keyword()) ::
          {:ok, :ready_for_runtime, IdentityStore.t()}
          | {:ok, :ready_for_runtime, IdentityStore.t(), map()}
          | {:ok, :ready_for_legacy_runtime, keyword()}
          | {:ok, :needs_enrollment}
          | {:error, term()}
  def plan_start(state_dir, opts \\ []) do
    case IdentityStore.load(state_dir) do
      {:ok, material} -> ready_runtime_plan(state_dir, material)
      {:error, :missing_trusted_material} -> legacy_or_enrollment(opts)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  @spec enrollment_core_url(binary()) ::
          {:ok, binary()} | {:error, :invalid_enrollment_url | :insecure_enrollment_url}
  def enrollment_core_url(core_url) when is_binary(core_url) do
    core_url
    |> enrollment_uri()
    |> normalize_enrollment_uri()
    |> validate_enrollment_core_url()
  end

  defp enrollment_uri(core_url) do
    uri = URI.parse(core_url)

    if is_nil(uri.scheme) and is_nil(uri.host) and binary_present?(uri.path) do
      URI.parse("https://#{core_url}")
    else
      uri
    end
  end

  defp normalize_enrollment_uri(%URI{} = uri) do
    scheme =
      case uri.scheme do
        "ws" -> "http"
        "wss" -> "https"
        nil -> "https"
        other -> other
      end

    %{uri | scheme: scheme, path: nil, query: nil, fragment: nil}
  end

  defp validate_enrollment_core_url(%URI{scheme: scheme, host: host} = uri)
       when scheme in ["http", "https"] and is_binary(host) and host != "" do
    url = URI.to_string(uri)

    cond do
      scheme == "https" -> {:ok, url}
      allow_insecure_enrollment?() -> {:ok, url}
      true -> {:error, :insecure_enrollment_url}
    end
  end

  defp validate_enrollment_core_url(_uri), do: {:error, :invalid_enrollment_url}

  defp allow_insecure_enrollment? do
    Application.get_env(
      :secrethub_agent,
      :allow_insecure_enrollment,
      @allow_insecure_enrollment_default
    )
  end

  @doc false
  @spec trusted_connection_opts(IdentityStore.t(), (map() -> term()) | nil) :: keyword()
  def trusted_connection_opts(%IdentityStore{} = material, on_runtime_accepted \\ nil) do
    [
      agent_id: material.agent_id,
      connect_info: material.connect_info,
      certificate_pem: material.certificate_pem,
      private_key_pem: material.private_key_pem,
      ca_pem: material.ca_chain_pem,
      on_runtime_accepted: on_runtime_accepted
    ]
  end

  @doc false
  @spec runtime_accepted_callback(pid()) :: (map() -> :ok)
  def runtime_accepted_callback(owner \\ self()) when is_pid(owner) do
    fn payload ->
      send(owner, {:runtime_accepted, payload})
      :ok
    end
  end

  @impl true
  def init(opts) do
    state = %__MODULE__{
      core_url: Keyword.get(opts, :core_url, @default_core_url),
      core_endpoints:
        Keyword.get(opts, :core_endpoints, [Keyword.get(opts, :core_url, @default_core_url)]),
      state_dir:
        Keyword.get(
          opts,
          :state_dir,
          System.get_env("SECRET_HUB_AGENT_STATE_DIR") || @default_state_dir
        ),
      enrollment_opts: Keyword.get(opts, :enrollment_opts, []),
      legacy_connection_opts: legacy_connection_opts(opts)
    }

    {:ok, state, {:continue, :start_runtime}}
  end

  @impl true
  def handle_continue(:start_runtime, state) do
    case plan_start(state.state_dir, state.legacy_connection_opts) do
      {:ok, :ready_for_runtime, material} ->
        start_runtime(material, nil, state)

      {:ok, :ready_for_runtime, material, pending} ->
        case pending_enrollment_core_url(pending, state) do
          {:ok, core_url} ->
            finalization = pending_finalization(core_url, pending, material.connect_info)

            start_enrolled_runtime(
              material,
              runtime_accepted_callback(self()),
              finalization,
              state
            )

          {:error, reason} ->
            {:stop, reason, state}
        end

      {:ok, :ready_for_legacy_runtime, legacy_opts} ->
        start_legacy_runtime(legacy_opts, state)

      {:ok, :needs_enrollment} ->
        enroll_and_start_runtime(state)

      {:error, reason} ->
        {:stop, reason, state}
    end
  end

  @impl true
  def handle_info({:runtime_accepted, payload}, %{pending_finalization: nil} = state) do
    Logger.debug("Runtime accepted without pending enrollment finalization",
      payload: inspect(payload)
    )

    {:noreply, state}
  end

  def handle_info({:runtime_accepted, payload}, state) do
    %{core_url: core_url, pending: pending, timer: timer} = state.pending_finalization
    cancel_timer(timer)

    Logger.info("Trusted runtime accepted by Core",
      enrollment_id: pending["enrollment_id"],
      agent_id: payload["agent_id"]
    )

    case finalize_success(core_url, pending, state.state_dir) do
      :ok ->
        {:noreply, %{state | pending_finalization: nil}}

      {:error, reason} ->
        {:noreply,
         %{
           state
           | pending_finalization:
               schedule_finalize_success_retry(state.pending_finalization, reason)
         }}
    end
  end

  def handle_info(:runtime_finalize_success_retry, %{pending_finalization: nil} = state) do
    {:noreply, state}
  end

  def handle_info(
        :runtime_finalize_success_retry,
        %{pending_finalization: %{phase: :finalize_success_retry}} = state
      ) do
    %{core_url: core_url, pending: pending} = state.pending_finalization

    case finalize_success(core_url, pending, state.state_dir) do
      :ok ->
        {:noreply, %{state | pending_finalization: nil}}

      {:error, reason} ->
        {:noreply,
         %{
           state
           | pending_finalization:
               schedule_finalize_success_retry(state.pending_finalization, reason)
         }}
    end
  end

  def handle_info(:runtime_finalize_success_retry, state), do: {:noreply, state}

  def handle_info(:runtime_start_retry, %{pending_finalization: nil} = state) do
    {:noreply, state}
  end

  def handle_info(
        :runtime_start_retry,
        %{pending_finalization: %{phase: :runtime_start_retry} = finalization} = state
      ) do
    cancel_timer(finalization.timer)

    case start_runtime_process(finalization.material, finalization.callback) do
      {:ok, pid} ->
        {:noreply,
         %{
           state
           | runtime_pid: pid,
             pending_finalization: schedule_runtime_accept_timeout(finalization)
         }}

      {:error, {:already_started, pid}} ->
        {:noreply,
         %{
           state
           | runtime_pid: pid,
             pending_finalization: schedule_runtime_accept_timeout(finalization)
         }}

      {:error, reason} ->
        retry =
          schedule_runtime_start_retry(
            finalization,
            finalization.material,
            finalization.callback,
            reason
          )

        {:noreply, %{state | pending_finalization: retry}}
    end
  end

  def handle_info(:runtime_start_retry, state), do: {:noreply, state}

  def handle_info(
        :runtime_accept_timeout,
        %{pending_finalization: %{phase: :finalize_success_retry}} = state
      ) do
    {:noreply, state}
  end

  def handle_info(
        :runtime_accept_timeout,
        %{pending_finalization: %{phase: :runtime_start_retry}} = state
      ) do
    {:noreply, state}
  end

  def handle_info(:runtime_accept_timeout, %{pending_finalization: nil} = state) do
    {:noreply, state}
  end

  def handle_info(:runtime_accept_timeout, state) do
    %{core_url: core_url, pending: pending} = state.pending_finalization

    error = %{
      "phase" => "trusted_runtime_connect",
      "message" => "timed out waiting for trusted runtime connection"
    }

    finalize_failure_terminal(core_url, pending, state.state_dir, error)

    {:stop, :trusted_runtime_connect_timeout, %{state | pending_finalization: nil}}
  end

  defp enroll_and_start_runtime(state) do
    endpoint = enrollment_endpoint(state)

    with {:ok, enrollment_url} <- enrollment_core_url(endpoint) do
      Logger.info("Trusted Agent material missing; starting enrollment",
        core_url: enrollment_url,
        state_dir: state.state_dir
      )

      enrollment_opts =
        state.enrollment_opts
        |> Keyword.put(:core_url, enrollment_url)
        |> Keyword.put(:storage_dir, state.state_dir)

      case Enrollment.enroll(enrollment_opts) do
        {:ok, enrolled} ->
          report_endpoint_success(endpoint)

          with {:ok, material} <- IdentityStore.load(state.state_dir) do
            finalization =
              pending_finalization(enrollment_url, enrolled.pending, material.connect_info)

            start_enrolled_runtime(
              material,
              runtime_accepted_callback(self()),
              finalization,
              state
            )
          else
            {:error, reason} ->
              report_endpoint_failure(endpoint)
              {:stop, reason, state}
          end

        {:error, reason} ->
          report_endpoint_failure(endpoint)
          {:stop, reason, state}
      end
    else
      {:error, reason} ->
        report_endpoint_failure(endpoint)
        {:stop, reason, state}
    end
  end

  defp start_runtime(%IdentityStore{} = material, callback, state) do
    Logger.info("Starting trusted Agent runtime connection", agent_id: material.agent_id)

    case start_runtime_process(material, callback) do
      {:ok, pid} -> {:noreply, %{state | runtime_pid: pid}}
      {:error, {:already_started, pid}} -> {:noreply, %{state | runtime_pid: pid}}
      {:error, reason} -> {:stop, reason, state}
    end
  end

  defp start_enrolled_runtime(material, callback, finalization, state) do
    Logger.info("Starting trusted Agent runtime connection", agent_id: material.agent_id)

    case start_runtime_process(material, callback) do
      {:ok, pid} ->
        {:noreply, %{state | runtime_pid: pid, pending_finalization: finalization}}

      {:error, {:already_started, pid}} ->
        {:noreply, %{state | runtime_pid: pid, pending_finalization: finalization}}

      {:error, reason} ->
        cancel_timer(finalization.timer)
        retry = schedule_runtime_start_retry(finalization, material, callback, reason)
        {:noreply, %{state | pending_finalization: retry}}
    end
  end

  defp start_runtime_process(material, callback) do
    TrustedConnection.start_link(trusted_connection_opts(material, callback))
  end

  defp start_legacy_runtime(legacy_opts, state) do
    Logger.info("Starting trusted Agent runtime connection from legacy certificate paths",
      agent_id: Keyword.fetch!(legacy_opts, :agent_id)
    )

    case ConnectionManager.start_link(legacy_opts) do
      {:ok, pid} -> {:noreply, %{state | runtime_pid: pid}}
      {:error, {:already_started, pid}} -> {:noreply, %{state | runtime_pid: pid}}
      {:error, reason} -> {:stop, reason, state}
    end
  end

  defp legacy_or_enrollment(opts) do
    if legacy_configured?(opts) do
      {:ok, :ready_for_legacy_runtime, opts}
    else
      {:ok, :needs_enrollment}
    end
  end

  defp ready_runtime_plan(state_dir, material) do
    case load_pending_token(state_dir) do
      {:ok, pending} -> {:ok, :ready_for_runtime, material, pending}
      {:error, :missing_pending_token} -> {:ok, :ready_for_runtime, material}
      {:error, reason} -> {:error, reason}
    end
  end

  defp legacy_connection_opts(opts) do
    [
      agent_id: Keyword.get(opts, :agent_id),
      core_endpoints:
        Keyword.get(opts, :core_endpoints, [Keyword.get(opts, :core_url, @default_core_url)]),
      cert_path: Keyword.get(opts, :cert_path),
      key_path: Keyword.get(opts, :key_path),
      ca_path: Keyword.get(opts, :ca_path)
    ]
  end

  defp legacy_configured?(opts) do
    binary_present?(Keyword.get(opts, :agent_id)) and
      nonempty_list?(Keyword.get(opts, :core_endpoints)) and
      regular_file?(Keyword.get(opts, :cert_path)) and
      regular_file?(Keyword.get(opts, :key_path)) and
      regular_file?(Keyword.get(opts, :ca_path))
  end

  defp pending_finalization(core_url, pending, connect_info) do
    timeout_ms = connect_timeout_ms(connect_info)
    timer = Process.send_after(self(), :runtime_accept_timeout, timeout_ms)

    %{
      core_url: core_url,
      pending: pending,
      timer: timer,
      timeout_ms: timeout_ms,
      phase: :waiting_for_runtime,
      retry_count: 0
    }
  end

  defp schedule_runtime_accept_timeout(finalization) do
    %{
      finalization
      | phase: :waiting_for_runtime,
        timer: Process.send_after(self(), :runtime_accept_timeout, finalization.timeout_ms)
    }
  end

  defp finalize_success(core_url, pending, state_dir) do
    case Enrollment.finalize_success(core_url, pending, state_dir) do
      {:ok, _finalized} ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to finalize trusted Agent enrollment",
          enrollment_id: pending["enrollment_id"],
          reason: inspect(reason)
        )

        {:error, reason}
    end
  end

  defp schedule_finalize_success_retry(finalization, reason) do
    retry_count = Map.get(finalization, :retry_count, 0) + 1
    delay_ms = finalize_retry_delay_ms(retry_count)

    Logger.warning("Retrying trusted Agent enrollment finalization",
      enrollment_id: finalization.pending["enrollment_id"],
      retry_count: retry_count,
      delay_ms: delay_ms,
      reason: inspect(reason)
    )

    %{
      finalization
      | phase: :finalize_success_retry,
        retry_count: retry_count,
        timer: Process.send_after(self(), :runtime_finalize_success_retry, delay_ms)
    }
  end

  defp finalize_retry_delay_ms(retry_count) do
    @finalize_retry_base_ms
    |> Kernel.*(:math.pow(2, max(retry_count - 1, 0)))
    |> round()
    |> min(@finalize_retry_max_ms)
  end

  defp schedule_runtime_start_retry(finalization, material, callback, reason) do
    retry_count = Map.get(finalization, :retry_count, 0) + 1
    delay_ms = finalize_retry_delay_ms(retry_count)

    Logger.warning("Retrying trusted Agent runtime start",
      enrollment_id: finalization.pending["enrollment_id"],
      retry_count: retry_count,
      delay_ms: delay_ms,
      reason: inspect(reason)
    )

    Map.merge(finalization, %{
      material: material,
      callback: callback,
      phase: :runtime_start_retry,
      retry_count: retry_count,
      last_start_error: reason,
      timer: Process.send_after(self(), :runtime_start_retry, delay_ms)
    })
  end

  defp finalize_failure_terminal(core_url, pending, state_dir, error) do
    result =
      case Enrollment.finalize_failure(core_url, pending, error) do
        {:ok, _failed} ->
          :ok

        {:error, reason} ->
          Logger.error("Failed to report trusted runtime connection failure",
            enrollment_id: pending["enrollment_id"],
            reason: inspect(reason)
          )

          {:error, reason}
      end

    case result do
      :ok -> delete_enrollment_state(state_dir)
      {:error, reason} -> {:error, reason}
    end
  end

  defp delete_enrollment_state(state_dir) do
    with :ok <- Enrollment.delete_pending_token(state_dir),
         :ok <- IdentityStore.delete_trusted_material(state_dir) do
      :ok
    end
  end

  defp load_pending_token(state_dir) do
    state_dir
    |> Path.join("pending.json")
    |> File.read()
    |> case do
      {:ok, body} -> Jason.decode(body)
      {:error, :enoent} -> {:error, :missing_pending_token}
      {:error, reason} -> {:error, reason}
    end
  end

  defp pending_enrollment_core_url(pending, state) do
    case Map.get(pending, "enrollment_core_url") || Map.get(pending, :enrollment_core_url) do
      core_url when is_binary(core_url) and core_url != "" -> enrollment_core_url(core_url)
      _missing -> state |> enrollment_endpoint() |> enrollment_core_url()
    end
  end

  defp enrollment_endpoint(state) do
    case endpoint_manager_next_endpoint() do
      {:ok, endpoint} -> endpoint
      {:error, _reason} -> state.core_url
    end
  end

  defp endpoint_manager_next_endpoint do
    if Process.whereis(EndpointManager) do
      EndpointManager.get_next_endpoint()
    else
      {:error, :endpoint_manager_not_started}
    end
  catch
    :exit, _reason -> {:error, :endpoint_manager_unavailable}
  end

  defp report_endpoint_success(endpoint) do
    if Process.whereis(EndpointManager), do: EndpointManager.report_success(endpoint)
    :ok
  catch
    :exit, _reason -> :ok
  end

  defp report_endpoint_failure(endpoint) do
    if Process.whereis(EndpointManager), do: EndpointManager.report_failure(endpoint)
    :ok
  catch
    :exit, _reason -> :ok
  end

  defp connect_timeout_ms(connect_info) do
    case Map.get(connect_info, "connect_timeout_ms") || Map.get(connect_info, :connect_timeout_ms) do
      timeout when is_integer(timeout) and timeout > 0 -> timeout
      timeout when is_binary(timeout) -> parse_positive_integer(timeout)
      _other -> @default_connect_timeout_ms
    end
  end

  defp parse_positive_integer(timeout) do
    case Integer.parse(timeout) do
      {value, ""} when value > 0 -> value
      _invalid -> @default_connect_timeout_ms
    end
  end

  defp cancel_timer(timer) when is_reference(timer) do
    Process.cancel_timer(timer)
    :ok
  end

  defp cancel_timer(_timer), do: :ok

  defp binary_present?(value), do: is_binary(value) and value != ""
  defp nonempty_list?(value), do: is_list(value) and value != []
  defp regular_file?(value), do: is_binary(value) and File.regular?(value)
end
