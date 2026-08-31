defmodule SecretHub.Agent.PKI.TrustBundleManager do
  @moduledoc """
  Coordinates Agent-side Client Auth PKI trust bundle receipt, validation,
  atomic disk application, and status reporting.
  """

  use GenServer
  require Logger

  alias SecretHub.Agent.PKI.{AtomicStore, BundleValidator}

  defstruct [
    :state_dir,
    :base_dir,
    :agent_id,
    current_generation: 0,
    current_crl_number: 0,
    bundle_sha256: nil,
    last_applied_at: nil,
    last_error_code: nil,
    last_error_detail: nil,
    status: "initializing"
  ]

  @type t :: %__MODULE__{}

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    state_dir = Keyword.get(opts, :state_dir, Path.expand("~/.local/state/secrethub/agent"))
    base_dir = Path.join(state_dir, "pki/client-auth")
    agent_id = Keyword.get(opts, :agent_id)

    # Initialize from current manifest on disk if it exists
    state =
      case AtomicStore.read_current_manifest(base_dir) do
        {:ok, manifest} ->
          %__MODULE__{
            state_dir: state_dir,
            base_dir: base_dir,
            agent_id: agent_id,
            current_generation: manifest["generation"] || 0,
            current_crl_number: manifest["crl_number"] || 0,
            bundle_sha256: manifest["bundle_sha256"],
            last_applied_at: parse_datetime(manifest["applied_at"]),
            status: "applied"
          }

        _ ->
          %__MODULE__{
            state_dir: state_dir,
            base_dir: base_dir,
            agent_id: agent_id,
            status: "initializing"
          }
      end

    {:ok, state}
  end

  @doc """
  Processes a trust bundle map from Core (validates and writes atomically).
  Returns `{:ok, receipt}` or `{:error, error_code, receipt}`.
  """
  @spec process_bundle(pid() | module(), map(), keyword()) ::
          {:ok, map()}
          | {:error, atom(), map()}
  def process_bundle(server \\ __MODULE__, bundle, opts \\ []) do
    GenServer.call(server, {:process_bundle, bundle, opts})
  end

  @doc """
  Returns the current status of the TrustBundleManager.
  """
  @spec status(pid() | module()) :: map()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :get_status)
  end

  @impl true
  def handle_call({:process_bundle, bundle, opts}, _from, state) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    force = Keyword.get(opts, :force, false)

    case BundleValidator.validate(bundle, opts) do
      {:ok, validated} ->
        if !force and validated.generation <= state.current_generation and
             state.status == "applied" do
          # Already at or ahead of this generation
          receipt = build_receipt(state, "applied", now)
          {:reply, {:ok, receipt}, state}
        else
          case AtomicStore.write_bundle(state.base_dir, bundle, opts) do
            {:ok, _result} ->
              new_state = %{
                state
                | current_generation: validated.generation,
                  current_crl_number: validated.crl_number,
                  bundle_sha256: validated.bundle_sha256,
                  last_applied_at: now,
                  last_error_code: nil,
                  last_error_detail: nil,
                  status: "applied"
              }

              receipt = build_receipt(new_state, "applied", now)

              Logger.info(
                "Client Auth trust bundle updated to generation #{validated.generation}"
              )

              {:reply, {:ok, receipt}, new_state}

            {:error, reason} ->
              error_code = :atomic_write_failed
              error_detail = inspect(reason)

              new_state = %{
                state
                | last_error_code: to_string(error_code),
                  last_error_detail: error_detail,
                  status: "failed"
              }

              receipt = build_error_receipt(new_state, bundle, error_code, error_detail, now)
              {:reply, {:error, error_code, receipt}, new_state}
          end
        end

      {:error, error_code, detail} ->
        new_state = %{
          state
          | last_error_code: to_string(error_code),
            last_error_detail: detail,
            status: "failed"
        }

        receipt = build_error_receipt(new_state, bundle, error_code, detail, now)
        Logger.error("Client Auth trust bundle validation failed: #{error_code} - #{detail}")
        {:reply, {:error, error_code, receipt}, new_state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    info = %{
      current_generation: state.current_generation,
      current_crl_number: state.current_crl_number,
      bundle_sha256: state.bundle_sha256,
      last_applied_at: state.last_applied_at,
      status: state.status,
      last_error_code: state.last_error_code,
      last_error_detail: state.last_error_detail,
      base_dir: state.base_dir
    }

    {:reply, info, state}
  end

  # Helpers

  defp build_receipt(state, status, now) do
    %{
      "agent_id" => state.agent_id,
      "generation" => state.current_generation,
      "crl_number" => state.current_crl_number,
      "bundle_sha256" => state.bundle_sha256,
      "status" => status,
      "applied_at" => DateTime.to_iso8601(now)
    }
  end

  defp build_error_receipt(state, bundle, error_code, error_detail, now) do
    %{
      "agent_id" => state.agent_id,
      "generation" => bundle["generation"] || state.current_generation,
      "crl_number" => bundle["crl_number"] || state.current_crl_number,
      "bundle_sha256" => bundle["bundle_sha256"] || state.bundle_sha256 || "",
      "status" => "failed",
      "last_error_code" => to_string(error_code),
      "last_error_detail" => error_detail,
      "applied_at" => DateTime.to_iso8601(now)
    }
  end

  defp parse_datetime(nil), do: nil

  defp parse_datetime(iso_str) when is_binary(iso_str) do
    case DateTime.from_iso8601(iso_str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
end
