defmodule SecretHub.Agent.HostCredentials.Provider do
  @moduledoc """
  systemd `LoadCredential=` provider sockets.

  Each configured endpoint is a separate AF_UNIX stream socket mapped to
  exactly one credential binding ID and response field; callers cannot select
  another entry or a source path. systemd (PID 1) connects, reads the raw
  credential bytes until EOF, and passes a copy to the service.

  * Peers are restricted by kernel credentials (`SO_PEERCRED`) to the allowed
    UIDs, by default only root (the service manager).
  * When `units` is configured, the unit name systemd encodes in its abstract
    client address must be listed. It is routing metadata checked in addition
    to the peer UID, never as proof of identity on its own.
  * Every acquisition is a fresh, audited Core decision through the same path
    as local reads. On any failure nothing is written: systemd then sees an
    empty credential, which the mandatory `secrethub-exec --credential` main
    launcher refuses. Error text is never sent as credential data.

  Configuration (`SECRET_HUB_AGENT_CREDENTIAL_PROVIDERS` names a JSON file
  containing only identifiers, never values):

      {"socket_dir": "/run/secrethub-credentials",
       "allowed_uids": [0],
       "providers": {"db-password": {"entry_id": "<uuid>", "field": "value",
                                      "units": ["billing.service"]}}}
  """
  use GenServer
  require Logger

  alias SecretHub.Agent.HostCredentials.LocalAPI
  alias SecretHub.Agent.SSH.Identity
  alias SecretHub.Agent.UDSServer
  alias SecretHub.Shared.HostCredentials, as: Contract

  @name ~r/\A[A-Za-z0-9_.-]{1,64}\z/
  @acceptors 4

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Parses and validates provider configuration JSON."
  def parse_config(json) do
    with {:ok, %{"socket_dir" => dir, "providers" => providers} = config}
         when is_binary(dir) and is_map(providers) <- Jason.decode(json),
         true <- String.starts_with?(dir, "/") and byte_size(dir) <= 64,
         {:ok, uids} <- uids(Map.get(config, "allowed_uids", [0])),
         {:ok, endpoints} <- endpoints(providers) do
      {:ok, %{socket_dir: dir, allowed_uids: uids, endpoints: endpoints}}
    else
      {:error, reason} when is_binary(reason) -> {:error, reason}
      _ -> {:error, "invalid credential provider configuration"}
    end
  end

  defp uids(list) when is_list(list) and list != [] do
    if Enum.all?(list, &(is_integer(&1) and &1 >= 0)),
      do: {:ok, list},
      else: {:error, "allowed_uids must be non-negative integers"}
  end

  defp uids(_), do: {:error, "allowed_uids must be a non-empty list"}

  defp endpoints(providers) do
    Enum.reduce_while(providers, {:ok, []}, fn {name, spec}, {:ok, acc} ->
      with true <- Regex.match?(@name, name),
           %{"entry_id" => id, "field" => field} <- spec,
           true <- Contract.uuid?(id) and field in ["value", "username"],
           units when is_list(units) <- Map.get(spec, "units", []),
           true <- Enum.all?(units, &(is_binary(&1) and byte_size(&1) in 1..256)) do
        {:cont, {:ok, [%{name: name, entry_id: id, field: field, units: units} | acc]}}
      else
        _ -> {:halt, {:error, "invalid credential provider #{inspect(name)}"}}
      end
    end)
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    config = Keyword.fetch!(opts, :config)
    tasks = Keyword.get(opts, :task_supervisor, SecretHub.Agent.HostCredentials.Tasks)
    resolver = Keyword.get(opts, :resolver, &resolve/4)

    listeners = Enum.map(config.endpoints, &start_endpoint(&1, config, tasks, resolver))

    {:ok, %{listeners: listeners}}
  rescue
    error in MatchError ->
      Logger.error("Credential provider socket unavailable")
      {:stop, {:provider_unavailable, error.term}}
  end

  @impl true
  def terminate(_reason, state) do
    Enum.each(state.listeners, fn {listener, path} ->
      :gen_tcp.close(listener)
      File.rm(path)
    end)
  end

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted)

  defp start_endpoint(endpoint, config, tasks, resolver) do
    path = Path.join(config.socket_dir, endpoint.name <> ".sock")
    {:ok, listener} = listen(path)

    for _ <- 1..@acceptors do
      {:ok, _} =
        Task.Supervisor.start_child(tasks, fn ->
          accept(listener, endpoint, config.allowed_uids, resolver)
        end)
    end

    {listener, path}
  end

  defp listen(path) do
    File.mkdir_p!(Path.dirname(path))
    File.rm(path)

    with {:ok, listener} <-
           :gen_tcp.listen(0, [
             :binary,
             active: false,
             packet: :raw,
             ifaddr: {:local, to_charlist(path)},
             backlog: 16,
             send_timeout: 10_000,
             send_timeout_close: true
           ]),
         :ok <- File.chmod(path, 0o600) do
      {:ok, listener}
    end
  end

  defp accept(listener, endpoint, allowed_uids, resolver) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        try do
          serve(socket, endpoint, allowed_uids, resolver)
        catch
          _, _ -> :ok
        after
          :gen_tcp.close(socket)
        end

        accept(listener, endpoint, allowed_uids, resolver)

      {:error, _} ->
        :ok
    end
  end

  defp serve(socket, endpoint, allowed_uids, resolver) do
    with {:ok, uid} <- Identity.peer_uid(socket),
         true <- uid in allowed_uids || {:error, :peer_not_allowed},
         :ok <- unit_allowed(socket, endpoint),
         {:ok, context} <- UDSServer.runtime_context() do
      resolver.(socket, endpoint.entry_id, endpoint.field, context)
    else
      error ->
        Logger.warning("Credential provider refused #{endpoint.name}: #{reason(error)}")
    end
  end

  defp resolve(socket, entry_id, field, context),
    do: LocalAPI.deliver_raw(socket, entry_id, field, context)

  # systemd binds its client socket to "\\0<random>/unit/<unit>/<credential>".
  defp unit_allowed(_socket, %{units: []}), do: :ok

  defp unit_allowed(socket, %{units: units}) do
    with {:ok, {:local, address}} <- :inet.peername(socket),
         [_random, "unit", unit, _credential] <- String.split(IO.iodata_to_binary(address), "/"),
         true <- unit in units do
      :ok
    else
      _ -> {:error, :unit}
    end
  end

  defp reason({:error, reason}) when is_atom(reason), do: Atom.to_string(reason)
  defp reason(_), do: "unavailable"
end
