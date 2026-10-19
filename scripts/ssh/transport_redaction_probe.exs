# Diagnostic for the upstream confidentiality gate. Uses a sentinel, never a key.
# Run: MIX_ENV=test mix run --no-start scripts/ssh/transport_redaction_probe.exs
Logger.configure(level: :warning)
{:ok, _} = Application.ensure_all_started(:phoenix_socket_client)

alias Phoenix.SocketClient.{Channel, Message, Socket}
alias Phoenix.SocketClient.Channel.State

sentinel = "SSH_PRIVATE_MATERIAL_SENTINEL"
payload = %{"status" => "ok", "response" => %{"private_key" => sentinel}}
raw = Jason.encode!(["join", "reply", "agent:runtime", "phx_reply", payload])
handler = "ssh-redaction-probe-#{System.unique_integer([:positive])}"
parent = self()

:ok =
  :telemetry.attach(
    handler,
    [:phoenix, :socket_client, :message, :received],
    fn _, _, metadata, _ -> send(parent, {:metadata, metadata}) end,
    nil
  )

{:ok, supervisor} =
  Phoenix.SocketClient.start_link(
    name: SSHRedactionProbe,
    auto_connect: false,
    json_library: Jason
  )

try do
  socket = Phoenix.SocketClient.get_process_pid(supervisor, :socket)
  original = :sys.get_state(socket)

  # Execute the production receive/decode callback. Its decode result is sent
  # to this diagnostic process, keeping the returned pending state deterministic.
  {:noreply, pending} = Socket.handle_info({:receive, raw}, original)
  :sys.replace_state(socket, fn _ -> pending end)
  status_exposes = inspect(:sys.get_status(socket), limit: :infinity) =~ sentinel
  :sys.replace_state(socket, fn _ -> original end)

  tag = make_ref()
  message = %Message{event: "phx_reply", topic: "agent:runtime", ref: "reply", payload: payload}

  state = %State{
    caller: self(),
    topic: "agent:runtime",
    join_ref: "join",
    pushes: [{{self(), tag}, %Message{ref: "reply"}}]
  }

  {:noreply, _} =
    Channel.Helpers.handle_phx_reply_info(message, state, fn _, _, s -> {:noreply, s} end)

  telemetry_exposes =
    receive do
      {:metadata, metadata} -> inspect(metadata, limit: :infinity) =~ sentinel
    after
      1000 -> raise "expected production message telemetry"
    end

  IO.puts("socket_status_exposes_private_material=#{status_exposes}")
  IO.puts("reply_telemetry_exposes_private_material=#{telemetry_exposes}")

  if status_exposes or telemetry_exposes do
    IO.puts("BLOCKED_UPSTREAM: private SSH responses require upstream redaction")
    System.at_exit(fn _ -> :erlang.halt(1) end)
  else
    IO.puts("PASS: private material absent from status and telemetry")
  end
after
  Supervisor.stop(supervisor)
  :telemetry.detach(handler)
end
