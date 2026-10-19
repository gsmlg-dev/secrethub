defmodule SecretHub.Agent.SSH.OpenSSHTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  alias SecretHub.Agent.SSH.{Helper, Server}
  alias SecretHub.Shared.SSH.Key

  setup do
    dir =
      Path.join(
        System.user_home!(),
        "sho-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    tasks = start_supervised!({Task.Supervisor, []})
    %{dir: dir, tasks: tasks}
  end

  for algorithm <- ["ed25519", "rsa"] do
    @tag algorithm: algorithm
    test "OpenSSH lists and verifies #{algorithm} signing, then fresh authorization denies",
         ctx do
      key_path = Path.join(ctx.dir, "identity")

      {_output, 0} =
        System.cmd("ssh-keygen", [
          "-q",
          "-t",
          ctx.algorithm,
          "-b",
          "2048",
          "-N",
          "",
          "-f",
          key_path
        ])

      pem = File.read!(key_path)

      public =
        (key_path <> ".pub") |> File.read!() |> String.split() |> Enum.take(2) |> Enum.join(" ")

      {:ok, authorization} = Agent.start_link(fn -> %{allowed: true, requests: 0} end)
      on_exit(fn -> if Process.alive?(authorization), do: Agent.stop(authorization) end)

      request = fn
        "identities", _ ->
          {:ok, %{"identities" => [%{"public_key" => public}]}}

        "authorize_sign", _ ->
          Agent.get_and_update(authorization, fn state ->
            result =
              if state.allowed,
                do: {:ok, %{"public_key" => public, "private_key" => pem}},
                else: {:error, :denied}

            {result, %{state | requests: state.requests + 1}}
          end)
      end

      socket = Path.join(ctx.dir, "agent.sock")

      server =
        start_supervised!(
          {Server, path: socket, kind: :signing, task_supervisor: ctx.tasks, request: request}
        )

      {listed, 0} = System.cmd("ssh-add", ["-L"], env: [{"SSH_AUTH_SOCK", socket}])
      assert listed =~ public

      assert {_output, 0} =
               System.cmd("ssh-add", ["-T", key_path <> ".pub"],
                 env: [{"SSH_AUTH_SOCK", socket}],
                 stderr_to_stdout: true
               )

      assert %{requests: 1} = Agent.get(authorization, & &1)
      Agent.update(authorization, &%{&1 | allowed: false})

      assert {_output, status} =
               System.cmd("ssh-add", ["-T", key_path <> ".pub"],
                 env: [{"SSH_AUTH_SOCK", socket}],
                 stderr_to_stdout: true
               )

      assert status != 0
      assert %{requests: 2} = Agent.get(authorization, & &1)
      refute inspect(:sys.get_status(server)) =~ pem
    end
  end

  test "helpers output validated public lines, empty deny and stderr-only errors", ctx do
    key_path = Path.join(ctx.dir, "public")
    {_output, 0} = System.cmd("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key_path])
    {:ok, key} = Key.decode_public(File.read!(key_path <> ".pub"))
    public = key.public_line
    parent = self()

    request = fn op, payload ->
      send(parent, {op, payload})

      lines =
        if op == "authorized_keys",
          do: ["no-agent-forwarding " <> public],
          else: ["example.com " <> public]

      {:ok, %{"lines" => lines}}
    end

    socket = Path.join(ctx.dir, "lookup.sock")

    start_supervised!(
      {Server, path: socket, kind: :lookup, task_supervisor: ctx.tasks, request: request}
    )

    assert capture_io(fn ->
             assert Helper.run(["fetch-ssh-keys", "--socket", socket, "nobody", key.encoded]) == 0
           end) == "no-agent-forwarding " <> public <> "\n"

    assert_receive {"authorized_keys", %{"username" => "nobody", "key" => encoded}}
    assert encoded == key.encoded

    for reason <- ["ORDER", "HOSTNAME", "ADDRESS"] do
      assert capture_io(fn ->
               assert Helper.run([
                        "fetch-ssh-host-keys",
                        "--socket",
                        socket,
                        reason,
                        "example.com",
                        "22"
                      ]) == 0
             end) == "example.com " <> public <> "\n"

      assert_receive {"known_hosts", %{"reason" => ^reason, "uid" => _, "username" => _}}
    end

    assert capture_io(fn ->
             assert capture_io(:stderr, fn ->
                      assert Helper.run(["fetch-ssh-keys", "--socket", socket, "nobody", "bad"]) ==
                               1
                    end) =~ "SSH lookup unavailable"
           end) == ""

    assert capture_io(fn ->
             assert capture_io(:stderr, fn ->
                      assert Helper.run([
                               "fetch-ssh-host-keys",
                               "--socket",
                               socket,
                               "INVALID",
                               "example.com",
                               "22"
                             ]) == 1
                    end) =~ "SSH lookup unavailable"
           end) == ""
  end
end
