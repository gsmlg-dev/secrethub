defmodule SecretHub.Core.PreflightListenerTest do
  use ExUnit.Case, async: true

  @moduletag :tmp_dir

  # Execute only the listener checks and their TLS helper. Other runtime
  # checks are deliberately outside this focused regression's scope.
  source =
    Path.expand("../../lib/secrethub_core/preflight.ex", __DIR__)
    |> File.stream!()

  listener_checks =
    source
    |> Enum.drop_while(&(not String.starts_with?(&1, "      machine_listener:")))
    |> Enum.take_while(&(not String.starts_with?(&1, "      human_disabled:")))
    |> Enum.join()

  tls_helper =
    source
    |> Enum.drop_while(&(not String.starts_with?(&1, "  defp tls_files_readable?(")))
    |> Enum.take_while(&(not String.starts_with?(&1, "  defp writable_tmp?")))
    |> Enum.join()

  Code.compile_string("""
  defmodule #{__MODULE__}.ListenerChecks do
    def run(machine, agent) do
      %{
        #{listener_checks}
      }
    end

    #{tls_helper}
  end
  """)

  alias __MODULE__.ListenerChecks

  test "unset listeners pass without TLS material" do
    assert %{machine_listener: true, agent_mtls: true} = ListenerChecks.run([], [])
  end

  test "explicitly disabled listeners pass without TLS material" do
    assert %{machine_listener: true, agent_mtls: true} =
             ListenerChecks.run([server: false], server: false)
  end

  test "enabled Machine listener retains its existing selection validation" do
    assert %{machine_listener: true, agent_mtls: true} =
             ListenerChecks.run([server: true], [])
  end

  test "malformed listener selections fail" do
    assert %{machine_listener: false, agent_mtls: false} =
             ListenerChecks.run([server: "false"], server: "false")
  end

  test "enabled Agent listener fails without TLS material" do
    assert %{machine_listener: true, agent_mtls: false} =
             ListenerChecks.run([], server: true)
  end

  test "enabled Agent listener passes with readable TLS files and strict verification", context do
    assert %{machine_listener: true, agent_mtls: true} =
             ListenerChecks.run([], server: true, https: tls_config(context.tmp_dir))
  end

  test "enabled Agent listener rejects every missing TLS file", context do
    https = tls_config(context.tmp_dir)

    for path <- [https[:certfile], https[:keyfile], ca_path(https)] do
      File.rm!(path)

      assert %{agent_mtls: false} = ListenerChecks.run([], server: true, https: https)

      File.write!(path, "test material")
    end
  end

  test "enabled Agent listener requires peer verification", context do
    https =
      context.tmp_dir
      |> tls_config()
      |> put_in([:thousand_island_options, :transport_options, :verify], :verify_none)

    assert %{agent_mtls: false} = ListenerChecks.run([], server: true, https: https)
  end

  test "enabled Agent listener requires a client certificate", context do
    https =
      context.tmp_dir
      |> tls_config()
      |> put_in([:thousand_island_options, :transport_options, :fail_if_no_peer_cert], false)

    assert %{agent_mtls: false} = ListenerChecks.run([], server: true, https: https)
  end

  defp tls_config(tmp_dir) do
    paths = for name <- ["cert.pem", "key.pem", "ca.pem"], do: Path.join(tmp_dir, name)
    Enum.each(paths, &File.write!(&1, "test material"))
    [cert, key, ca] = paths

    [
      certfile: cert,
      keyfile: key,
      thousand_island_options: [
        transport_options: [
          cacertfile: String.to_charlist(ca),
          verify: :verify_peer,
          fail_if_no_peer_cert: true
        ]
      ]
    ]
  end

  defp ca_path(https),
    do: get_in(https, [:thousand_island_options, :transport_options, :cacertfile])
end
