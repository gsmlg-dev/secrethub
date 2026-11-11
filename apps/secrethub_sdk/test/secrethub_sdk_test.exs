defmodule SecretHub.SDKTest do
  use ExUnit.Case, async: true

  alias SecretHub.SDK
  alias SecretHub.SDK.Error

  setup do
    path = Path.join(System.tmp_dir!(), "sh-sdk-#{System.unique_integer([:positive])}.sock")
    on_exit(fn -> File.rm(path) end)
    %{socket_path: path}
  end

  describe "put_secret/3" do
    test "sends one framed secret_put request and maps the result", %{socket_path: path} do
      agent!(path, fn "secret_put", params ->
        assert params == %{
                 "path" => "backplane.llm.openai-main",
                 "data" => %{"api_key" => "sk-1"},
                 "expected_version" => 2
               }

        {:ok, %{"status" => "updated", "path" => params["path"], "version" => 3}}
      end)

      assert {:ok, %{status: :updated, path: "backplane.llm.openai-main", version: 3}} =
               SDK.put_secret("backplane.llm.openai-main", %{"api_key" => "sk-1"},
                 socket_path: path,
                 expected_version: 2
               )
    end

    test "Agent error codes become typed errors", %{socket_path: path} do
      for {code, expected} <- [
            {"FORBIDDEN", :forbidden},
            {"CONFLICT", :conflict},
            {"INVALID_REQUEST", :invalid_request},
            {"UNCONFIRMED", :unconfirmed},
            {"INCOMPATIBLE_VERSION", :incompatible_version},
            {"VAULT_SEALED", :sealed},
            {"SOMETHING_NEW", :unknown}
          ] do
        agent!(path, fn _, _ -> {:error, code} end)

        assert {:error, %Error{code: ^expected, agent_code: ^code} = error} =
                 SDK.put_secret("a.b", %{"k" => "secret-value"}, socket_path: path)

        refute Exception.message(error) =~ "secret-value"
      end
    end

    test "a lost reply leaves a write unconfirmed", %{socket_path: path} do
      agent!(path, fn _, _ -> :close end)

      assert {:error, %Error{code: :unconfirmed}} =
               SDK.put_secret("a.b", %{"k" => "v"}, socket_path: path)
    end
  end

  describe "delete_secret/2 and get_secret/2" do
    test "delete maps deleted and absent", %{socket_path: path} do
      agent!(path, fn "secret_delete", %{"path" => "a.b"} -> {:ok, %{"status" => "absent"}} end)
      assert {:ok, %{status: :absent}} = SDK.delete_secret("a.b", socket_path: path)
    end

    test "get returns structured data and wraps text values", %{socket_path: path} do
      agent!(path, fn "get_secret", %{"path" => "a.b"} ->
        {:ok, %{"value" => %{"api_key" => "sk"}, "version" => 4, "revision" => 9}}
      end)

      assert {:ok, %{data: %{"api_key" => "sk"}, version: 4}} =
               SDK.get_secret("a.b", socket_path: path)

      agent!(path, fn "get_secret", _ -> {:ok, %{"value" => "plain", "version" => 1}} end)
      assert {:ok, %{data: %{"value" => "plain"}}} = SDK.get_secret("a.b", socket_path: path)
    end

    test "a missing Agent is distinguishable from a SecretHub answer" do
      assert {:error, %Error{code: :agent_unavailable}} =
               SDK.get_secret("a.b", socket_path: "/nonexistent/agent.sock")

      assert {:error, %Error{code: :agent_unavailable}} =
               SDK.put_secret("a.b", %{"k" => "v"}, socket_path: "/nonexistent/agent.sock")
    end
  end

  describe "path/1" do
    test "normalizes segments into a SecretHub path" do
      assert SDK.path(["backplane", :llm, "OpenAI_Main  Key"]) ==
               "backplane.llm.openai-main-key"

      assert SDK.path(["Backplane", "--x--"]) == "backplane.x"
    end

    test "refuses segments that normalize to nothing" do
      assert_raise ArgumentError, fn -> SDK.path(["backplane", "__"]) end
    end
  end

  # Serves exactly one connection on `path`: decodes the request frame, calls
  # `fun.(action, params)` and answers with the same request_id.
  defp agent!(path, fun) do
    File.rm(path)

    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :line,
        active: false,
        ifaddr: {:local, to_charlist(path)}
      ])

    test = self()

    Task.start_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listener, 5_000)
      {:ok, line} = :gen_tcp.recv(socket, 0, 5_000)
      %{"request_id" => id, "action" => action, "params" => params} = Jason.decode!(line)

      case fun.(action, params) do
        {:ok, data} ->
          send_frame(socket, %{request_id: id, status: "ok", data: data})

        {:error, code} ->
          send_frame(socket, %{request_id: id, status: "error", error: %{code: code}})

        :close ->
          :ok
      end

      :gen_tcp.close(socket)
      :gen_tcp.close(listener)
      send(test, :served)
    end)
  end

  defp send_frame(socket, frame), do: :gen_tcp.send(socket, Jason.encode!(frame) <> "\n")
end
