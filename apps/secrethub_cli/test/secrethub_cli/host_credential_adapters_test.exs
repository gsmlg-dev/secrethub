defmodule SecretHub.CLI.HostCredentialAdaptersTest do
  use ExUnit.Case, async: true

  alias SecretHub.CLI.Commands.CredentialCommands
  alias SecretHub.CLI.{DockerCredential, ExecResolver, GitCredential}

  # A recording fake Agent client: replies come from the given function.
  defp client(reply) do
    parent = self()

    fn action, params, _opts ->
      send(parent, {:agent, action, params})
      reply.(action, params)
    end
  end

  describe "git-credential-secrethub" do
    test "get maps Git fields to a git selector and prints only the protocol reply" do
      fake = client(fn _, _ -> {:ok, %{"username" => "alice", "value" => "s3cret"}} end)
      input = "protocol=https\nhost=git.example.com:8443\npath=org/repo.git\nwwwauth[]=Basic\n\n"

      assert {"username=alice\npassword=s3cret\n", 0, []} =
               GitCredential.run("get", input, client: fake)

      assert_received {:agent, "credential_get",
                       %{
                         "namespace" => "git",
                         "service" => "https",
                         "authority" => "git.example.com:8443",
                         "context" => "org/repo.git",
                         "account" => nil
                       }}
    end

    test "omitted path is not invented and EOF without a blank line is accepted" do
      fake = client(fn _, _ -> {:error, "NOT_FOUND"} end)
      assert {"", 0, []} = GitCredential.run("get", "protocol=https\nhost=h", client: fake)
      assert_received {:agent, "credential_get", %{"context" => "", "authority" => "h"}}
    end

    test "a miss or ambiguity is an ordinary miss; Agent failure quits Git" do
      for code <- ["NOT_FOUND", "AMBIGUOUS"] do
        fake = client(fn _, _ -> {:error, code} end)
        assert {"", 0, []} = GitCredential.run("get", "protocol=https\nhost=h\n\n", client: fake)
      end

      for code <- ["FORBIDDEN", "Agent unavailable", "VAULT_SEALED"] do
        fake = client(fn _, _ -> {:error, code} end)

        assert {"quit=true\n", 1, [diagnostic]} =
                 GitCredential.run("get", "protocol=https\nhost=h\n\n", client: fake)

        assert diagnostic =~ code
      end
    end

    test "store sends the username and exact password, including empty values" do
      fake = client(fn _, _ -> {:ok, %{"status" => "created"}} end)
      input = "protocol=https\nhost=h\nusername=bob\npassword=\n\n"
      assert {"", 0, []} = GitCredential.run("store", input, client: fake)

      assert_received {:agent, "credential_put",
                       %{"account" => "bob", "value" => "", "namespace" => "git"}}
    end

    test "erase passes the rejected password as a constraint and reports refusals" do
      fake = client(fn _, _ -> {:error, "AMBIGUOUS"} end)
      input = "protocol=https\nhost=h\npassword=old\n\n"
      assert {"", 1, [_]} = GitCredential.run("erase", input, client: fake)

      assert_received {:agent, "credential_delete",
                       %{"expected_value" => "old", "account" => nil}}
    end

    test "unknown operations are ignored and NUL fields are rejected" do
      fake = client(fn _, _ -> flunk("Agent must not be called") end)
      assert {"", 0, []} = GitCredential.run("capabilities", "", client: fake)

      assert {"quit=true\n", 1, _} =
               GitCredential.run("get", "protocol=https\nhost=a\0b\n\n", client: fake)
    end

    test "values that Git lines cannot carry are refused rather than truncated" do
      fake = client(fn _, _ -> {:ok, %{"username" => "u", "value" => "a\nb"}} end)

      assert {"quit=true\n", 1, _} =
               GitCredential.run("get", "protocol=https\nhost=h\n\n", client: fake)
    end
  end

  describe "docker-credential-secrethub" do
    test "registry keys follow a finite Docker Hub alias table and keep ports" do
      for alias <- ~w(docker.io index.docker.io https://index.docker.io/v1/ registry-1.docker.io
                     https://registry.hub.docker.com) do
        assert {:ok, "https://index.docker.io/v1/"} = DockerCredential.registry_key(alias)
      end

      assert {:ok, "localhost:5000"} = DockerCredential.registry_key("http://LocalHost:5000/")
      assert {:ok, "registry.example.com"} = DockerCredential.registry_key("registry.example.com")

      refute DockerCredential.registry_key("registry.example.com:5001") ==
               DockerCredential.registry_key("registry.example.com")

      assert {:error, _} = DockerCredential.registry_key("registry.example.com/team/repo")
      assert {:error, _} = DockerCredential.registry_key("bad host")
    end

    test "store, get, erase and list use docker-credential-helpers framing" do
      fake =
        client(fn
          "credential_put", _ ->
            {:ok, %{"status" => "created"}}

          "credential_get", _ ->
            {:ok, %{"username" => "<token>", "value" => "idtok"}}

          "credential_delete", _ ->
            {:ok, %{"status" => "deleted"}}

          "credential_list", _ ->
            {:ok,
             %{
               "entries" => [%{"service" => "localhost:5000", "username" => "u"}],
               "next_cursor" => nil
             }}
        end)

      payload = ~s({"ServerURL":"localhost:5000","Username":"<token>","Secret":"idtok"})
      assert {"", 0, []} = DockerCredential.run("store", payload, client: fake)

      assert_received {:agent, "credential_put",
                       %{"service" => "localhost:5000", "username" => "<token>"}}

      assert {json, 0, []} = DockerCredential.run("get", "localhost:5000", client: fake)
      assert %{"Username" => "<token>", "Secret" => "idtok"} = Jason.decode!(json)

      assert {"", 0, []} = DockerCredential.run("erase", "localhost:5000\n", client: fake)
      assert {list, 0, []} = DockerCredential.run("list", "unused", client: fake)
      assert Jason.decode!(list) == %{"localhost:5000" => "u"}
    end

    test "a genuine miss uses the exact not-found message; other errors stay distinct" do
      miss = client(fn _, _ -> {:error, "NOT_FOUND"} end)

      assert {"credentials not found in native keychain\n", 1, []} =
               DockerCredential.run("get", "localhost:5000", client: miss)

      denied = client(fn _, _ -> {:error, "FORBIDDEN"} end)
      assert {message, 1, []} = DockerCredential.run("get", "localhost:5000", client: denied)
      refute message =~ "not found"

      absent = client(fn _, _ -> {:ok, %{"status" => "absent"}} end)

      assert {"credentials not found in native keychain\n", 1, []} =
               DockerCredential.run("erase", "localhost:5000", client: absent)
    end

    test "an explicitly empty secret stays distinct from a missing credential" do
      fake = client(fn _, _ -> {:ok, %{"username" => "u", "value" => ""}} end)
      assert {json, 0, []} = DockerCredential.run("get", "localhost:5000", client: fake)
      assert %{"Secret" => ""} = Jason.decode!(json)
    end

    test "list follows pagination cursors" do
      pages = %{
        nil =>
          {:ok, %{"entries" => [%{"service" => "a", "username" => "1"}], "next_cursor" => "c1"}},
        "c1" =>
          {:ok, %{"entries" => [%{"service" => "b", "username" => "2"}], "next_cursor" => nil}}
      }

      fake = client(fn "credential_list", params -> pages[params["cursor"]] end)
      assert {json, 0, []} = DockerCredential.run("list", "", client: fake)
      assert Jason.decode!(json) == %{"a" => "1", "b" => "2"}
    end
  end

  describe "exec resolver" do
    @id "11111111-2222-4333-8444-555555555555"

    test "emits NUL-terminated records only after every value resolves" do
      fake =
        client(fn "credential_get", %{"entry_id" => @id} ->
          {:ok, %{"username" => "svc", "value" => "multi\nline value"}}
        end)

      map =
        Jason.encode!(%{
          "env" => %{
            "DB_USER" => %{"entry_id" => @id, "field" => "username"},
            "DB_PASS" => %{"entry_id" => @id, "field" => "value"}
          }
        })

      assert {:ok, "DB_PASS=multi\nline value\0DB_USER=svc\0"} =
               ExecResolver.resolve(map, client: fake)
    end

    test "missing, denied, empty or NUL values stop resolution without output" do
      map = Jason.encode!(%{"env" => %{"A" => %{"entry_id" => @id, "field" => "value"}}})

      for reply <- [
            {:error, "NOT_FOUND"},
            {:error, "FORBIDDEN"},
            {:ok, %{"value" => ""}},
            {:ok, %{"value" => "a\0b"}},
            {:ok, %{"username" => "u"}}
          ] do
        assert {:error, message} = ExecResolver.resolve(map, client: client(fn _, _ -> reply end))
        refute message =~ "a\0b"
      end

      allowed =
        Jason.encode!(%{
          "env" => %{"A" => %{"entry_id" => @id, "field" => "value", "allow_empty" => true}}
        })

      assert {:ok, "A=\0"} =
               ExecResolver.resolve(allowed,
                 client: client(fn _, _ -> {:ok, %{"value" => ""}} end)
               )
    end

    test "maps reject embedded values, invalid names and non-scalar entries" do
      fake = client(fn _, _ -> flunk("Agent must not be called") end)

      for env <- [
            %{"A" => "plaintext"},
            %{"1BAD" => %{"entry_id" => @id, "field" => "value"}},
            %{"A" => %{"entry_id" => "not-a-uuid", "field" => "value"}},
            %{"A" => %{"entry_id" => @id, "field" => "value", "value" => "x"}},
            %{"A" => %{"entry_id" => @id, "field" => "password"}}
          ] do
        assert {:error, _} = ExecResolver.resolve(Jason.encode!(%{"env" => env}), client: fake)
      end
    end
  end

  describe "secrethub credential" do
    test "put reads the value from stdin and never from arguments" do
      fake = client(fn _, _ -> {:ok, %{"status" => "created"}} end)

      assert {_, 0, []} =
               CredentialCommands.run(
                 ~w(put --namespace generic --service svc --account u),
                 fn -> "from-stdin" end,
                 client: fake
               )

      assert_received {:agent, "credential_put", %{"value" => "from-stdin", "account" => "u"}}
      assert {_, 2, _} = CredentialCommands.run(~w(put --value x), fn -> "" end, client: fake)
    end

    test "get prints JSON or one exact field, and errors exit non-zero" do
      fake = client(fn _, _ -> {:ok, %{"username" => "u", "value" => "v"}} end)
      args = ~w(get --namespace generic --service svc --account u)
      assert {json, 0, []} = CredentialCommands.run(args, fn -> "" end, client: fake)
      assert %{"value" => "v"} = Jason.decode!(json)

      assert {"v", 0, []} =
               CredentialCommands.run(args ++ ~w(--field value), fn -> "" end, client: fake)

      denied = client(fn _, _ -> {:error, "FORBIDDEN"} end)
      assert {"", 1, [message]} = CredentialCommands.run(args, fn -> "" end, client: denied)
      assert message =~ "FORBIDDEN"
    end
  end
end
