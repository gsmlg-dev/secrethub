defmodule SecretHub.Core.HumanAccess.MountConfigTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.HumanAccess.{MountConfig, PostgreSQLBackend}
  @moduletag :tmp_dir

  defp catalog do
    %{
      "postgres-runtime" => %{
        "engine" => "postgresql",
        "connection" => %{
          "hostname" => "database.example.test",
          "port" => 5432,
          "database" => "runtime_database",
          "username" => "runtime_operator",
          "password" => Base.url_encode64(:crypto.strong_rand_bytes(32)),
          "ssl" => true
        },
        "roles" => %{"reader" => %{"schema" => "public", "privileges" => ["select"]}}
      }
    }
  end

  test "bounded trusted JSON maps only fixed PostgreSQL connection and privilege atoms", %{
    tmp_dir: dir
  } do
    input = catalog()
    path = Path.join(dir, "mounts.json")
    File.write!(path, Jason.encode!(input))
    assert {:ok, %{"postgres-runtime" => backend}} = MountConfig.read(path)
    assert backend.engine == PostgreSQLBackend

    assert backend.connection[:password] ==
             get_in(input, ["postgres-runtime", "connection", "password"])

    assert backend.connection[:ssl] == true
    assert backend.roles == %{"reader" => %{schema: "public", privileges: [:select]}}
    assert PostgreSQLBackend.validate_config(backend) == :ok
    assert MountConfig.load!(path) == %{"postgres-runtime" => backend}
  end

  test "local socket connections are allowed without accepting arbitrary driver options", %{
    tmp_dir: dir
  } do
    input = catalog()

    connection = %{
      "socket_dir" => dir,
      "database" => "runtime_database",
      "username" => "runtime_operator"
    }

    path = Path.join(dir, "socket.json")

    File.write!(
      path,
      Jason.encode!(put_in(input, ["postgres-runtime", "connection"], connection))
    )

    assert {:ok, %{"postgres-runtime" => %{connection: connection}}} = MountConfig.read(path)
    assert connection[:socket_dir] == dir
    refute Keyword.has_key?(connection, :hostname)
  end

  test "malformed and secret-shaped catalog errors never expose file contents or paths", %{
    tmp_dir: dir
  } do
    canary = "MOUNT-CONFIG-CREDENTIAL-CANARY"
    input = catalog()

    variants = [
      "{\"password\":\"#{canary}\"",
      Jason.encode!([canary]),
      Jason.encode!(%{}),
      Jason.encode!(put_in(input, ["postgres-runtime", "engine"], canary)),
      Jason.encode!(
        put_in(input, ["postgres-runtime", "connection", "arbitrary_secret_option"], canary)
      ),
      Jason.encode!(
        put_in(input, ["postgres-runtime", "roles", "reader", "privileges"], [canary])
      ),
      Jason.encode!(put_in(input, ["postgres-runtime", "connection", "port"], 0)),
      Jason.encode!(put_in(input, ["postgres-runtime", "connection", "ssl"], "true")),
      Jason.encode!(
        put_in(input, ["postgres-runtime", "roles", "reader", "schema"], "public;DROP ROLE test")
      ),
      Jason.encode!(put_in(input, ["postgres-runtime", "roles", "reader", "statement"], canary)),
      String.duplicate("x", 1_048_577)
    ]

    path = Path.join(dir, canary <> ".json")

    for json <- variants do
      File.write!(path, json)
      assert {:error, :invalid_mount_config} = MountConfig.read(path)
      error = assert_raise ArgumentError, fn -> MountConfig.load!(path) end
      assert Exception.message(error) == "HUMAN_DYNAMIC_MOUNTS_FILE: invalid_mount_config"
      refute inspect(error) =~ canary
    end

    assert {:error, :invalid_mount_config} = MountConfig.read(dir)
    assert {:error, :invalid_mount_config} = MountConfig.read(Path.join(dir, "missing.json"))
  end

  test "catalog and role counts are bounded", %{tmp_dir: dir} do
    mount = catalog()["postgres-runtime"]
    excessive_catalog = Map.new(1..41, &{"mount-#{&1}", mount})

    excessive_roles =
      Map.new(1..51, &{"role-#{&1}", %{"schema" => "public", "privileges" => ["select"]}})

    path = Path.join(dir, "bounded.json")

    for input <- [
          excessive_catalog,
          %{"postgres-runtime" => %{mount | "roles" => excessive_roles}}
        ] do
      File.write!(path, Jason.encode!(input))
      assert {:error, :invalid_mount_config} = MountConfig.read(path)
    end
  end
end
