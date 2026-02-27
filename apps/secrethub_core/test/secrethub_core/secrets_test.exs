defmodule SecretHub.Core.SecretsTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Policies, Secrets}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.Secret

  # Helper: initialize vault and unseal it so master key is available.
  defp unseal_vault do
    {:ok, shares} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(Enum.at(shares, 0))
    {:ok, _} = SealState.unseal(Enum.at(shares, 1))
    :ok
  end

  setup do
    case Process.whereis(SealState) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal)
    end

    {:ok, _pid} = start_supervised(SealState)
    :ok
  end

  describe "create_secret/1" do
    test "creates a static secret with encrypted data when vault is unsealed" do
      unseal_vault()

      attrs = %{
        "name" => "DB Password",
        "secret_path" => "prod.db.postgres.password",
        "secret_type" => "static",
        "secret_data" => %{"username" => "admin", "password" => "s3cr3t"}
      }

      assert {:ok, secret} = Secrets.create_secret(attrs)
      assert secret.name == "DB Password"
      assert secret.secret_path == "prod.db.postgres.password"
      assert secret.secret_type == :static
      # Data should be encrypted at rest — not raw JSON
      assert is_binary(secret.encrypted_data)
      refute String.contains?(secret.encrypted_data, "s3cr3t")
    end

    test "fails when vault is sealed" do
      # SealState is initialized but NOT unsealed
      {:ok, _shares} = SealState.initialize(3, 2)

      attrs = %{
        "name" => "Sealed Secret",
        "secret_path" => "test.sealed.secret",
        "secret_type" => "static",
        "secret_data" => %{"key" => "value"}
      }

      assert {:error, :sealed} = Secrets.create_secret(attrs)
    end

    test "fails with duplicate secret_path" do
      unseal_vault()

      attrs = %{
        "name" => "Original Secret",
        "secret_path" => "prod.duplicate.path",
        "secret_type" => "static",
        "secret_data" => %{"key" => "value1"}
      }

      assert {:ok, _} = Secrets.create_secret(attrs)
      assert {:error, changeset} = Secrets.create_secret(Map.put(attrs, "name", "Duplicate"))
      assert {_msg, _} = changeset.errors[:secret_path]
    end

    test "creates secret with empty secret_data" do
      unseal_vault()

      attrs = %{
        "name" => "Empty Secret",
        "secret_path" => "test.empty.data",
        "secret_type" => "static"
      }

      assert {:ok, secret} = Secrets.create_secret(attrs)
      assert secret.name == "Empty Secret"
    end
  end

  describe "get_secret/1" do
    test "returns secret by ID" do
      unseal_vault()

      {:ok, created} =
        Secrets.create_secret(%{
          "name" => "Test Secret",
          "secret_path" => "test.get.by.id",
          "secret_type" => "static",
          "secret_data" => %{"key" => "val"}
        })

      assert {:ok, fetched} = Secrets.get_secret(created.id)
      assert fetched.id == created.id
      assert fetched.name == "Test Secret"
    end

    test "returns error for non-existent ID" do
      assert {:error, "Secret not found"} = Secrets.get_secret(Ecto.UUID.generate())
    end
  end

  describe "get_secret_by_path/1" do
    test "returns secret by path" do
      unseal_vault()

      {:ok, _created} =
        Secrets.create_secret(%{
          "name" => "Path Secret",
          "secret_path" => "test.path.lookup",
          "secret_type" => "static",
          "secret_data" => %{"k" => "v"}
        })

      assert {:ok, fetched} = Secrets.get_secret_by_path("test.path.lookup")
      assert fetched.secret_path == "test.path.lookup"
    end

    test "returns error for unknown path" do
      assert {:error, "Secret not found"} =
               Secrets.get_secret_by_path("nonexistent.path.xyz")
    end
  end

  describe "read_decrypted/1" do
    test "returns decrypted secret data" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "Decryption Test",
          "secret_path" => "test.decrypt.roundtrip",
          "secret_type" => "static",
          "secret_data" => %{"username" => "alice", "password" => "hunter2"}
        })

      assert {:ok, data, secret} = Secrets.read_decrypted("test.decrypt.roundtrip")
      assert data["username"] == "alice"
      assert data["password"] == "hunter2"
      assert %Secret{} = secret
    end

    test "returns error when path not found" do
      unseal_vault()
      assert {:error, "Secret not found"} = Secrets.read_decrypted("no.such.path")
    end
  end

  describe "update_secret/3" do
    test "updates secret value and increments version" do
      unseal_vault()

      {:ok, original} =
        Secrets.create_secret(%{
          "name" => "Update Test",
          "secret_path" => "test.update.version",
          "secret_type" => "static",
          "secret_data" => %{"password" => "old_pass"}
        })

      assert original.version == 1

      assert {:ok, updated} =
               Secrets.update_secret(original.id, %{
                 "secret_data" => %{"password" => "new_pass"}
               })

      assert updated.version == 2
    end

    test "archives previous version when updating" do
      unseal_vault()

      {:ok, secret} =
        Secrets.create_secret(%{
          "name" => "Archive Test",
          "secret_path" => "test.archive.versions",
          "secret_type" => "static",
          "secret_data" => %{"val" => "v1"}
        })

      {:ok, _} = Secrets.update_secret(secret.id, %{"secret_data" => %{"val" => "v2"}})

      versions = Secrets.list_secret_versions(secret.id)
      # v1 archived; v2 is current (not archived yet)
      assert length(versions) == 1
      assert hd(versions).version_number == 1
    end

    test "returns error for non-existent secret" do
      unseal_vault()

      assert {:error, "Secret not found"} =
               Secrets.update_secret(Ecto.UUID.generate(), %{"name" => "ghost"})
    end
  end

  describe "delete_secret/1" do
    test "deletes an existing secret" do
      unseal_vault()

      {:ok, secret} =
        Secrets.create_secret(%{
          "name" => "Deletable",
          "secret_path" => "test.delete.me",
          "secret_type" => "static",
          "secret_data" => %{"k" => "v"}
        })

      assert {:ok, _} = Secrets.delete_secret(secret.id)
      assert {:error, "Secret not found"} = Secrets.get_secret(secret.id)
    end

    test "returns error for non-existent secret" do
      assert {:error, "Secret not found"} = Secrets.delete_secret(Ecto.UUID.generate())
    end
  end

  describe "list_secrets/1" do
    test "returns all secrets without filter" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "List A",
          "secret_path" => "test.list.a",
          "secret_type" => "static",
          "secret_data" => %{}
        })

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "List B",
          "secret_path" => "test.list.b",
          "secret_type" => "static",
          "secret_data" => %{}
        })

      secrets = Secrets.list_secrets()
      paths = Enum.map(secrets, & &1.secret_path)
      assert "test.list.a" in paths
      assert "test.list.b" in paths
    end

    test "filters by secret_type" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "Static Only",
          "secret_path" => "test.filter.static",
          "secret_type" => "static",
          "secret_data" => %{}
        })

      secrets = Secrets.list_secrets(%{secret_type: :static})
      assert Enum.all?(secrets, fn s -> s.secret_type == :static end)
    end

    test "filters by search term" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "SearchableUniqueXYZ",
          "secret_path" => "test.search.unique.xyz",
          "secret_type" => "static",
          "secret_data" => %{}
        })

      results = Secrets.list_secrets(%{search: "SearchableUniqueXYZ"})
      assert length(results) >= 1
      assert Enum.any?(results, fn s -> s.name == "SearchableUniqueXYZ" end)
    end
  end

  describe "rollback_secret/3" do
    test "rolls back to a previous version" do
      unseal_vault()

      {:ok, secret} =
        Secrets.create_secret(%{
          "name" => "Rollback Test",
          "secret_path" => "test.rollback.secret",
          "secret_type" => "static",
          "secret_data" => %{"val" => "v1"}
        })

      {:ok, _v2} = Secrets.update_secret(secret.id, %{"secret_data" => %{"val" => "v2"}})
      {:ok, _v3} = Secrets.update_secret(secret.id, %{"secret_data" => %{"val" => "v3"}})

      # Roll back to version 1
      assert {:ok, rolled_back} = Secrets.rollback_secret(secret.id, 1)
      assert rolled_back.version == 4

      # The content should now be v1's data
      {:ok, data, _} = Secrets.read_decrypted("test.rollback.secret")
      assert data["val"] == "v1"
    end
  end

  describe "prune_old_versions/2" do
    test "deletes versions beyond keep_versions limit" do
      unseal_vault()

      {:ok, secret} =
        Secrets.create_secret(%{
          "name" => "Prune Test",
          "secret_path" => "test.prune.versions",
          "secret_type" => "static",
          "secret_data" => %{"v" => "1"}
        })

      # Create 5 updates (so 5 archived versions)
      for i <- 2..6 do
        Secrets.update_secret(secret.id, %{"secret_data" => %{"v" => "#{i}"}})
      end

      assert length(Secrets.list_secret_versions(secret.id)) == 5

      # keep_days: 0 ensures the date cutoff is now (older than 0 days = all of them),
      # so only keep_versions: 2 determines what stays
      assert {:ok, result} = Secrets.prune_old_versions(secret.id, keep_versions: 2, keep_days: 0)
      assert result.deleted == 3
      assert result.kept == 2
      assert length(Secrets.list_secret_versions(secret.id)) == 2
    end
  end

  describe "get_secret_stats/0" do
    test "returns counts of static and dynamic secrets" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "Stats Static",
          "secret_path" => "test.stats.static",
          "secret_type" => "static",
          "secret_data" => %{}
        })

      stats = Secrets.get_secret_stats()
      assert is_integer(stats.total)
      assert is_integer(stats.static)
      assert is_integer(stats.dynamic)
      assert stats.total >= 1
      assert stats.static >= 1
    end
  end

  describe "get_secret_for_entity/3" do
    test "denies access when no policy grants it" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "Policy Guarded",
          "secret_path" => "test.policy.guarded",
          "secret_type" => "static",
          "secret_data" => %{"key" => "secret_value"}
        })

      # No policy grants agent-unknown access to this path
      assert {:error, _reason} =
               Secrets.get_secret_for_entity("agent-unknown-001", "test.policy.guarded", %{})
    end

    test "grants access when a matching policy exists" do
      unseal_vault()

      {:ok, _} =
        Secrets.create_secret(%{
          "name" => "Policy Allowed",
          "secret_path" => "test.policy.allowed",
          "secret_type" => "static",
          "secret_data" => %{"answer" => "42"}
        })

      # Create a permissive policy bound to the test agent
      {:ok, _policy} =
        Policies.create_policy(%{
          name: "allow-test-policy-allowed-#{System.unique_integer()}",
          description: "Allow access to test.policy.allowed",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["test.policy.allowed"],
            "allowed_operations" => ["read"]
          },
          entity_bindings: ["agent-test-allowed-001"]
        })

      assert {:ok, data} =
               Secrets.get_secret_for_entity(
                 "agent-test-allowed-001",
                 "test.policy.allowed",
                 %{}
               )

      assert data["answer"] == "42"
    end
  end
end
