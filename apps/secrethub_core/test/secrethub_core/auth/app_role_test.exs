defmodule SecretHub.Core.Auth.AppRoleTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Auth.AppRole

  describe "create_role/2" do
    test "creates a role with default options" do
      assert {:ok, result} = AppRole.create_role("test-app")
      assert result.role_name == "test-app"
      assert is_binary(result.role_id)
      assert is_binary(result.secret_id)
      assert {:ok, _} = Ecto.UUID.cast(result.role_id)
      assert {:ok, _} = Ecto.UUID.cast(result.secret_id)
    end

    test "creates a role with custom policies" do
      assert {:ok, result} =
               AppRole.create_role("policy-app", policies: ["secret-read", "secret-write"])

      {:ok, role} = AppRole.get_role(result.role_id)
      assert role.policies == ["secret-read", "secret-write"]
    end

    test "creates a role with custom TTL and usage limits" do
      assert {:ok, result} =
               AppRole.create_role("custom-app",
                 secret_id_ttl: 1800,
                 secret_id_num_uses: 5
               )

      {:ok, role} = AppRole.get_role(result.role_id)
      assert role.secret_id_ttl == 1800
      assert role.secret_id_num_uses == 5
    end

    test "creates a role with CIDR binding" do
      assert {:ok, result} =
               AppRole.create_role("cidr-app", bound_cidr_list: ["10.0.0.0/8"])

      {:ok, role} = AppRole.get_role(result.role_id)
      assert role.bound_cidr_list == ["10.0.0.0/8"]
    end
  end

  describe "login/3" do
    test "successful login with valid credentials" do
      {:ok, created} = AppRole.create_role("login-app", secret_id_num_uses: 0)

      assert {:ok, result} = AppRole.login(created.role_id, created.secret_id, "127.0.0.1")
      assert is_binary(result.token)
      assert result.role_name == "login-app"
      assert is_list(result.policies)
    end

    test "login fails with wrong secret_id" do
      {:ok, created} = AppRole.create_role("wrong-secret-app")

      assert {:error, "Invalid credentials"} =
               AppRole.login(created.role_id, Ecto.UUID.generate(), "127.0.0.1")
    end

    test "login fails with wrong role_id" do
      assert {:error, "Invalid credentials"} =
               AppRole.login(Ecto.UUID.generate(), Ecto.UUID.generate(), "127.0.0.1")
    end

    test "login fails with non-UUID role_id" do
      assert {:error, "Invalid credentials"} =
               AppRole.login("not-a-uuid", "not-a-uuid", "127.0.0.1")
    end

    test "returns same error for wrong role_id and wrong secret_id (no enumeration)" do
      {:ok, created} = AppRole.create_role("enum-test-app")

      {:error, msg1} = AppRole.login(Ecto.UUID.generate(), Ecto.UUID.generate(), "127.0.0.1")
      {:error, msg2} = AppRole.login(created.role_id, Ecto.UUID.generate(), "127.0.0.1")

      assert msg1 == msg2
    end

    test "single-use secret_id is exhausted after first login" do
      {:ok, created} = AppRole.create_role("single-use-app", secret_id_num_uses: 1)

      assert {:ok, _} = AppRole.login(created.role_id, created.secret_id, "127.0.0.1")

      assert {:error, "Invalid credentials"} =
               AppRole.login(created.role_id, created.secret_id, "127.0.0.1")
    end

    test "unlimited use secret_id allows multiple logins" do
      {:ok, created} = AppRole.create_role("unlimited-app", secret_id_num_uses: 0)

      assert {:ok, _} = AppRole.login(created.role_id, created.secret_id, "127.0.0.1")
      assert {:ok, _} = AppRole.login(created.role_id, created.secret_id, "127.0.0.1")
      assert {:ok, _} = AppRole.login(created.role_id, created.secret_id, "127.0.0.1")
    end

    test "login fails when source IP not in CIDR binding" do
      {:ok, created} =
        AppRole.create_role("cidr-bound-app",
          bound_cidr_list: ["10.0.0.0/8"],
          secret_id_num_uses: 0
        )

      assert {:error, "Invalid credentials"} =
               AppRole.login(created.role_id, created.secret_id, "192.168.1.1")
    end

    test "login succeeds when source IP is in CIDR binding" do
      {:ok, created} =
        AppRole.create_role("cidr-ok-app",
          bound_cidr_list: ["10.0.0.0/8"],
          secret_id_num_uses: 0
        )

      assert {:ok, _} = AppRole.login(created.role_id, created.secret_id, "10.0.1.50")
    end
  end

  describe "rotate_secret_id/1" do
    test "rotates the secret_id and invalidates the old one" do
      {:ok, created} = AppRole.create_role("rotate-app", secret_id_num_uses: 0)

      assert {:ok, %{secret_id: new_secret_id}} = AppRole.rotate_secret_id(created.role_id)
      assert new_secret_id != created.secret_id

      # Old secret_id should no longer work
      assert {:error, "Invalid credentials"} =
               AppRole.login(created.role_id, created.secret_id, "127.0.0.1")

      # New secret_id should work
      assert {:ok, _} = AppRole.login(created.role_id, new_secret_id, "127.0.0.1")
    end

    test "returns error for non-existent role" do
      assert {:error, "Role not found"} = AppRole.rotate_secret_id(Ecto.UUID.generate())
    end
  end

  describe "delete_role/1" do
    test "deletes an existing role" do
      {:ok, created} = AppRole.create_role("delete-app")

      assert :ok = AppRole.delete_role(created.role_id)
      assert {:error, "Role not found"} = AppRole.get_role(created.role_id)
    end

    test "returns error for non-existent role" do
      assert {:error, "Role not found"} = AppRole.delete_role(Ecto.UUID.generate())
    end
  end

  describe "list_roles/0" do
    test "lists all approle roles" do
      {:ok, _} = AppRole.create_role("list-app-1")
      {:ok, _} = AppRole.create_role("list-app-2")

      roles = AppRole.list_roles()
      names = Enum.map(roles, & &1.role_name)
      assert "list-app-1" in names
      assert "list-app-2" in names
    end
  end

  describe "get_role/1 and get_role_by_name/1" do
    test "gets role by role_id" do
      {:ok, created} = AppRole.create_role("get-by-id-app")

      assert {:ok, role} = AppRole.get_role(created.role_id)
      assert role.role_name == "get-by-id-app"
    end

    test "gets role by name" do
      {:ok, _} = AppRole.create_role("get-by-name-app")

      assert {:ok, role} = AppRole.get_role_by_name("get-by-name-app")
      assert role.role_name == "get-by-name-app"
    end

    test "returns error for non-existent role" do
      assert {:error, "Role not found"} = AppRole.get_role(Ecto.UUID.generate())
      assert {:error, "Role not found"} = AppRole.get_role_by_name("nonexistent")
    end
  end

  describe "verify_token/1" do
    test "verifies a valid token" do
      {:ok, created} = AppRole.create_role("token-app", secret_id_num_uses: 0)
      {:ok, %{token: token}} = AppRole.login(created.role_id, created.secret_id, "127.0.0.1")

      assert {:ok, payload} = AppRole.verify_token(token)
      assert payload.role_name == "token-app"
      assert payload.role_id == created.role_id
    end

    test "rejects an invalid token" do
      assert {:error, "Invalid token"} = AppRole.verify_token("invalid-token")
    end
  end

  describe "generate_secret_id/1" do
    test "generates and returns a new secret_id" do
      {:ok, created} = AppRole.create_role("gen-secret-app")

      assert {:ok, new_id} = AppRole.generate_secret_id(created.role_id)
      assert is_binary(new_id)
      assert {:ok, _} = Ecto.UUID.cast(new_id)
      assert new_id != created.secret_id
    end

    test "returns error for non-existent role" do
      assert {:error, "Role not found"} = AppRole.generate_secret_id(Ecto.UUID.generate())
    end
  end
end
