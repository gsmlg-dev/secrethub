defmodule SecretHub.HumanWeb.BitwardenAPITest do
  use SecretHub.Human.DataCase, async: true
  import Phoenix.ConnTest
  import Plug.Conn
  @endpoint SecretHub.HumanWeb.Endpoint
  alias SecretHub.Human.Accounts

  defp encrypted,
    do: "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

  setup do
    attrs = %{
      email: "bw-#{System.unique_integer([:positive])}@example.test",
      name: "Owner",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted()
    }

    {:ok, user} = Accounts.provision(attrs, server_iterations: 1000)
    %{attrs: attrs, user: user}
  end

  defp token(attrs) do
    body =
      URI.encode_query(%{
        grant_type: "password",
        username: attrs.email,
        password: attrs.password_hash,
        deviceIdentifier: "bw-device",
        deviceName: "Official Client",
        deviceType: 9,
        client_id: "cli",
        scope: "api offline_access"
      })

    conn =
      build_conn()
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> post("/identity/connect/token", body)

    assert conn.status == 200
    json_response(conn, 200)
  end

  defp bearer(token), do: build_conn() |> put_req_header("authorization", "Bearer " <> token)

  test "prelogin and identity exchange expose client KDF and an independently signed revocable token",
       %{attrs: attrs, user: user} do
    assert %{"kdf" => 0, "kdfIterations" => 600_000} =
             json_response(
               post(build_conn(), "/api/accounts/prelogin", %{email: attrs.email}),
               200
             )

    assert %{"kdfSettings" => %{"kdfType" => 0, "iterations" => 600_000}, "salt" => salt} =
             json_response(
               post(build_conn(), "/identity/accounts/prelogin/password", %{email: attrs.email}),
               200
             )

    assert salt == attrs.email
    response = token(attrs)
    assert response["Key"] == attrs.encrypted_key
    assert response["token_type"] == "Bearer"
    assert response["expires_in"] == 900
    assert [_, claims, _] = String.split(response["access_token"], ".")

    assert %{"sub" => subject, "aud" => "api"} =
             claims |> Base.url_decode64!(padding: false) |> Jason.decode!()

    assert subject == user.id

    assert %{"id" => ^subject} =
             json_response(get(bearer(response["access_token"]), "/api/accounts/profile"), 200)

    assert get(bearer(response["access_token"] <> "tampered"), "/api/sync").status == 401
    assert get(build_conn(), "/api/sync").status == 401
    key_id = String.duplicate("ab", 16)

    assert post(bearer(response["access_token"]), "/api/accounts/key-management/user-key-id", %{
             userKeyId: key_id
           }).status == 200

    assert %{"userDecryption" => %{"userKeyId" => ^key_id}} =
             json_response(get(bearer(response["access_token"]), "/api/sync"), 200)

    assert post(bearer(response["access_token"]), "/api/accounts/key-management/user-key-id", %{
             userKeyId: "plaintext-key"
           }).status == 400

    assert post(bearer(response["access_token"]), "/api/accounts/key-management/user-key-id", %{
             userKeyId: String.duplicate("cd", 16)
           }).status == 400

    assert %{"access_token" => next} =
             json_response(
               post(build_conn(), "/identity/connect/token", %{
                 grant_type: "refresh_token",
                 refresh_token: response["refresh_token"]
               }),
               200
             )

    assert get(bearer(response["access_token"]), "/api/sync").status == 200
    assert get(bearer(next), "/api/sync").status == 200

    assert post(build_conn(), "/identity/connect/token", %{
             grant_type: "refresh_token",
             refresh_token: response["refresh_token"]
           }).status == 400

    assert get(bearer(response["access_token"]), "/api/sync").status == 401
    assert get(bearer(next), "/api/sync").status == 401
  end

  test "official-shaped cipher and folder changes appear in sync including tombstones", %{
    attrs: attrs
  } do
    access = token(attrs)["access_token"]
    name = encrypted()

    assert %{"id" => folder_id} =
             json_response(post(bearer(access), "/api/folders", %{name: name}), 200)

    payload = %{
      type: 1,
      name: name,
      notes: nil,
      folderId: folder_id,
      favorite: false,
      login: %{
        username: encrypted(),
        password: encrypted(),
        response: nil,
        uris: [%{uri: encrypted(), uriChecksum: encrypted(), match: nil, response: nil}],
        totp: nil
      }
    }

    assert %{
             "id" => item_id,
             "type" => 1,
             "folderId" => ^folder_id,
             "permissions" => %{"delete" => true, "restore" => false}
           } = json_response(post(bearer(access), "/api/ciphers", payload), 200)

    assert %{"ciphers" => [%{"id" => ^item_id}], "folders" => [%{"id" => ^folder_id}]} =
             json_response(get(bearer(access), "/api/sync"), 200)

    changed = encrypted()

    assert %{"name" => ^changed} =
             json_response(
               put(bearer(access), "/api/ciphers/" <> item_id, %{payload | name: changed}),
               200
             )

    assert delete(bearer(access), "/api/ciphers/" <> item_id).status == 200

    assert %{"ciphers" => [%{"id" => ^item_id, "deletedDate" => date}]} =
             json_response(get(bearer(access), "/api/sync"), 200)

    assert is_binary(date)
    assert delete(bearer(access), "/api/folders/" <> folder_id).status == 200
  end

  test "plaintext and unsupported auth cannot pass the protocol boundary", %{attrs: attrs} do
    access = token(attrs)["access_token"]
    assert post(bearer(access), "/api/ciphers", %{type: 1, name: "plaintext"}).status == 400

    assert post(build_conn(), "/identity/connect/token", %{grant_type: "client_credentials"}).status ==
             400

    assert post(build_conn(), "/api/accounts/register", %{
             email: "signup@example.test",
             masterPasswordHash: attrs.password_hash,
             key: attrs.encrypted_key
           }).status == 403

    assert post(build_conn(), "/human/vault/export", %{confirm: true}).status == 401
  end
end
