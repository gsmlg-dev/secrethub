defmodule SecretHub.HumanWeb.AttachmentUploadTest do
  alias SecretHub.HumanWeb.Bitwarden.Token
  use SecretHub.Human.DataCase, async: false
  import Phoenix.ConnTest
  import Plug.Conn
  @endpoint SecretHub.HumanWeb.Endpoint
  alias SecretHub.Human.{Accounts, Vault}

  defp encrypted(size \\ 16),
    do: "2." <> Enum.map_join([16, size, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

  setup do
    root = Path.join(System.tmp_dir!(), "human-http-attachments-#{Ecto.UUID.generate()}")
    keys = [:attachment_directory, :attachment_max_bytes, :attachment_quota_bytes]
    previous = Map.new(keys, &{&1, Application.fetch_env(:secrethub_human, &1)})
    Application.put_env(:secrethub_human, :attachment_directory, root)
    Application.put_env(:secrethub_human, :attachment_max_bytes, 10_485_760)
    Application.put_env(:secrethub_human, :attachment_quota_bytes, 20_971_520)

    on_exit(fn ->
      File.rm_rf!(root)

      for {key, value} <- previous do
        case value do
          {:ok, value} -> Application.put_env(:secrethub_human, key, value)
          :error -> Application.delete_env(:secrethub_human, key)
        end
      end
    end)

    attrs = %{
      email: "upload-#{Ecto.UUID.generate()}@example.test",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted()
    }

    {:ok, _} = Accounts.provision(attrs, server_iterations: 1000)

    {:ok, session} =
      Accounts.authenticate(attrs.email, attrs.password_hash, %{identifier: "uploads"})

    {:ok, item} =
      Vault.create_item(session.actor, %{type: "login", ciphertext: %{"name" => encrypted()}})

    %{access: Token.issue(session), item: item}
  end

  defp upload(ctx, content) do
    body =
      Jason.encode!(%{filename: encrypted(), encrypted_key: encrypted(80), ciphertext: content})

    build_conn()
    |> put_req_header("authorization", "Bearer " <> ctx.access)
    |> put_req_header("content-type", "application/json")
    |> post("/human/vault/items/#{ctx.item.id}/attachments", body)
  end

  test "configured ciphertext uploads above the default parser limit reach the authorized context",
       ctx do
    content = encrypted(6_500_000)
    assert byte_size(content) > 8_000_000
    conn = upload(ctx, content)
    assert %{"data" => %{"id" => id}} = json_response(conn, 200)

    assert byte_size(
             File.read!(
               Path.join(Application.fetch_env!(:secrethub_human, :attachment_directory), id)
             )
           ) == byte_size(content)

    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "runtime ciphertext limit is still enforced with bounded metadata allowance", ctx do
    Application.put_env(:secrethub_human, :attachment_max_bytes, 1024)
    assert %{"error" => "attachment_too_large"} = json_response(upload(ctx, encrypted(1024)), 400)
    assert_raise Plug.Parsers.RequestTooLargeError, fn -> upload(ctx, encrypted(2_000_000)) end
  end
end
