defmodule SecretHub.HumanWeb.Bitwarden.DTO do
  @moduledoc "Explicit protocol conversion; cipher DTOs never become Ecto changesets directly."
  @types %{1 => "login", 2 => "secure_note", 3 => "card", 4 => "identity", 5 => "ssh_key"}
  @encrypted_keys ~w(name notes login secureNote card identity sshKey fields passwordHistory)

  def item_input(params) do
    %{
      type: Map.get(@types, params["type"]),
      ciphertext: params |> Map.take(@encrypted_keys) |> strip_response_fields(),
      folder_id: params["folderId"],
      favorite: Map.get(params, "favorite", false)
    }
  end

  defp strip_response_fields(value) when is_map(value),
    do:
      value
      |> Map.reject(fn {key, value} -> key == "response" and is_nil(value) end)
      |> Map.new(fn {key, value} -> {key, strip_response_fields(value)} end)

  defp strip_response_fields(value) when is_list(value),
    do: Enum.map(value, &strip_response_fields/1)

  defp strip_response_fields(value), do: value

  def cipher(item) do
    Map.merge(item.ciphertext, %{
      id: item.id,
      object: "cipher",
      type: type_id(item.type),
      folderId: item.folder_id,
      organizationId: nil,
      favorite: item.favorite,
      edit: true,
      viewPassword: true,
      organizationUseTotp: false,
      permissions: %{delete: is_nil(item.deleted_at), restore: false},
      collectionIds: [],
      attachments: [],
      reprompt: 0,
      revisionDate: date(item.updated_at),
      creationDate: date(item.inserted_at),
      deletedDate: date(item.deleted_at)
    })
  end

  def folder(folder),
    do: %{
      id: folder.id,
      object: "folder",
      name: folder.name,
      revisionDate: date(folder.updated_at)
    }

  def profile(user),
    do: %{
      id: user.id,
      object: "profile",
      name: user.name,
      email: user.email,
      emailVerified: true,
      premium: false,
      key: user.encrypted_key,
      privateKey: user.encrypted_private_key,
      securityStamp: user.id,
      accountKeys: account_keys(user),
      twoFactorEnabled: false,
      organizations: [],
      providers: [],
      forcePasswordReset: false
    }

  def user_decryption(user),
    do: %{
      hasMasterPassword: true,
      userKeyId: user.user_key_id,
      masterPasswordUnlock: %{
        kdf: %{kdfType: user.kdf, iterations: user.kdf_iterations},
        masterKeyEncryptedUserKey: user.encrypted_key,
        salt: user.email
      }
    }

  def account_keys(%{encrypted_private_key: nil}), do: nil

  def account_keys(user),
    do: %{
      publicKeyEncryptionKeyPair: %{
        publicKey: user.public_key,
        wrappedPrivateKey: user.encrypted_private_key
      }
    }

  def date(nil), do: nil
  def date(date), do: DateTime.to_iso8601(date)
  defp type_id(type), do: Enum.find_value(@types, 1, fn {id, name} -> if type == name, do: id end)
end
