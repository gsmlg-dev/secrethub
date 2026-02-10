defmodule SecretHub.Web.SecretApiController do
  @moduledoc """
  REST API controller for secret CRUD operations via Vault-style paths.

  Routes:
  - POST /v1/secret/data/*path — Create or update a secret
  - GET /v1/secret/data/*path — Read a secret
  - DELETE /v1/secret/data/*path — Delete a secret
  - GET /v1/secret/metadata/*path — Get secret metadata

  Vault-style URL paths (e.g., `test-app/database`) are converted to
  dot-notation (e.g., `test-app.database`) for internal storage, since the
  Secret schema validates paths as reverse domain notation.
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.Secrets
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Secret

  @doc """
  POST /v1/secret/data/*path

  Create or update a secret at the given path.
  """
  def create_or_update(conn, params) do
    path = extract_path(params)
    agent = conn.assigns[:current_agent]
    secret_path = vault_path_to_dot(path)
    # Keep Vault-style path for policy check (policies use Vault patterns)
    vault_path = "secret/data/" <> path

    # Check policy allows write/create
    case check_policy(agent, vault_path, "create") do
      :ok ->
        data = params["data"]

        unless is_map(data) and map_size(data) > 0 do
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Missing or empty 'data' field"})
        else
          case Secrets.get_secret_by_path(secret_path) do
            {:ok, existing} ->
              # Update existing secret
              case Secrets.update_secret(existing.id, %{"secret_data" => data},
                     created_by: agent.agent_id,
                     change_description: "Updated via API") do
                {:ok, updated} ->
                  json(conn, %{version: updated.version})

                {:error, reason} ->
                  conn
                  |> put_status(:unprocessable_entity)
                  |> json(%{error: inspect(reason)})
              end

            {:error, _} ->
              # Create new secret — derive name from last path segment
              name = path |> String.split("/") |> List.last() |> String.replace(~r/[^a-zA-Z0-9\s\-_]/, "_")
              attrs = %{
                "name" => name,
                "secret_path" => secret_path,
                "secret_data" => data,
                "secret_type" => "static",
                "engine_type" => "static",
                "description" => "Created via API"
              }

              case Secrets.create_secret(attrs) do
                {:ok, secret} ->
                  json(conn, %{version: secret.version || 1})

                {:error, reason} ->
                  Logger.error("Secret creation failed", reason: inspect(reason), path: secret_path)
                  conn
                  |> put_status(:unprocessable_entity)
                  |> json(%{error: inspect(reason)})
              end
          end
        end

      {:error, _reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "permission denied"})
    end
  end

  @doc """
  GET /v1/secret/data/*path

  Read a secret at the given path.
  """
  def read(conn, params) do
    path = extract_path(params)
    agent = conn.assigns[:current_agent]
    secret_path = vault_path_to_dot(path)
    vault_path = "secret/data/" <> path

    case check_policy(agent, vault_path, "read") do
      :ok ->
        version = params["version"]

        if version do
          read_specific_version(conn, secret_path, version)
        else
          case Secrets.read_decrypted(secret_path) do
            {:ok, decrypted_data, secret} ->
              json(conn, %{
                data: decrypted_data,
                metadata: %{
                  version: secret.version || 1,
                  created_time: secret.inserted_at,
                  updated_time: secret.updated_at
                }
              })

            {:error, _} ->
              conn
              |> put_status(:not_found)
              |> json(%{error: "Secret not found"})
          end
        end

      {:error, _reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "permission denied"})
    end
  end

  @doc """
  DELETE /v1/secret/data/*path

  Delete a secret at the given path.
  """
  def delete(conn, params) do
    path = extract_path(params)
    agent = conn.assigns[:current_agent]
    secret_path = vault_path_to_dot(path)
    vault_path = "secret/data/" <> path

    case check_policy(agent, vault_path, "delete") do
      :ok ->
        case Secrets.get_secret_by_path(secret_path) do
          {:ok, secret} ->
            case Secrets.delete_secret(secret.id) do
              {:ok, _} -> send_resp(conn, :no_content, "")
              {:error, reason} ->
                conn
                |> put_status(:unprocessable_entity)
                |> json(%{error: inspect(reason)})
            end

          {:error, _} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Secret not found"})
        end

      {:error, _reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "permission denied"})
    end
  end

  @doc """
  GET /v1/secret/metadata/*path

  Get metadata for secrets at the given path.
  """
  def metadata(conn, params) do
    path = extract_path(params)
    agent = conn.assigns[:current_agent]
    secret_path = vault_path_to_dot(path)
    vault_path = "secret/metadata/" <> path

    case check_policy(agent, vault_path, "read") do
      :ok ->
        if params["list"] == "true" do
          # List secrets with a matching prefix
          list_secrets_at_path(conn, secret_path)
        else
          # Get metadata for a specific secret
          case Secrets.get_secret_by_path(secret_path) do
            {:ok, secret} ->
              json(conn, %{
                versions: %{
                  "#{secret.version || 1}" => %{
                    created_time: secret.inserted_at,
                    version: secret.version || 1
                  }
                },
                created_time: secret.inserted_at,
                updated_time: secret.updated_at,
                current_version: secret.version || 1
              })

            {:error, _} ->
              conn
              |> put_status(:not_found)
              |> json(%{error: "Secret not found"})
          end
        end

      {:error, _reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "permission denied"})
    end
  end

  # Private helpers

  defp extract_path(%{"path" => path_parts}) when is_list(path_parts) do
    Enum.join(path_parts, "/")
  end

  defp extract_path(%{"path" => path}) when is_binary(path), do: path
  defp extract_path(_), do: ""

  # Convert Vault-style slash paths to dot-notation for DB storage.
  # "test-app/database" -> "test-app.database"
  defp vault_path_to_dot(path) do
    path
    |> String.replace("/", ".")
  end

  defp check_policy(agent, vault_path, operation) do
    # Get policies associated with the agent
    policies = agent.policies || []

    matching =
      Enum.find(policies, fn policy ->
        doc = policy.policy_document || %{}
        patterns = doc["allowed_secrets"] || []
        operations = doc["allowed_operations"] || []

        path_matches?(vault_path, patterns) and operation in operations
      end)

    if matching, do: :ok, else: {:error, "No policy allows access"}
  end

  defp path_matches?(_path, []), do: false

  defp path_matches?(path, patterns) do
    Enum.any?(patterns, fn pattern ->
      regex_pattern =
        pattern
        |> String.replace(".", "\\.")
        |> String.replace("*", ".*")
        |> then(&("^" <> &1 <> "$"))

      case Regex.compile(regex_pattern) do
        {:ok, regex} -> Regex.match?(regex, path)
        _ -> path == pattern
      end
    end)
  end

  defp read_specific_version(conn, secret_path, version_str) do
    alias SecretHub.Core.Vault.SealState
    alias SecretHub.Shared.Crypto.Encryption

    with {version_num, ""} <- Integer.parse(version_str),
         {:ok, secret} <- Secrets.get_secret_by_path(secret_path),
         {:ok, version} <- Secrets.get_secret_version(secret.id, version_num),
         {:ok, master_key} <- SealState.get_master_key(),
         {:ok, json_data} <- Encryption.decrypt_from_blob(version.encrypted_data, master_key),
         {:ok, data} <- Jason.decode(json_data) do
      json(conn, %{
        data: data,
        metadata: %{
          version: version.version_number,
          created_time: version.inserted_at
        }
      })
    else
      _ ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Version not found"})
    end
  end

  defp list_secrets_at_path(conn, prefix) do
    import Ecto.Query

    secrets =
      from(s in Secret,
        where: like(s.secret_path, ^"#{prefix}%"),
        select: s.secret_path
      )
      |> Repo.all()

    # Extract relative keys
    keys =
      Enum.map(secrets, fn full_path ->
        String.replace_prefix(full_path, prefix <> ".", "")
      end)

    json(conn, %{keys: keys})
  end
end
