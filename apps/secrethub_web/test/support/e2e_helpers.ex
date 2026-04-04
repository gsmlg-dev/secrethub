defmodule SecretHub.E2E.Helpers do
  @moduledoc """
  Shared helpers for E2E test scenarios.

  Uses Phoenix.ConnTest for HTTP calls and Phoenix.ChannelTest for WebSocket.
  All helpers return structured results for easy assertion.
  """

  import Phoenix.ConnTest
  import Plug.Conn

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Auth.AppRole

  @endpoint SecretHub.Web.Endpoint

  # ─── HTTP Helpers ──────────────────────────────────────────

  @doc "Build a JSON connection with optional headers."
  def api_conn(headers \\ []) do
    conn =
      build_conn()
      |> put_req_header("content-type", "application/json")

    Enum.reduce(headers, conn, fn {key, value}, conn ->
      put_req_header(conn, key, value)
    end)
  end

  @doc "Build a connection with X-Vault-Token authentication."
  def authed_conn(token) do
    api_conn([{"x-vault-token", token}])
  end

  # ─── Vault Operations ─────────────────────────────────────

  @doc """
  Initialize the vault via HTTP API.

  Returns `{conn, %{"shares" => [...], "threshold" => N, "total_shares" => N}}`.
  """
  def init_vault(shares \\ 5, threshold \\ 3) do
    conn =
      api_conn()
      |> post("/v1/sys/init", %{secret_shares: shares, secret_threshold: threshold})

    {conn, json_response(conn, 200)}
  end

  @doc """
  Unseal the vault by submitting shares one at a time via HTTP API.

  Returns the final unseal response.
  """
  def unseal_vault(shares, threshold \\ 3) do
    shares
    |> Enum.take(threshold)
    |> Enum.reduce(nil, fn share, _acc ->
      conn =
        api_conn()
        |> post("/v1/sys/unseal", %{share: share})

      json_response(conn, 200)
    end)
  end

  @doc "Get vault seal status via HTTP."
  def seal_status do
    conn = api_conn() |> get("/v1/sys/seal-status")
    json_response(conn, 200)
  end

  # ─── AppRole Operations ────────────────────────────────────

  @doc """
  Create an AppRole directly (bypasses HTTP auth).

  The AppRole management API requires admin auth, which isn't available
  in a fresh vault. This uses the module directly.

  Returns `{role_id, secret_id}`.
  """
  def create_approle(role_name, opts \\ []) do
    opts = Keyword.merge([secret_id_num_uses: 0, secret_id_ttl: 3600], opts)

    {:ok, %{role_id: role_id, secret_id: secret_id}} =
      AppRole.create_role(role_name, opts)

    {role_id, secret_id}
  end

  @doc """
  Login via AppRole REST endpoint.

  Returns `{status, response_body}`.
  """
  def approle_login(role_id, secret_id) do
    conn =
      api_conn()
      |> post("/v1/auth/approle/login", %{role_id: role_id, secret_id: secret_id})

    {conn.status, json_response(conn, conn.status)}
  end

  # ─── Agent Bootstrap ───────────────────────────────────────

  @doc """
  Bootstrap an agent with the given AppRole credentials.

  Creates the Agent record in the database so that
  `AuthController.login` (which calls `Agents.authenticate_with_approle`)
  can find it.

  Returns the agent struct.
  """
  def bootstrap_agent(role_id, secret_id, name \\ "e2e-test-agent") do
    {:ok, agent} =
      Agents.bootstrap_agent(role_id, secret_id, %{
        "name" => name,
        "ip_address" => "127.0.0.1",
        "user_agent" => "E2E Test Suite"
      })

    agent
  end

  # ─── Policy Operations ─────────────────────────────────────

  @doc """
  Create an access policy and link it to an agent.

  The policy grants the specified operations on the given path patterns.
  """
  def create_and_link_policy(agent, opts \\ []) do
    name = Keyword.get(opts, :name, "e2e-test-policy")

    allowed_secrets =
      Keyword.get(opts, :allowed_secrets, ["secret/data/e2e/*", "secret/metadata/e2e/*"])

    allowed_operations = Keyword.get(opts, :allowed_operations, ["read", "create", "delete"])

    alias SecretHub.Core.Repo
    alias SecretHub.Shared.Schemas.Policy

    {:ok, policy} =
      %Policy{}
      |> Policy.changeset(%{
        name: name,
        description: "E2E test policy",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => allowed_secrets,
          "allowed_operations" => allowed_operations
        }
      })
      |> Repo.insert()

    # Link policy to agent via join table.
    # insert_all with a raw table name bypasses Ecto schema type casting,
    # so we must dump UUIDs to their binary representation manually.
    {:ok, agent_id_bin} = Ecto.UUID.dump(agent.id)
    {:ok, policy_id_bin} = Ecto.UUID.dump(policy.id)

    Repo.insert_all("agents_policies", [
      %{agent_id: agent_id_bin, policy_id: policy_id_bin}
    ])

    policy
  end

  # ─── Secret Operations ─────────────────────────────────────

  @doc "Create or update a secret via REST API."
  def write_secret(token, path, data) do
    conn =
      authed_conn(token)
      |> post("/v1/secret/data/#{path}", %{data: data})

    {conn.status, json_response(conn, conn.status)}
  end

  @doc "Read a secret via REST API."
  def read_secret(token, path) do
    conn =
      authed_conn(token)
      |> get("/v1/secret/data/#{path}")

    {conn.status, json_response(conn, conn.status)}
  end

  # ─── Health Operations ─────────────────────────────────────

  @doc "Check health endpoint."
  def check_health(path \\ "/v1/sys/health") do
    conn = api_conn() |> get(path)
    {conn.status, json_response(conn, conn.status)}
  end

  # ─── Audit Log Queries ─────────────────────────────────────

  @doc """
  Query audit logs for a specific event type or all events.

  Returns logs ordered by sequence_number ascending.
  """
  def query_audit_logs(opts \\ []) do
    import Ecto.Query

    alias SecretHub.Core.Repo
    alias SecretHub.Shared.Schemas.AuditLog

    query =
      from(l in AuditLog,
        order_by: [asc: l.sequence_number]
      )

    query =
      case Keyword.get(opts, :event_type) do
        nil -> query
        type -> from(l in query, where: l.event_type == ^type)
      end

    query =
      case Keyword.get(opts, :secret_path) do
        nil ->
          query

        path ->
          from(l in query,
            where: fragment("?->>'secret_path' = ?", l.event_data, ^path)
          )
      end

    Repo.all(query)
  end

  # json_response/2 is available via `import Phoenix.ConnTest` above
end
