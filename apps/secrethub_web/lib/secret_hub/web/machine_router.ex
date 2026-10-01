defmodule SecretHub.Web.MachineRouter do
  @moduledoc "Explicit machine route set; management and LiveView are absent."
  use SecretHub.Web, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  defp discard_untrusted_forwarded_for(conn, _opts) do
    Plug.Conn.delete_req_header(conn, "x-forwarded-for")
  end

  # Rate-limited authentication pipeline
  pipeline :auth_api do
    plug :api

    plug SecretHub.Web.Plugs.RateLimiter,
      max_requests: 5,
      window_ms: 60_000,
      scope: :auth
  end

  pipeline :cli_access_poll_api do
    plug :api

    plug SecretHub.Web.Plugs.RateLimiter,
      max_requests: 90,
      window_ms: 60_000,
      scope: :cli_access_poll
  end

  pipeline :agent_enrollment_api do
    plug :api

    plug SecretHub.Web.Plugs.RateLimiter,
      max_requests: 30,
      window_ms: 60_000,
      scope: :agent_enrollment
  end

  pipeline :app_certificate_bootstrap_api do
    plug :api
    plug :discard_untrusted_forwarded_for

    plug SecretHub.Web.Plugs.RateLimiter,
      max_requests: 5,
      window_ms: 60_000,
      scope: :app_certificate_bootstrap
  end

  pipeline :app_certificate_renewal_api do
    plug :api
    plug :discard_untrusted_forwarded_for

    plug SecretHub.Web.Plugs.RateLimiter,
      max_requests: 5,
      window_ms: 60_000,
      scope: :app_certificate_renewal
  end

  pipeline :vault_token do
    plug :api
    plug SecretHub.Web.Plugs.VaultTokenAuth
    plug SecretHub.Web.Plugs.LaunchFeatures
  end

  scope "/", SecretHub.Web do
    pipe_through :api

    get "/health", SysController, :health
  end

  scope "/v1/sys", SecretHub.Web do
    pipe_through :api

    get "/seal-status", SysController, :status
    get "/health", SysController, :health
    get "/health/ready", SysController, :readiness
    get "/health/live", SysController, :liveness
  end

  scope "/v1/auth/approle", SecretHub.Web do
    pipe_through :auth_api

    # AppRole login (public, rate-limited)
    post "/login", AuthController, :login
    post "/renew", AuthController, :renew

    # Public RoleID lookup for AppRole authentication (rate limited)
    get "/role/:role_name/role-id", AuthController, :get_role_id
  end

  scope "/v1/auth", SecretHub.Web do
    pipe_through :auth_api

    post "/cli-access", CliAccessController, :create
  end

  scope "/v1/auth", SecretHub.Web do
    pipe_through :cli_access_poll_api

    get "/cli-access/:request_id", CliAccessController, :poll
  end

  scope "/v1/secret", SecretHub.Web do
    pipe_through :vault_token

    post "/data/*path", SecretApiController, :create_or_update
    get "/data/*path", SecretApiController, :read
    delete "/data/*path", SecretApiController, :delete
    get "/metadata/*path", SecretApiController, :metadata
  end

  scope "/v1/agent", SecretHub.Web do
    pipe_through :agent_enrollment_api

    post "/enrollments", AgentEnrollmentController, :create
    get "/enrollments/:id/status", AgentEnrollmentController, :status
    post "/enrollments/:id/csr", AgentEnrollmentController, :submit_csr
    get "/enrollments/:id/connect-info", AgentEnrollmentController, :connect_info
    post "/enrollments/:id/finalize", AgentEnrollmentController, :finalize
  end

  scope "/v1/agent", SecretHub.Web do
    pipe_through :vault_token

    post "/certificate/renew", AgentCertController, :renew
  end

  scope "/v1/pki/app", SecretHub.Web do
    pipe_through :app_certificate_bootstrap_api

    post "/issue", PKIController, :issue_app_certificate
  end

  scope "/v1/pki/app", SecretHub.Web do
    pipe_through :app_certificate_renewal_api

    post "/renew", PKIController, :renew_app_certificate
  end

  scope "/v1/secrets/dynamic", SecretHub.Web do
    pipe_through :vault_token

    # Generate dynamic credentials
    post "/:role", DynamicSecretsController, :generate
  end

  scope "/v1/sys/leases", SecretHub.Web do
    pipe_through :vault_token

    # Lease operations
    post "/renew", DynamicSecretsController, :renew
    post "/revoke", DynamicSecretsController, :revoke
    get "/", DynamicSecretsController, :list
    get "/stats", DynamicSecretsController, :stats
  end

  scope "/v1/pki", SecretHub.Web do
    pipe_through :vault_token

    # Certificate operations
    get "/certificates", PKIController, :list_certificates
    get "/certificates/:id", PKIController, :get_certificate
  end

  scope "/v1/pki/client-auth", SecretHub.Web do
    pipe_through :api

    get "/bundle", ClientAuthPKIController, :get_bundle
    get "/authority/status", ClientAuthPKIController, :authority_status
  end

  scope "/v1/apps", SecretHub.Web do
    pipe_through :vault_token

    get "/", AppsController, :list_apps
    get "/:id", AppsController, :get_app
    get "/:id/certificates", AppsController, :list_certificates
  end

  match :*, "/*path", SecretHub.Web.ErrorController, :not_found
end
