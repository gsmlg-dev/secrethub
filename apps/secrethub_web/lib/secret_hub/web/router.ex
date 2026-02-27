defmodule SecretHub.Web.Router do
  use SecretHub.Web, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {SecretHub.Web.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Admin authentication plug
  defp require_admin_auth(conn, _opts) do
    SecretHub.Web.AdminAuthController.require_admin_auth(conn, [])
  end

  pipeline :admin_browser do
    plug :browser
    plug :require_admin_auth
  end

  pipeline :admin_api do
    plug :api
    plug :require_admin_auth
  end

  # AppRole management pipeline (requires authentication)
  pipeline :approle_management do
    plug :api
    plug SecretHub.Web.Plugs.AppRoleAuth
  end

  # Rate-limited authentication pipeline
  pipeline :auth_api do
    plug :api

    plug SecretHub.Web.Plugs.RateLimiter,
      max_requests: 5,
      window_ms: 60_000,
      scope: :auth
  end

  scope "/", SecretHub.Web do
    pipe_through :browser

    get "/", PageController, :home
  end

  # Vault management routes (no auth required - needed for initial setup)
  scope "/vault", SecretHub.Web do
    pipe_through :browser

    live "/init", VaultInitLive, :index
    live "/unseal", VaultUnsealLive, :index
  end

  # Admin authentication routes (no auth required)
  scope "/admin/auth", SecretHub.Web do
    pipe_through :browser

    get "/login", AdminPageController, :login_form
    post "/login", AdminAuthController, :login
    get "/health", AdminAuthController, :health_check
  end

  # Admin routes with authentication
  scope "/admin", SecretHub.Web do
    pipe_through :admin_browser

    get "/", AdminPageController, :index
    delete "/logout", AdminAuthController, :logout

    # All admin LiveViews use the admin layout and hook
    live_session :admin,
      on_mount: [{SecretHub.Web.AdminLayoutHook, :default}],
      layout: {SecretHub.Web.Layouts, :admin} do
      live "/dashboard", AdminDashboardLive, :index
      live "/agents", AgentMonitoringLive, :index
      live "/agents/:id", AgentMonitoringLive, :show
      live "/secrets", SecretManagementLive, :index
      live "/secrets/:id/versions", SecretVersionHistoryLive, :index
      live "/policies", PolicyManagementLive, :index
      live "/policies/new", PolicyEditorLive, :new
      live "/policies/templates", PolicyTemplatesLive, :index
      live "/policies/:id/edit", PolicyEditorLive, :edit
      live "/policies/:id/simulate", PolicySimulatorLive, :show
      live "/audit", AuditLogLive, :index
      live "/pki", PKIManagementLive, :index
      live "/certificates", AdminCertificateLive, :index
      live "/approles", AppRoleManagementLive, :index
      live "/dynamic/postgresql", DynamicPostgreSQLConfigLive, :index
      live "/leases", LeaseViewerLive, :index
      live "/leases/dashboard", LeaseDashboardLive, :index
      live "/templates", TemplateManagementLive, :index
      live "/templates/:template_id", TemplateManagementLive, :show
      live "/cluster", ClusterStatusLive, :index
      live "/cluster/nodes/:node_id", NodeHealthLive, :show
      live "/cluster/alerts", HealthAlertsLive, :index
      live "/cluster/auto-unseal", AutoUnsealConfigLive, :index
      live "/cluster/deployment", DeploymentStatusLive, :index
      live "/engines", EngineConfigurationLive, :index
      live "/engines/new/:type", EngineSetupWizardLive, :new
      live "/engines/:id/health", EngineHealthDashboardLive, :show
      live "/rotations", RotationScheduleLive, :index
      live "/rotations/:id", RotationScheduleLive, :show
      live "/rotations/:id/history", RotationHistoryLive, :show
      # TODO: Implement MetricsDashboardLive module
      # live "/metrics", MetricsDashboardLive, :index
      live "/alerts", AlertConfigurationLive, :index
      live "/anomalies", AnomalyDetectionLive, :index
      live "/performance", PerformanceDashboardLive, :index
    end
  end

  # Admin API routes
  scope "/admin/api", SecretHub.Web do
    pipe_through :admin_api

    get "/dashboard/stats", AdminDashboardController, :system_stats
    get "/dashboard/agents", AdminDashboardController, :connected_agents
    get "/dashboard/secrets", AdminDashboardController, :secret_stats
    get "/dashboard/audit", AdminDashboardController, :audit_logs
    post "/export/audit", AdminDashboardController, :export_audit_logs
    post "/actions/rotate-leases", AdminDashboardController, :rotate_all_leases
    post "/actions/cleanup-expired", AdminDashboardController, :cleanup_expired_secrets
    post "/agents/:id/disconnect", AgentController, :disconnect
    post "/agents/:id/reconnect", AgentController, :reconnect
    post "/agents/:id/restart", AgentController, :restart
  end

  # System API routes (initialization, unsealing, health)
  # These do not require authentication as they are needed before the vault is operational
  scope "/v1/sys", SecretHub.Web do
    pipe_through :api

    post "/init", SysController, :init
    post "/unseal", SysController, :unseal
    post "/seal", SysController, :seal
    get "/seal-status", SysController, :status
    get "/health", SysController, :health
    get "/health/ready", SysController, :readiness
    get "/health/live", SysController, :liveness
  end

  # Authentication API routes (AppRole management - PROTECTED)
  scope "/v1/auth/approle", SecretHub.Web do
    pipe_through :approle_management

    # Role management (requires admin authentication)
    post "/role/:role_name", AuthController, :create_role
    get "/role", AuthController, :list_roles
    delete "/role/:role_name", AuthController, :delete_role
  end

  # Authentication API routes (AppRole usage - rate limited)
  scope "/v1/auth/approle", SecretHub.Web do
    pipe_through :auth_api

    # AppRole login (public, rate-limited)
    post "/login", AuthController, :login

    # Public endpoints for AppRole authentication (rate limited)
    get "/role/:role_name", AuthController, :get_role
    post "/role/:role_name/secret-id", AuthController, :rotate_secret_id
    get "/role/:role_name/role-id", AuthController, :get_role_id
  end

  # Token-authenticated pipeline for Vault-style API
  pipeline :vault_token do
    plug :api
    plug SecretHub.Web.Plugs.VaultTokenAuth
  end

  # Secret CRUD API (token-authenticated via X-Vault-Token)
  scope "/v1/secret", SecretHub.Web do
    pipe_through :vault_token

    post "/data/*path", SecretApiController, :create_or_update
    get "/data/*path", SecretApiController, :read
    delete "/data/*path", SecretApiController, :delete
    get "/metadata/*path", SecretApiController, :metadata
  end

  # Agent certificate operations (token-authenticated)
  scope "/v1/agent", SecretHub.Web do
    pipe_through :vault_token

    post "/certificate/renew", AgentCertController, :renew
  end

  # Dynamic Secrets API routes (token-authenticated)
  scope "/v1/secrets/dynamic", SecretHub.Web do
    pipe_through :vault_token

    # Generate dynamic credentials
    post "/:role", DynamicSecretsController, :generate
  end

  # Lease management API routes (token-authenticated)
  scope "/v1/sys/leases", SecretHub.Web do
    pipe_through :vault_token

    # Lease operations
    post "/renew", DynamicSecretsController, :renew
    post "/revoke", DynamicSecretsController, :revoke
    get "/", DynamicSecretsController, :list
    get "/stats", DynamicSecretsController, :stats
  end

  # PKI API routes (token-authenticated)
  scope "/v1/pki", SecretHub.Web do
    pipe_through :vault_token

    # CA generation
    post "/ca/root/generate", PKIController, :generate_root_ca
    post "/ca/intermediate/generate", PKIController, :generate_intermediate_ca

    # Certificate operations
    post "/sign-request", PKIController, :sign_csr
    get "/certificates", PKIController, :list_certificates
    get "/certificates/:id", PKIController, :get_certificate
    post "/certificates/:id/revoke", PKIController, :revoke_certificate

    # Application certificate operations
    post "/app/issue", PKIController, :issue_app_certificate
    post "/app/renew", PKIController, :renew_app_certificate
    post "/app/revoke", PKIController, :revoke_app_certificate
  end

  # Application management API routes (token-authenticated)
  scope "/v1/apps", SecretHub.Web do
    pipe_through :vault_token

    # Application registration and management
    post "/", AppsController, :register_app
    get "/", AppsController, :list_apps
    get "/:id", AppsController, :get_app
    put "/:id", AppsController, :update_app
    delete "/:id", AppsController, :delete_app

    # Application lifecycle
    post "/:id/suspend", AppsController, :suspend_app
    post "/:id/activate", AppsController, :activate_app

    # Application certificates
    get "/:id/certificates", AppsController, :list_certificates
  end

  # Other API scopes may use custom stacks.
  # scope "/api", SecretHub.Web do
  #   pipe_through :api
  # end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:secrethub_web, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: SecretHub.Web.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
