defmodule SecretHub.WebWeb.Router do
  use SecretHub.WebWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {SecretHub.WebWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Admin authentication plug
  defp require_admin_auth(conn, _opts) do
    SecretHub.WebWeb.AdminAuthController.require_admin_auth(conn, [])
  end

  pipeline :admin_browser do
    plug :browser
    plug :require_admin_auth
  end

  pipeline :admin_api do
    plug :api
    plug :require_admin_auth
  end

  scope "/", SecretHub.WebWeb do
    pipe_through :browser

    get "/", PageController, :home
  end

  # Vault management routes (no auth required - needed for initial setup)
  scope "/vault", SecretHub.WebWeb do
    pipe_through :browser

    live "/init", VaultInitLive, :index
    live "/unseal", VaultUnsealLive, :index
  end

  # Admin authentication routes (no auth required)
  scope "/admin/auth", SecretHub.WebWeb do
    pipe_through :browser

    get "/login", AdminPageController, :login_form
    post "/login", AdminAuthController, :login
    get "/health", AdminAuthController, :health_check
  end

  # Admin routes with authentication
  scope "/admin", SecretHub.WebWeb do
    pipe_through :admin_browser

    get "/", AdminPageController, :index
    live "/dashboard", AdminDashboardLive, :index
    live "/agents", AgentMonitoringLive, :index
    live "/agents/:id", AgentMonitoringLive, :show
    live "/secrets", SecretManagementLive, :index
    live "/policies", PolicyManagementLive, :index
    live "/audit", AuditLogLive, :index
    live "/pki", PKIManagementLive, :index
    live "/certificates", AdminCertificateLive, :index
    live "/approles", AppRoleManagementLive, :index
    live "/dynamic/postgresql", DynamicPostgreSQLConfigLive, :index
    live "/leases", LeaseViewerLive, :index
    live "/leases/dashboard", LeaseDashboardLive, :index

    delete "/logout", AdminAuthController, :logout
  end

  # Admin API routes
  scope "/admin/api", SecretHub.WebWeb do
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
  scope "/v1/sys", SecretHub.WebWeb do
    pipe_through :api

    post "/init", SysController, :init
    post "/unseal", SysController, :unseal
    post "/seal", SysController, :seal
    get "/seal-status", SysController, :status
    get "/health", SysController, :health
  end

  # Authentication API routes (AppRole management)
  scope "/v1/auth/approle", SecretHub.WebWeb do
    pipe_through :api

    # Role management
    post "/role/:role_name", AuthController, :create_role
    get "/role/:role_name", AuthController, :get_role
    get "/role", AuthController, :list_roles
    delete "/role/:role_name", AuthController, :delete_role

    # SecretID operations
    post "/role/:role_name/secret-id", AuthController, :rotate_secret_id
    get "/role/:role_name/role-id", AuthController, :get_role_id
  end

  # Dynamic Secrets API routes
  scope "/v1/secrets/dynamic", SecretHub.WebWeb do
    pipe_through :api

    # Generate dynamic credentials
    post "/:role", DynamicSecretsController, :generate
  end

  # Lease management API routes
  scope "/v1/sys/leases", SecretHub.WebWeb do
    pipe_through :api

    # Lease operations
    post "/renew", DynamicSecretsController, :renew
    post "/revoke", DynamicSecretsController, :revoke
    get "/", DynamicSecretsController, :list
    get "/stats", DynamicSecretsController, :stats
  end

  # PKI API routes (Certificate Authority operations)
  scope "/v1/pki", SecretHub.WebWeb do
    pipe_through :api

    # CA generation
    post "/ca/root/generate", PKIController, :generate_root_ca
    post "/ca/intermediate/generate", PKIController, :generate_intermediate_ca

    # Certificate operations
    post "/sign-request", PKIController, :sign_csr
    get "/certificates", PKIController, :list_certificates
    get "/certificates/:id", PKIController, :get_certificate
    post "/certificates/:id/revoke", PKIController, :revoke_certificate
  end

  # Other API scopes may use custom stacks.
  # scope "/api", SecretHub.WebWeb do
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

      live_dashboard "/dashboard", metrics: SecretHub.WebWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
