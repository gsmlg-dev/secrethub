defmodule SecretHub.HumanWeb.Router do
  use SecretHub.HumanWeb, :router

  pipeline :api do
    plug(:accepts, ["json"])
  end

  pipeline :authenticated do
    plug(SecretHub.HumanWeb.Plugs.Authenticate)
  end

  scope "/identity", SecretHub.HumanWeb.Bitwarden do
    pipe_through(:api)
    post("/connect/token", IdentityController, :token)
    post("/accounts/prelogin/password", IdentityController, :password_prelogin)
    post("/accounts/prelogin", IdentityController, :prelogin)
  end

  scope "/api", SecretHub.HumanWeb.Bitwarden do
    pipe_through(:api)
    get("/config", ConfigController, :show)
    post("/accounts/prelogin", IdentityController, :prelogin)
    post("/accounts/register", IdentityController, :register)
  end

  scope "/notifications", SecretHub.HumanWeb.Bitwarden do
    get("/hub", NotificationController, :connect)
  end

  scope "/api", SecretHub.HumanWeb.Bitwarden do
    pipe_through([:api, :authenticated])
    post("/accounts/key-management/user-key-id", IdentityController, :key_id)
    get("/accounts/profile", VaultController, :profile)
    get("/accounts/revision-date", VaultController, :revision)
    get("/sync", VaultController, :sync)
    get("/ciphers", VaultController, :list_ciphers)
    get("/ciphers/:id", VaultController, :get_cipher)
    post("/ciphers", VaultController, :create_cipher)
    put("/ciphers/:id", VaultController, :update_cipher)
    delete("/ciphers/:id", VaultController, :delete_cipher)
    put("/ciphers/:id/delete", VaultController, :delete_cipher)
    get("/folders", VaultController, :list_folders)
    post("/folders", VaultController, :create_folder)
    put("/folders/:id", VaultController, :update_folder)
    delete("/folders/:id", VaultController, :delete_folder)
  end

  scope "/human", SecretHub.HumanWeb.Native do
    get("/ui", UIController, :index)
  end

  scope "/human", SecretHub.HumanWeb.Native do
    pipe_through([:api, :authenticated])
    get("/capabilities", DynamicController, :capabilities)
    get("/dynamic/references", DynamicController, :references)
    post("/dynamic/references", DynamicController, :create_reference)
    post("/dynamic/references/:id/request", DynamicController, :request)
    post("/dynamic/references/:id/approval", DynamicController, :request_approval)
    post("/dynamic/reveal", DynamicController, :reveal)
    get("/leases", DynamicController, :leases)
    post("/leases/:id/renew", DynamicController, :renew)
    delete("/leases/:id", DynamicController, :revoke)
    get("/approvals", DynamicController, :approvals)
    post("/approvals/:id/approve", DynamicController, :approve)
    post("/approvals/:id/deny", DynamicController, :deny)
    get("/organizations", OrganizationController, :index)
    post("/organizations", OrganizationController, :create)
    get("/organizations/:id/members", OrganizationController, :members)
    post("/organizations/:id/members", OrganizationController, :add_member)
    delete("/organizations/:id/members/:user_id", OrganizationController, :remove_member)
    get("/organizations/:id/collections", OrganizationController, :collections)
    post("/organizations/:id/collections", OrganizationController, :create_collection)
    put("/collections/:id", OrganizationController, :update_collection)
    put("/collections/:id/permissions", OrganizationController, :permission)
    get("/collections/:id/items", OrganizationController, :items)
    post("/collections/:id/items", OrganizationController, :share)
    get("/shared/items/:id", OrganizationController, :show_item)
    put("/shared/items/:id", OrganizationController, :update_item)
    delete("/shared/items/:id", OrganizationController, :delete_item)
    get("/collections/:id/references", OrganizationController, :references)
    post("/collections/:id/references", OrganizationController, :create_reference)
    post("/collections/:id/references/:reference_id/request", OrganizationController, :request)

    post(
      "/collections/:id/references/:reference_id/approval",
      OrganizationController,
      :request_approval
    )

    get("/vault/items/:id/attachments", AttachmentController, :index)
    post("/vault/items/:id/attachments", AttachmentController, :create)
    get("/attachments/:id", AttachmentController, :download)
    delete("/attachments/:id", AttachmentController, :delete)
    get("/devices", AccountsController, :devices)
    delete("/devices/:id", AccountsController, :remove_device)
    delete("/sessions/:id", AccountsController, :revoke_session)
    get("/vault/items", VaultController, :index)
    post("/vault/items", VaultController, :create)
    get("/vault/items/:id", VaultController, :show)
    put("/vault/items/:id", VaultController, :update)
    delete("/vault/items/:id", VaultController, :delete)
    get("/vault/items/:id/history", VaultController, :history)
    post("/vault/export", VaultController, :export)
  end

  scope "/", SecretHub.HumanWeb do
    pipe_through(:api)

    get("/", PageController, :index)
    get("/health", HealthController, :show)
    get("/health/ready", HealthController, :ready)
  end
end
