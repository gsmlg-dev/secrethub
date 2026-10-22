defmodule SecretHub.Web.Plugs.LaunchFeatures do
  @moduledoc "Availability of workflows excluded from the first launch profile."
  import Plug.Conn
  alias SecretHub.Shared.LaunchProfile

  @paths [
    {"/admin/pki/trust-stores", :public_trust},
    {"/admin/api/pki/trust-stores", :public_trust},
    {"/admin/pki/acme", :acme},
    {"/admin/api/pki/acme", :acme},
    {"/v1/secrets/dynamic", :dynamic_secrets},
    {"/v1/sys/leases", :dynamic_secrets},
    {"/admin/dynamic", :dynamic_secrets},
    {"/admin/leases", :dynamic_secrets},
    {"/admin/engines", :dynamic_secrets},
    {"/admin/rotators", :rotation},
    {"/admin/rotations", :rotation},
    {"/admin/api/actions/rotate-leases", :dynamic_secrets},
    {"/admin/api/actions/cleanup-expired", :dynamic_secrets}
  ]

  @dynamic_views [
    SecretHub.Web.DynamicPostgreSQLConfigLive,
    SecretHub.Web.LeaseViewerLive,
    SecretHub.Web.LeaseDashboardLive,
    SecretHub.Web.EngineConfigurationLive,
    SecretHub.Web.EngineSetupWizardLive,
    SecretHub.Web.EngineHealthDashboardLive
  ]
  @rotation_views [
    SecretHub.Web.SecretRotatorLive,
    SecretHub.Web.RotationScheduleLive,
    SecretHub.Web.RotationHistoryLive
  ]

  def init(opts), do: opts

  def call(conn, _opts) do
    feature =
      Enum.find_value(@paths, fn {prefix, feature} ->
        if conn.request_path == prefix or String.starts_with?(conn.request_path, prefix <> "/"),
          do: feature
      end)

    if is_nil(feature) or LaunchProfile.enabled?(feature) or lifecycle_recovery?(conn) do
      conn
    else
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(503, Jason.encode!(%{error: "feature_unavailable"}))
      |> halt()
    end
  end

  def allowed_view?(view) when view in @dynamic_views,
    do: LaunchProfile.enabled?(:dynamic_secrets)

  def allowed_view?(view) when view in @rotation_views, do: LaunchProfile.enabled?(:rotation)
  def allowed_view?(SecretHub.Web.TrustStoresLive), do: LaunchProfile.enabled?(:public_trust)
  # Existing material and recovery obligations remain inspectable when issuance is disabled.
  def allowed_view?(SecretHub.Web.AcmeLive), do: true
  def allowed_view?(_view), do: true

  defp lifecycle_recovery?(%{method: "GET", request_path: path}),
    do:
      path == "/admin/pki/acme" or String.starts_with?(path, "/admin/pki/acme/") or
        path == "/admin/api/pki/acme" or String.starts_with?(path, "/admin/api/pki/acme/")

  defp lifecycle_recovery?(%{
         method: "POST",
         path_info: ["admin", "api", "pki", "acme", kind, _id, action]
       }),
       do: {kind, action} in [{"orders", "cancel"}, {"versions", "revoke"}, {"cleanup", "retry"}]

  defp lifecycle_recovery?(_), do: false
end
