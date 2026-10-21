# Run with an assembled Core release's eval command. No Core application is started.
alias SecretHub.Core.PKI.TrustStores

{:ok, _} = Application.ensure_all_started(:public_key)

for app <- [:castore, :secrethub_core] do
  case Application.load(app) do
    :ok -> :ok
    {:error, {:already_loaded, ^app}} -> :ok
  end
end

nil = Process.whereis(SecretHub.Core.Repo)
nil = Process.whereis(SecretHub.Core.Vault.SealState)

release_root = System.fetch_env!("RELEASE_ROOT") |> Path.expand()
bundle_path = CAStore.file_path() |> Path.expand()
true = String.starts_with?(bundle_path, release_root <> "/")
{:ok, pem} = TrustStores.pem()
^pem = File.read!(bundle_path)
{:ok, catalogue} = TrustStores.catalogue()
{:ok, cacerts} = TrustStores.cacerts()
true = catalogue.root_count > 100
true = catalogue.root_count == length(cacerts)
true = catalogue.package_version != "unknown"
true = catalogue.release != "unknown"
true = catalogue.sha256 == Base.encode16(:crypto.hash(:sha256, pem), case: :lower)
true = Enum.all?(catalogue.roots, &is_binary(&1.subject))
notice = Application.app_dir(:secrethub_core, "priv/pki/PUBLIC-TRUST-NOTICE.txt") |> File.read!()
true = String.contains?(notice, "Apache License, Version 2.0")
true = String.contains?(notice, "Mozilla Public")

for {root, der} <- Enum.zip(catalogue.roots, cacerts) do
  true = root.fingerprint_sha256 == Base.encode16(:crypto.hash(:sha256, der), case: :lower)
end

# A bundled staging issuance profile is separate from the default public roots.
{:ok, staging} = TrustStores.profile("letsencrypt_staging_issuance")
true = staging.sha256 != catalogue.sha256
true = staging.cacerts != cacerts
{:error, :unknown_trust_store} = TrustStores.pem("internal_agent_identity")
# Retry-After's HTTP-date parser must also be packaged, rather than available
# only through development/test dependencies.
now = ~U[2026-10-22 00:00:00Z]
expected_retry = DateTime.add(now, 120)

^expected_retry =
  SecretHub.Core.PKI.ACME.Client.retry_at(
    %{"retry-after" => ["Thu, 22 Oct 2026 00:02:00 GMT"]},
    now
  )

nil = Process.whereis(SecretHub.Core.Repo)
nil = Process.whereis(SecretHub.Core.Vault.SealState)

IO.puts(
  Jason.encode!(%{
    result: "PASS",
    release: catalogue.release,
    package: "castore",
    package_version: catalogue.package_version,
    root_count: catalogue.root_count,
    sha256: catalogue.sha256,
    staging_root_count: staging.root_count,
    staging_sha256: staging.sha256,
    bundle_path: bundle_path,
    services_started: false
  })
)
