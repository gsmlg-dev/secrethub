defmodule SecretHub.Core.PKI.ManagedCertificates do
  @moduledoc "Management commands for public server certificates and their durable obligations."
  alias Ecto.Changeset
  alias SecretHub.Core.Audit
  alias SecretHub.Core.AuthorizationVersions
  alias SecretHub.Core.PKI.ACME.Client
  alias SecretHub.Core.PKI.ACME.Keys
  alias SecretHub.Core.PKI.ACME.Worker
  alias SecretHub.Core.PKI.DNS
  alias SecretHub.Core.PKI.DNS.Names
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Secrets
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.LaunchProfile
  alias SecretHub.Shared.Schemas.AcmeAccount
  alias SecretHub.Shared.Schemas.AcmeOrder
  alias SecretHub.Shared.Schemas.DNSChallengeOperation
  alias SecretHub.Shared.Schemas.DNSProvider
  alias SecretHub.Shared.Schemas.ManagedCertificate
  alias SecretHub.Shared.Schemas.ManagedCertificateVersion
  alias SecretHub.Shared.Schemas.Secret
  import Ecto.Query

  @terminal ["published", "failed", "cancelled"]
  @directories %{
    "production" => "https://acme-v02.api.letsencrypt.org/directory",
    "staging" => "https://acme-staging-v02.api.letsencrypt.org/directory"
  }

  def now, do: DateTime.utc_now() |> DateTime.truncate(:second)
  def list_accounts, do: Repo.all(from(a in AcmeAccount, order_by: a.inserted_at))
  def list_providers, do: Repo.all(from(p in DNSProvider, order_by: p.name))
  @doc "Lists credential secret paths without loading encrypted or plaintext values."
  def credential_secret_options do
    if LaunchProfile.enabled?(:acme), do: Repo.all(credential_secrets_query()), else: []
  end

  @doc "Reads available public zones using the selected stored credential reference."
  def discover_provider_zones(attrs, opts \\ []) do
    attrs = Map.put_new(attrs, "credential_mode", "secret")

    with :ok <- LaunchProfile.check(:acme),
         :ok <- discovery_configuration(attrs),
         {:ok, config} <- resolve_provider_reference(attrs),
         :ok <- provider_credentials(config),
         {:ok, credentials} <- discovery_credentials(config),
         {:ok, zones} <- DNS.list_zones(config, credentials, opts) do
      transaction(fn ->
        audit!("acme.provider.zones_discovered", config["credential_secret_id"], %{
          provider: config["provider"],
          zone_count: length(zones)
        })

        zones
      end)
    else
      {:error, reason} -> {:error, discovery_error(reason)}
    end
  end

  def list_managed, do: Repo.all(from(m in ManagedCertificate, order_by: m.slug))

  @doc "Lists published certificate metadata without loading PEM or encrypted material."
  def list_published_certificates do
    Repo.all(
      from(v in ManagedCertificateVersion,
        join: m in ManagedCertificate,
        on: m.id == v.managed_certificate_id,
        order_by: [desc: v.inserted_at, desc: v.publication_sequence],
        select: %{
          id: v.id,
          managed_certificate_id: m.id,
          name: m.name,
          slug: m.slug,
          publication_sequence: v.publication_sequence,
          environment: v.environment,
          fingerprint: v.fingerprint,
          identifiers: v.identifiers,
          not_before: v.not_before,
          not_after: v.not_after,
          key_policy: v.key_policy,
          inserted_at: v.inserted_at,
          quarantined_at: v.quarantined_at,
          revocation_state: v.revocation_state,
          current: coalesce(m.current_version_id == v.id, false)
        }
      )
    )
  end

  def get_managed(id), do: fetch(ManagedCertificate, id)
  def get_order(id), do: fetch(AcmeOrder, id)
  def get_version(id), do: fetch(ManagedCertificateVersion, id)

  def list_versions(id),
    do:
      Repo.all(
        from(v in ManagedCertificateVersion,
          where: v.managed_certificate_id == ^id,
          order_by: [desc: v.publication_sequence]
        )
      )

  def list_orders(id),
    do:
      Repo.all(
        from(o in AcmeOrder,
          where: o.managed_certificate_id == ^id,
          order_by: [desc: o.inserted_at],
          limit: 100
        )
      )

  def list_cleanup,
    do:
      Repo.all(
        from(d in DNSChallengeOperation,
          where: d.cleanup_status != "cleaned",
          order_by: d.inserted_at,
          limit: 200
        )
      )

  @doc "Reads the current service agreement from a supported environment's ACME directory."
  def discover_account_terms(environment, opts \\ []) do
    with :ok <- LaunchProfile.check(:acme),
         directory when is_binary(directory) <- @directories[environment],
         {:ok, metadata} <- Client.directory(directory, opts),
         %{"meta" => %{"termsOfService" => url}} when is_binary(url) <- metadata,
         %URI{scheme: "https", host: host, userinfo: nil, fragment: nil} when is_binary(host) <-
           URI.parse(url) do
      {:ok, url}
    else
      nil -> {:error, :unsupported_environment}
      {:error, _} = error -> error
      _ -> {:error, :terms_unavailable}
    end
  end

  def create_account(attrs) do
    with :ok <- LaunchProfile.check(:acme),
         true <- attrs["terms_accepted"] == true,
         directory when is_binary(directory) <- @directories[attrs["environment"]],
         {:ok, key} <- Keys.generate(),
         {:ok, encrypted} <- encrypt(key.private_key_pem) do
      attrs =
        Map.take(attrs, ~w(name environment contact terms_url))
        |> Map.merge(%{
          "directory_url" => directory,
          "terms_accepted_at" => now(),
          "encrypted_key" => encrypted
        })

      transaction(fn ->
        account = insert!(AcmeAccount.changeset(%AcmeAccount{}, attrs))
        audit!("acme.account.created", account.id)
        enqueue!(%{"account_id" => account.id})
        account
      end)
    else
      false -> {:error, :terms_acceptance_required}
      nil -> {:error, :unsupported_environment}
      error -> error
    end
  end

  def update_account(id, attrs) when is_map(attrs) do
    transaction(fn ->
      account = locked!(AcmeAccount, id)
      changes = Map.take(attrs, ~w(enabled))

      accepting_terms = attrs["terms_accepted"] == true and is_binary(attrs["terms_url"])

      if accepting_terms and not LaunchProfile.enabled?(:acme),
        do: Repo.rollback(:feature_unavailable)

      changes =
        if accepting_terms do
          Map.merge(changes, %{"terms_url" => attrs["terms_url"], "terms_accepted_at" => now()})
        else
          changes
        end

      account = update!(AcmeAccount.changeset(account, changes))
      audit!("acme.account.updated", id)
      if accepting_terms and account.enabled, do: enqueue_account_registration!(id)
      account
    end)
  end

  def register_account(id) do
    with :ok <- LaunchProfile.check(:acme), {:ok, %{enabled: true}} <- fetch(AcmeAccount, id) do
      transaction(fn ->
        account = locked!(AcmeAccount, id)
        account.enabled or Repo.rollback(:disabled)
        enqueue_account_registration!(id)
      end)
    else
      {:ok, _} -> {:error, :disabled}
      error -> error
    end
  end

  def create_provider(attrs) do
    with :ok <- LaunchProfile.check(:acme),
         {:ok, attrs} <- resolve_provider_reference(attrs),
         :ok <- provider_configuration(attrs) do
      transaction(fn ->
        provider =
          insert!(
            DNSProvider.changeset(
              %DNSProvider{},
              Map.take(
                attrs,
                ~w(name provider credential_mode credential_secret_id zones enabled)
              )
            )
          )

        audit!("acme.provider.created", provider.id)
        provider
      end)
    end
  end

  def update_provider(id, attrs) do
    transaction(fn ->
      provider = locked!(DNSProvider, id)

      attrs =
        Map.take(
          attrs,
          ~w(name credential_mode credential_secret_id credential_secret_path zones enabled)
        )

      if Map.keys(attrs) -- ~w(name enabled) != [] and provider_obligations?(id),
        do: Repo.rollback(:outstanding_obligations)

      candidate =
        provider
        |> Map.from_struct()
        |> Map.new(fn {k, v} -> {to_string(k), v} end)
        |> Map.merge(attrs)

      candidate =
        case resolve_provider_reference(candidate) do
          {:ok, candidate} -> candidate
          {:error, reason} -> Repo.rollback(reason)
        end

      case provider_configuration(candidate) do
        :ok -> :ok
        {:error, reason} -> Repo.rollback(reason)
      end

      changes = Map.take(candidate, ~w(name credential_mode credential_secret_id zones enabled))
      updated = update!(DNSProvider.changeset(provider, changes))
      audit!("acme.provider.updated", id)
      updated
    end)
  end

  def create_managed(attrs) do
    attrs =
      if Map.has_key?(attrs, "name"),
        do: Map.put_new_lazy(attrs, "slug", fn -> "cert-" <> Ecto.UUID.generate() end),
        else: attrs

    with :ok <- LaunchProfile.check(:acme),
         {:ok, names} <- normalize_identifiers(attrs["identifiers"]),
         {:ok, account} <- fetch(AcmeAccount, attrs["account_id"]),
         {:ok, bindings} <- validate_bindings(names, attrs["bindings"] || []) do
      transaction(fn ->
        resource =
          insert!(
            ManagedCertificate.changeset(
              %ManagedCertificate{},
              Map.take(attrs, ~w(name slug key_policy enabled))
              |> Map.merge(%{
                "account_id" => account.id,
                "identifiers" => names,
                "bindings" => bindings
              })
            )
          )

        audit!("acme.certificate.configured", resource.id)
        resource
      end)
    end
  end

  def update_managed(id, attrs) do
    transaction(fn ->
      resource = locked!(ManagedCertificate, id)
      attrs = Map.take(attrs, ~w(name identifiers bindings key_policy enabled))

      names =
        case normalize_identifiers(attrs["identifiers"] || resource.identifiers) do
          {:ok, names} -> names
          {:error, reason} -> Repo.rollback(reason)
        end

      bindings =
        case validate_bindings(names, attrs["bindings"] || resource.bindings) do
          {:ok, bindings} -> bindings
          {:error, reason} -> Repo.rollback(reason)
        end

      updated =
        update!(
          ManagedCertificate.changeset(
            resource,
            Map.merge(attrs, %{
              "identifiers" => names,
              "bindings" => bindings,
              "configuration_revision" => resource.configuration_revision + 1
            })
          )
        )

      audit!("acme.certificate.updated", id)
      updated
    end)
  end

  def request_issue(id, request_id) when is_binary(request_id) do
    transaction(fn ->
      resource = locked!(ManagedCertificate, id)

      digest =
        digest(%{
          identifiers: resource.identifiers,
          bindings: resource.bindings,
          configuration_revision: resource.configuration_revision,
          key_policy: resource.key_policy,
          account_id: resource.account_id
        })

      case Repo.get_by(AcmeOrder, managed_certificate_id: id, request_id: request_id) do
        %AcmeOrder{request_digest: ^digest} = existing ->
          existing

        %AcmeOrder{} ->
          Repo.rollback(:idempotency_conflict)

        nil ->
          create_order!(resource, request_id, digest)
      end
    end)
  end

  defp create_order!(resource, request_id, digest) do
    id = resource.id
    require_enabled!(resource)

    if Repo.exists?(
         from(o in AcmeOrder,
           where: o.managed_certificate_id == ^id and o.state not in ^@terminal
         )
       ),
       do: Repo.rollback(:active_order)

    account = Repo.get!(AcmeAccount, resource.account_id)
    bindings = snapshot_bindings!(resource.bindings)

    order =
      insert!(
        AcmeOrder.changeset(%AcmeOrder{}, %{
          managed_certificate_id: id,
          request_id: request_id,
          request_digest: digest,
          configuration_revision: resource.configuration_revision,
          expected_prior_version_id: resource.current_version_id,
          identifiers: resource.identifiers,
          bindings: bindings,
          account_snapshot: %{
            "id" => account.id,
            "environment" => account.environment,
            "directory_url" => account.directory_url
          },
          deadline_at: DateTime.add(now(), 86_400)
        })
      )

    audit!("acme.issuance.requested", id, %{order_id: order.id})
    enqueue!(%{"order_id" => order.id})
    order
  end

  def cancel_order(id) do
    transaction(fn ->
      order = locked!(AcmeOrder, id)
      if order.state == "published", do: Repo.rollback(:already_published)

      order =
        update!(
          Changeset.change(order, state: "cancelled", claim_token: nil, claim_expires_at: nil)
        )

      audit!("acme.order.cancelled", id)
      enqueue!(%{"cleanup_order_id" => id}, :cleanup)
      order
    end)
  end

  def retry_cleanup(id) do
    with {:ok, operation} <- fetch(DNSChallengeOperation, id) do
      enqueue(%{"cleanup_operation_id" => operation.id}, :cleanup)
    end
  end

  def request_revocation(version_id, reason \\ 0) when reason in [0, 1, 3, 4, 5] do
    transaction(fn ->
      AuthorizationVersions.lock_global()
      version = Repo.get(ManagedCertificateVersion, version_id) || Repo.rollback(:not_found)
      resource = locked!(ManagedCertificate, version.managed_certificate_id)
      version = locked!(ManagedCertificateVersion, version_id)

      version =
        update!(
          Changeset.change(version,
            quarantined_at: version.quarantined_at || now(),
            revocation_state:
              if(version.revocation_state == "confirmed", do: "confirmed", else: "pending"),
            revocation_reason: reason,
            revocation_next_attempt_at: now()
          )
        )

      if resource.current_version_id == version.id do
        # Existing trigger increments the normal path/cache revision, under its usual lock.
        Repo.update_all(
          from(s in SecretHub.Shared.Schemas.Secret, where: s.id == ^version.output_secret_id),
          set: [status: "quarantined", updated_at: now()]
        )
      end

      audit!("acme.revocation.requested", version.id)
      enqueue!(%{"revoke_version_id" => version.id}, :cleanup)
      version
    end)
  end

  def export_version(id) do
    with {:ok, version} <- get_version(id),
         :ok <- available(version),
         {:ok, material} <-
           Secrets.read_exact_material(version.output_secret_id, version.secret_version_number),
         true <-
           material["certificate_version_id"] == version.id and
             material["fingerprint"] == version.fingerprint do
      {:ok, material}
    else
      false -> {:error, :material_identity_mismatch}
      error -> error
    end
  end

  def available(%ManagedCertificateVersion{quarantined_at: nil, not_after: expiry}) do
    if DateTime.compare(expiry, now()) == :gt, do: :ok, else: {:error, :certificate_expired}
  end

  def available(%ManagedCertificateVersion{}), do: {:error, :certificate_quarantined}

  def check_delivery(secret_id, material_version \\ nil) do
    version =
      if material_version do
        Repo.get_by(ManagedCertificateVersion,
          output_secret_id: secret_id,
          secret_version_number: material_version
        )
      else
        Repo.one(
          from(v in ManagedCertificateVersion,
            join: m in ManagedCertificate,
            on: m.current_version_id == v.id,
            where: m.output_secret_id == ^secret_id
          )
        )
      end

    cond do
      version -> available(version)
      owned_output?(secret_id) -> {:error, :unknown_managed_material}
      true -> :ok
    end
  end

  def owned_output?(id),
    do: Repo.exists?(from(m in ManagedCertificate, where: m.output_secret_id == ^id))

  def retained_material?(secret_id, number),
    do:
      Repo.exists?(
        from(v in ManagedCertificateVersion,
          where: v.output_secret_id == ^secret_id and v.secret_version_number == ^number
        )
      )

  def require_enabled!(resource) do
    with :ok <- LaunchProfile.check(:acme),
         true <- resource.enabled,
         %AcmeAccount{enabled: true} <- shared(AcmeAccount, resource.account_id),
         true <-
           Enum.all?(resource.bindings, fn b ->
             match?(%DNSProvider{enabled: true}, shared(DNSProvider, b["provider_id"]))
           end) do
      :ok
    else
      _ -> Repo.rollback(:disabled)
    end
  end

  defp shared(schema, id), do: Repo.one(from(r in schema, where: r.id == ^id, lock: "FOR SHARE"))

  def enabled?(resource) do
    LaunchProfile.enabled?(:acme) and resource.enabled and
      match?(%AcmeAccount{enabled: true}, Repo.get(AcmeAccount, resource.account_id)) and
      Enum.all?(
        resource.bindings,
        &match?(%DNSProvider{enabled: true}, Repo.get(DNSProvider, &1["provider_id"]))
      )
  end

  def encrypt(bytes) do
    with {:ok, key} <- master_key(), do: Encryption.encrypt_to_blob(bytes, key)
  end

  def decrypt(bytes) do
    with {:ok, key} <- master_key(), do: Encryption.decrypt_from_blob(bytes, key)
  end

  defp master_key do
    SealState.get_master_key()
  catch
    :exit, _ -> {:error, :vault_unavailable}
  end

  def credentials(%{"credential_mode" => "aws_environment"}) do
    with id when is_binary(id) <- System.get_env("AWS_ACCESS_KEY_ID"),
         secret when is_binary(secret) <- System.get_env("AWS_SECRET_ACCESS_KEY") do
      {:ok,
       %{
         "access_key_id" => id,
         "secret_access_key" => secret,
         "session_token" => System.get_env("AWS_SESSION_TOKEN")
       }}
    else
      _ -> {:error, :credentials_unavailable}
    end
  end

  def credentials(%{"credential_secret_id" => id}) when is_binary(id) do
    with {:ok, secret} <- Secrets.get_secret(id),
         {:ok, data, _} <- Secrets.read_decrypted(secret.secret_path),
         do: {:ok, data}
  end

  defp enqueue_account_registration!(id) do
    args = %{"account_id" => id}
    worker = Oban.Worker.to_string(Worker)

    job =
      Repo.one(
        from(j in Oban.Job,
          where:
            j.worker == ^worker and j.args == ^args and
              j.state in ["available", "executing", "scheduled", "retryable"],
          order_by: [
            asc: fragment("CASE WHEN ? IN ('available', 'executing') THEN 0 ELSE 1 END", j.state),
            asc: j.id
          ],
          limit: 1,
          lock: "FOR UPDATE"
        )
      )

    case job do
      nil ->
        enqueue!(args)

      %{state: state} when state in ["scheduled", "retryable"] ->
        :ok = Oban.retry_job(SecretHub.Core.Oban, job)
        Repo.get!(Oban.Job, job.id)

      job ->
        job
    end
  end

  def enqueue(args, kind \\ :progress) do
    module = if kind == :cleanup, do: SecretHub.Core.PKI.ACME.CleanupWorker, else: Worker
    Oban.insert(SecretHub.Core.Oban, module.new(args))
  end

  defp enqueue!(args, kind \\ :progress) do
    case enqueue(args, kind) do
      {:ok, job} -> job
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  def audit!(event, id, data \\ %{}) do
    case Audit.log_event(%{
           event_type: event,
           hash_version: 2,
           actor_type: "system",
           actor_id: "acme",
           access_granted: true,
           event_data: Map.put(data, :resource_id, id)
         }) do
      {:ok, log} -> log
      {:error, reason} -> Repo.rollback({:audit_failed, reason})
    end
  end

  def transaction(fun), do: Repo.transaction(fun)
  def insert!(changeset), do: checked(Repo.insert(changeset))
  def update!(changeset), do: checked(Repo.update(changeset))
  defp checked({:ok, record}), do: record
  defp checked({:error, reason}), do: Repo.rollback(reason)

  def locked!(schema, id),
    do:
      Repo.one(from(r in schema, where: r.id == ^id, lock: "FOR UPDATE")) ||
        Repo.rollback(:not_found)

  defp fetch(schema, id) when is_binary(id) do
    case Ecto.UUID.cast(id) do
      {:ok, id} ->
        case Repo.get(schema, id) do
          nil -> {:error, :not_found}
          record -> {:ok, record}
        end

      :error ->
        {:error, :invalid_id}
    end
  end

  defp fetch(_, _), do: {:error, :invalid_id}

  defp credential_secrets_query do
    from(s in Secret,
      where:
        s.secret_type == :static and s.engine_type == "static" and s.status == "active" and
          not is_nil(s.encrypted_data),
      order_by: s.secret_path,
      select: %{id: s.id, secret_path: s.secret_path}
    )
  end

  defp resolve_provider_reference(%{"credential_mode" => "aws_environment"} = attrs),
    do:
      {:ok, attrs |> Map.delete("credential_secret_path") |> Map.put("credential_secret_id", nil)}

  defp resolve_provider_reference(%{"credential_secret_path" => path} = attrs)
       when is_binary(path) and path != "" do
    case Repo.one(where(credential_secrets_query(), [s], s.secret_path == ^path)) do
      %{id: id} ->
        {:ok,
         attrs |> Map.delete("credential_secret_path") |> Map.put("credential_secret_id", id)}

      nil ->
        {:error, :credential_secret_not_found}
    end
  end

  defp resolve_provider_reference(%{"credential_secret_path" => _}),
    do: {:error, :credential_reference_required}

  defp resolve_provider_reference(attrs), do: {:ok, attrs}

  defp discovery_configuration(%{"provider" => provider, "credential_mode" => mode}) do
    cond do
      provider not in ~w(cloudflare route53) -> {:error, :unsupported_provider}
      mode not in ~w(secret aws_environment) -> {:error, :unsupported_credential_mode}
      true -> :ok
    end
  end

  defp discovery_configuration(_), do: {:error, :unsupported_provider}

  defp discovery_credentials(config) do
    credentials(config)
  catch
    :exit, _ -> {:error, :vault_unavailable}
  end

  defp discovery_error(%{reason: reason}), do: discovery_error(reason)

  defp discovery_error(reason)
       when reason in [
              :feature_unavailable,
              :unsupported_provider,
              :unsupported_credential_mode,
              :credential_reference_required,
              :credential_secret_not_found,
              :credentials_unavailable,
              :sealed,
              :not_initialized,
              :vault_unavailable,
              :authentication,
              :throttled,
              :provider_unavailable,
              :invalid_provider_response,
              :pagination_limit
            ],
       do: reason

  defp discovery_error(_), do: :zone_discovery_failed

  defp provider_configuration(attrs) do
    allowed =
      ~w(name provider credential_mode credential_secret_id zones enabled id inserted_at updated_at __meta__)

    with true <- Map.keys(attrs) -- allowed == [],
         :ok <- provider_zones(attrs["zones"]) do
      provider_credentials(attrs)
    else
      false -> {:error, :unsupported_provider_settings}
      error -> error
    end
  end

  defp provider_zones(zones) when is_list(zones) and zones != [] do
    if Enum.all?(zones, &valid_zone?/1), do: :ok, else: {:error, :invalid_zone}
  end

  defp provider_zones(_), do: {:error, :explicit_zones_required}

  defp provider_credentials(%{"credential_mode" => "aws_environment", "provider" => "route53"}),
    do: :ok

  defp provider_credentials(%{"credential_mode" => "aws_environment"}),
    do: {:error, :unsupported_credential_mode}

  defp provider_credentials(%{"credential_secret_id" => id}) when is_binary(id), do: :ok
  defp provider_credentials(_), do: {:error, :credential_reference_required}

  defp valid_zone?(%{"zone_id" => id, "zone_name" => name} = zone) do
    is_binary(id) and id != "" and Map.keys(zone) -- ~w(zone_id zone_name) == [] and
      match?({:ok, ^name}, Names.normalize_identifier(name)) and
      not String.starts_with?(name, "*.")
  end

  defp valid_zone?(_), do: false

  defp normalize_identifiers(names) when is_list(names) and length(names) in 1..100 do
    Enum.reduce_while(names, {:ok, []}, fn name, {:ok, acc} ->
      case Names.normalize_identifier(name) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, names} -> {:ok, names |> Enum.uniq() |> Enum.sort()}
      error -> error
    end
  end

  defp normalize_identifiers(_), do: {:error, :invalid_identifiers}

  defp validate_bindings(names, bindings) when is_list(bindings) do
    valid = Enum.all?(bindings, &valid_binding?/1)

    covered = valid and Enum.all?(names, &match?({:ok, _}, Names.bind(&1, bindings)))
    if valid and covered, do: {:ok, bindings}, else: {:error, :invalid_bindings}
  end

  defp validate_bindings(_, _), do: {:error, :invalid_bindings}

  defp valid_binding?(binding) when is_map(binding) do
    Map.keys(binding) -- ~w(provider_id zone_id zone_name suffix delegated_owner) == [] and
      valid_binding_names?(binding) and configured_binding?(binding)
  end

  defp valid_binding?(_), do: false

  defp configured_binding?(binding) do
    case fetch(DNSProvider, binding["provider_id"]) do
      {:ok, %DNSProvider{zones: zones}} ->
        Enum.any?(
          zones,
          &(&1["zone_id"] == binding["zone_id"] and &1["zone_name"] == binding["zone_name"])
        )

      _ ->
        false
    end
  end

  defp valid_binding_names?(binding) do
    suffix = binding["suffix"] || binding["zone_name"]
    delegated = binding["delegated_owner"]

    match?({:ok, ^suffix}, Names.normalize_identifier(suffix)) and
      not String.starts_with?(suffix, "*.") and
      (is_nil(delegated) or
         (is_binary(delegated) and
            Regex.match?(~r/\A[a-z0-9_.-]+\z/, delegated) and
            Names.within_zone?(delegated, binding["zone_name"])))
  end

  defp snapshot_bindings!(bindings) do
    Enum.map(bindings, fn b ->
      p = Repo.get!(DNSProvider, b["provider_id"])

      Map.merge(b, %{
        "provider" => p.provider,
        "credential_mode" => p.credential_mode,
        "credential_secret_id" => p.credential_secret_id
      })
    end)
  end

  defp provider_obligations?(id) do
    Repo.exists?(
      from(d in DNSChallengeOperation,
        where: d.provider_id == ^id and d.cleanup_status != "cleaned"
      )
    ) or
      Enum.any?(
        Repo.all(from(o in AcmeOrder, where: o.state not in ^@terminal, select: o.bindings)),
        fn bindings -> Enum.any?(bindings, &(&1["provider_id"] == id)) end
      )
  end

  defp digest(value),
    do:
      :crypto.hash(:sha256, :erlang.term_to_binary(value, [:deterministic]))
      |> Base.encode16(case: :lower)
end
