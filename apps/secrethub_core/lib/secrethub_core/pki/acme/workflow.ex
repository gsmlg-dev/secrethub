defmodule SecretHub.Core.PKI.ACME.Workflow do
  @moduledoc "Bounded durable ACME steps. PostgreSQL owns progress; jobs may be replaced."
  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ACME.Client
  alias SecretHub.Core.PKI.ACME.DNSOperations
  alias SecretHub.Core.PKI.ACME.Keys
  alias SecretHub.Core.PKI.ACME.Publication
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.PKI.TrustStores
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.LaunchProfile
  alias SecretHub.Shared.Schemas.AcmeAccount
  alias SecretHub.Shared.Schemas.AcmeAuthorization
  alias SecretHub.Shared.Schemas.AcmeOrder
  alias SecretHub.Shared.Schemas.DNSChallengeOperation
  alias SecretHub.Shared.Schemas.ManagedCertificate
  alias SecretHub.Shared.Schemas.ManagedCertificateVersion
  import Ecto.Query

  @terminal ["published", "failed", "cancelled"]

  def step(id, opts \\ []) do
    case claim(id) do
      {:ok, order} -> perform_claimed(order, opts)
      {:error, :terminal} -> :ok
      {:error, reason} when reason in [:busy, :not_due] -> {:snooze, 30}
      error -> error
    end
  end

  defp perform_claimed(order, opts) do
    case advance(order, opts) do
      {:ok, :published} -> :ok
      {:ok, _} -> {:snooze, 1}
      {:wait, retry_at} -> defer(order, :remote_processing, retry_at)
      {:error, reason} -> handle_error(order, reason)
    end
  after
    Repo.update_all(
      from(o in AcmeOrder, where: o.id == ^order.id and o.claim_token == ^order.claim_token),
      set: [claim_token: nil, claim_expires_at: nil]
    )
  end

  def register_account(id, opts \\ []) do
    account = Repo.get(AcmeAccount, id)

    with :ok <- LaunchProfile.check(:acme),
         %AcmeAccount{enabled: true} <- account,
         {:ok, key} <- Managed.decrypt(account.encrypted_key),
         {:ok, directory} <- Client.directory(account.directory_url, opts),
         :ok <- accepted_terms(account, directory),
         {:ok, result} <- Client.register_account(directory, key, account.contact, true, opts),
         url when is_binary(url) <- result.location do
      Repo.transaction(fn ->
        account = Managed.locked!(AcmeAccount, id)

        updated =
          Managed.update!(
            Changeset.change(account,
              account_url: url,
              status: result.body["status"] || "valid",
              last_error: %{}
            )
          )

        Managed.audit!("acme.account.registered", id)
        updated
      end)
    else
      nil -> {:error, :account_unavailable}
      %AcmeAccount{} -> {:error, :disabled}
      {:error, _} = error -> error
      _ -> {:error, :invalid_account_response}
    end
  end

  defp claim(id) do
    Repo.transaction(fn ->
      order = Managed.locked!(AcmeOrder, id)

      cond do
        order.state in @terminal ->
          Repo.rollback(:terminal)

        order.claim_expires_at && DateTime.compare(order.claim_expires_at, Managed.now()) == :gt ->
          Repo.rollback(:busy)

        order.next_attempt_at && DateTime.compare(order.next_attempt_at, Managed.now()) == :gt ->
          Repo.rollback(:not_due)

        true ->
          Managed.update!(
            Changeset.change(order,
              claim_token: Ecto.UUID.generate(),
              claim_expires_at: DateTime.add(Managed.now(), 120),
              attempts: order.attempts + 1
            )
          )
      end
    end)
  end

  defp advance(order, opts) do
    resource = Repo.get!(ManagedCertificate, order.managed_certificate_id)

    cond do
      not Managed.enabled?(resource) ->
        terminal(order, "cancelled", :disabled)

      order.configuration_revision != resource.configuration_revision ->
        terminal(order, "cancelled", :configuration_superseded)

      DateTime.compare(order.deadline_at, Managed.now()) != :gt ->
        terminal(order, "failed", :order_deadline)

      true ->
        phase(order, resource, opts)
    end
  end

  defp phase(%{phase: "prepare"} = order, resource, opts) do
    with :ok <- issuance_profile(order.account_snapshot["environment"], opts),
         {:ok, key} <- Keys.generate(resource.key_policy),
         {:ok, csr} <- Keys.csr(key.private_key_pem, order.identifiers),
         {:ok, encrypted} <- Managed.encrypt(key.private_key_pem) do
      save(order, %{
        encrypted_pending_key: encrypted,
        csr: csr.der,
        csr_digest: csr.sha256,
        phase: "directory",
        state: "running"
      })
    end
  end

  defp phase(%{phase: "directory"} = order, _, opts) do
    with {:ok, directory} <- Client.directory(order.account_snapshot["directory_url"], opts),
         do: save(order, %{directory: directory, phase: "account"})
  end

  defp phase(%{phase: "account"} = order, _, opts) do
    account = Repo.get!(AcmeAccount, order.account_snapshot["id"])

    if account.account_url && account.status == "valid" do
      save(order, %{phase: "order"})
    else
      with {:ok, _} <- register_account(account.id, opts), do: save(order, %{phase: "order"})
    end
  end

  defp phase(%{phase: "order", remote_url: nil, remote_started_at: nil} = order, _, opts) do
    with {:ok, account} <- account_credentials(order),
         {:ok, order} <- save(order, %{remote_started_at: Managed.now()}) do
      result =
        Client.new_order(
          order.directory,
          account,
          order.identifiers,
          replacement_opts(order, opts)
        )

      new_order_result(order, result)
    end
  end

  defp phase(%{phase: "order", remote_url: nil} = order, _, _) do
    # A lost create response has no recoverable URL. Never guess which prior order
    # with the same names belongs to this request; a new operator request is explicit.
    terminal(order, "failed", :remote_order_outcome_unknown)
  end

  defp phase(%{phase: "order"} = order, _, _), do: save(order, %{phase: "authorizations"})

  defp phase(%{phase: "authorizations"} = order, _, opts) do
    known = Repo.all(from(a in AcmeAuthorization, where: a.order_id == ^order.id, select: a.url))

    case order.authorization_urls -- known do
      [url | _] ->
        discover_authorization(order, url, opts)

      [] ->
        repair_dns_intent(order, opts)
    end
  end

  defp phase(%{phase: "dns"} = order, _, opts) do
    case Repo.one(
           from(d in DNSChallengeOperation,
             where: d.order_id == ^order.id and d.state != "propagated",
             order_by: d.inserted_at,
             limit: 1
           )
         ) do
      nil ->
        save(order, %{phase: "challenges"})

      operation ->
        DNSOperations.advance(operation, Keyword.put(opts, :order_claim, order.claim_token))
    end
  end

  defp phase(%{phase: "challenges"} = order, _, opts) do
    case Repo.one(
           from(a in AcmeAuthorization,
             where: a.order_id == ^order.id and a.status != "valid",
             order_by: a.inserted_at,
             limit: 1
           )
         ) do
      nil -> save(order, %{phase: "finalize"})
      authorization -> progress_authorization(order, authorization, opts)
    end
  end

  defp phase(%{phase: "finalize"} = order, _, opts) do
    with {:ok, account} <- account_credentials(order),
         {:ok, result} <- Client.read_order(order.directory, account, order.remote_url, opts) do
      finalize_if_ready(order, account, result, opts)
    end
  end

  defp phase(%{phase: "download"} = order, _, opts) do
    with {:ok, account} <- account_credentials(order),
         {:ok, result} <- Client.download(order.directory, account, order.certificate_url, opts),
         true <- is_binary(result.body) do
      checkpoint(opts, :downloaded)
      save(order, %{downloaded_chain: result.body, phase: "publish"})
    else
      false -> {:error, :invalid_certificate_response}
      error -> error
    end
  end

  defp phase(%{phase: "publish"} = order, _, opts) do
    checkpoint(opts, :before_publication)

    with {:ok, _} <- Publication.publish(order.id, order.claim_token, opts) do
      Managed.enqueue(%{"cleanup_order_id" => order.id}, :cleanup)
      {:ok, :published}
    end
  end

  defp repair_dns_intent(order, opts) do
    missing =
      Repo.one(
        from(a in AcmeAuthorization,
          left_join: d in DNSChallengeOperation,
          on: d.authorization_id == a.id,
          where: a.order_id == ^order.id and a.status != "valid" and is_nil(d.id),
          select: a,
          limit: 1
        )
      )

    if missing do
      with {:ok, account} <- account_credentials(order),
           do: ensure_dns_intent(order, missing, account, opts)
    else
      save(order, %{phase: "dns"})
    end
  end

  defp finalize_if_ready(order, account, %{body: %{"status" => "ready"}}, opts) do
    with {:ok, _} <- save(order, %{remote_status: "finalizing"}),
         {:ok, result} <-
           Client.finalize(order.directory, account, order.finalize_url, order.csr, opts) do
      checkpoint(opts, :finalized)
      process_order_status(order, result)
    end
  end

  defp finalize_if_ready(order, _, result, _), do: process_order_status(order, result)

  defp discover_authorization(order, url, opts) do
    with {:ok, account} <- account_credentials(order),
         {:ok, result} <- Client.authorization(order.directory, account, url, opts),
         {:ok, attrs} <- authorization_attrs(order, url, result.body),
         {:ok, auth} <- persist_authorization(order, attrs) do
      ensure_dns_intent(order, auth, account, opts)
    end
  end

  defp authorization_attrs(
         order,
         url,
         %{"identifier" => %{"type" => "dns", "value" => identifier}, "status" => status} = body
       ) do
    challenge = Enum.find(body["challenges"] || [], &(&1["type"] == "dns-01"))
    requested = if body["wildcard"] == true, do: "*." <> identifier, else: identifier

    cond do
      requested not in order.identifiers ->
        {:error, :unexpected_authorization}

      status not in ["pending", "valid"] ->
        {:error, :authorization_failed}

      true ->
        authorization_attributes(order, url, identifier, body, challenge)
    end
  end

  defp authorization_attrs(_, _, _), do: {:error, :invalid_authorization_response}

  defp authorization_attributes(order, url, identifier, body, challenge) do
    with :ok <- challenge_available(body["status"], challenge) do
      {:ok,
       %{
         order_id: order.id,
         url: url,
         identifier: identifier,
         wildcard: body["wildcard"] == true,
         status: body["status"],
         challenge_url: challenge && challenge["url"],
         token: challenge && challenge["token"]
       }}
    end
  end

  defp challenge_available("valid", _), do: :ok

  defp challenge_available(_, %{"url" => url, "token" => token})
       when is_binary(url) and is_binary(token),
       do: :ok

  defp challenge_available(_, _), do: {:error, :dns_challenge_unavailable}

  defp persist_authorization(order, attrs) do
    Repo.transaction(fn ->
      ensure_claim!(order)

      Repo.get_by(AcmeAuthorization, order_id: order.id, url: attrs.url) ||
        Managed.insert!(AcmeAuthorization.changeset(%AcmeAuthorization{}, attrs))
    end)
  end

  defp ensure_dns_intent(_, %{status: "valid"} = auth, _, _), do: {:ok, auth}

  defp ensure_dns_intent(order, auth, account, opts) do
    thumbprint = account.key_pem |> JOSE.JWK.from_pem() |> JOSE.JWK.thumbprint()
    DNSOperations.create_intent(order, auth, Client.dns_value(auth.token, thumbprint), opts)
  end

  defp progress_authorization(order, auth, opts) do
    with {:ok, account} <- account_credentials(order),
         do: progress_authorization(order, auth, account, opts)
  end

  defp progress_authorization(order, %{status: "pending"} = auth, account, opts) do
    # Persist acknowledgement intent. A crash resumes by reading authorization.
    with {:ok, _} <-
           Repo.transaction(fn ->
             ensure_claim!(order)
             Managed.update!(Changeset.change(auth, status: "acknowledging"))
           end),
         {:ok, _} <- Client.acknowledge(order.directory, account, auth.challenge_url, opts) do
      checkpoint(opts, :acknowledged)
      {:ok, auth}
    end
  end

  defp progress_authorization(order, auth, account, opts) do
    with {:ok, result} <- Client.authorization(order.directory, account, auth.url, opts),
         do: authorization_status(order, auth, result)
  end

  defp authorization_status(order, auth, %{body: %{"status" => "valid"}}),
    do: save_authorization(order, auth, "valid")

  defp authorization_status(order, auth, %{body: %{"status" => "pending"} = body} = result) do
    challenge = Enum.find(body["challenges"] || [], &(&1["url"] == auth.challenge_url))

    case challenge do
      %{"status" => "pending"} -> save_authorization(order, auth, "pending")
      %{"status" => status} when status in ["processing", "valid"] -> {:wait, result.retry_at}
      _ -> terminal(order, "failed", :authorization_failed)
    end
  end

  defp authorization_status(_, _, %{body: %{"status" => "processing"}, retry_at: retry_at}),
    do: {:wait, retry_at}

  defp authorization_status(order, _, _), do: terminal(order, "failed", :authorization_failed)

  defp save_authorization(order, auth, status) do
    Repo.transaction(fn ->
      ensure_claim!(order)
      Managed.update!(Changeset.change(auth, status: status))
    end)
  end

  defp record_remote_order(
         order,
         %{location: url, body: %{"authorizations" => urls, "finalize" => finalize}} = result
       )
       when is_binary(url) and is_list(urls) and is_binary(finalize) do
    attrs = %{
      remote_url: url,
      authorization_urls: urls,
      finalize_url: finalize,
      remote_status: result.body["status"]
    }

    Repo.transaction(fn -> persist_remote_order(order, attrs) end)
  end

  defp record_remote_order(_, _), do: {:error, :invalid_order_response}

  defp new_order_result(order, {:ok, result}), do: record_remote_order(order, result)

  defp new_order_result(order, {:error, %{type: "urn:ietf:params:acme:error:badNonce"}} = error) do
    # An explicit nonce rejection proves this request did not create an order.
    with {:ok, _} <- save(order, %{remote_started_at: nil}), do: error
  end

  defp new_order_result(_, error), do: error

  defp persist_remote_order(order, attrs) do
    # Retain known effects even when cancellation/takeover wins the local race.
    current = Managed.locked!(AcmeOrder, order.id)

    if current.remote_url && current.remote_url != attrs.remote_url,
      do: Repo.rollback(:remote_order_conflict)

    attrs =
      if live_claim?(current, order.claim_token),
        do: Map.put(attrs, :phase, "authorizations"),
        else: attrs

    Managed.update!(Changeset.change(current, attrs))
  end

  defp process_order_status(order, result) do
    case result.body["status"] do
      "valid" ->
        if is_binary(result.body["certificate"]),
          do:
            save(order, %{
              certificate_url: result.body["certificate"],
              remote_status: "valid",
              phase: "download"
            }),
          else: {:error, :invalid_order_response}

      state when state in ["pending", "ready", "processing"] ->
        {:wait, result.retry_at}

      _ ->
        terminal(order, "failed", :remote_order_failed)
    end
  end

  defp account_credentials(order) do
    account = Repo.get!(AcmeAccount, order.account_snapshot["id"])

    with {:ok, _} <- Repo.transaction(fn -> ensure_claim!(order) end),
         {:ok, key} <- Managed.decrypt(account.encrypted_key),
         do: {:ok, %{key_pem: key, kid: account.account_url}}
  end

  defp replacement_opts(%{expected_prior_version_id: nil}, opts), do: opts

  defp replacement_opts(order, opts) do
    version = Repo.get!(ManagedCertificateVersion, order.expected_prior_version_id)

    if order.directory["renewalInfo"] && version.ari["certificate_id"],
      do: Keyword.put(opts, :replaces, version.ari["certificate_id"]),
      else: opts
  end

  defp accepted_terms(account, directory) do
    url = get_in(directory, ["meta", "termsOfService"])
    if is_nil(url) or account.terms_url == url, do: :ok, else: {:error, :terms_changed}
  end

  defp issuance_profile("staging", opts) do
    if opts[:test_mode] and opts[:test_issuance_cacerts] do
      :ok
    else
      case TrustStores.profile("letsencrypt_staging_issuance") do
        {:ok, _} -> :ok
        error -> error
      end
    end
  end

  defp issuance_profile("production", _), do: :ok

  defp save(order, attrs) do
    Repo.transaction(fn ->
      current = ensure_claim!(order)

      Managed.update!(
        Changeset.change(current, Map.merge(%{last_error: %{}, next_attempt_at: nil}, attrs))
      )
    end)
  end

  defp ensure_claim!(order) do
    current = Managed.locked!(AcmeOrder, order.id)

    unless live_claim?(current, order.claim_token),
      do: Repo.rollback(:stale_worker)

    current
  end

  defp live_claim?(order, token),
    do:
      not is_nil(token) and order.claim_token == token and
        order.state not in @terminal and not is_nil(order.claim_expires_at) and
        DateTime.compare(order.claim_expires_at, Managed.now()) == :gt

  defp terminal(order, state, reason) do
    with {:ok, updated} <- save(order, %{state: state, last_error: error(reason)}) do
      record_failure(order, state, reason)

      Managed.enqueue(%{"cleanup_order_id" => order.id}, :cleanup)
      {:ok, updated}
    end
  end

  defp record_failure(order, "failed", reason) do
    Repo.transaction(fn ->
      resource = Managed.locked!(ManagedCertificate, order.managed_certificate_id)
      record_renewal_failure(resource, order, reason)
    end)
  end

  defp record_failure(_, _, _), do: :ok

  defp record_renewal_failure(resource, order, reason) do
    if resource.configuration_revision == order.configuration_revision and
         resource.current_version_id == order.expected_prior_version_id do
      delay = min(21_600, 300 * Integer.pow(2, min(order.attempts, 6))) + :rand.uniform(60)
      due = if resource.current_version_id, do: DateTime.add(Managed.now(), delay)
      Managed.update!(Changeset.change(resource, last_error: error(reason), next_renewal_at: due))
      Managed.audit!("acme.order.failed", order.id)
    end
  end

  defp handle_error(order, reason) do
    if permanent?(reason) do
      case terminal(order, "failed", reason) do
        {:ok, _} -> :ok
        error -> error
      end
    else
      retry_at =
        if is_map(reason),
          do:
            Map.get(reason, :retry_at) ||
              Client.retry_at(%{"retry-after" => List.wrap(Map.get(reason, :retry_after))})

      defer(order, reason, retry_at)
    end
  end

  defp permanent?(reason) when is_atom(reason),
    do:
      reason in [
        :remote_order_outcome_unknown,
        :invalid_certificate_chain,
        :invalid_private_key,
        :private_key_mismatch,
        :identifier_mismatch,
        :server_auth_required,
        :leaf_is_ca,
        :invalid_certificate_validity,
        :untrusted_certificate_chain,
        :unexpected_authorization,
        :authorization_failed,
        :dns_challenge_unavailable,
        :terms_changed,
        :invalid_order_response,
        :invalid_authorization_response,
        :invalid_certificate_response
      ]

  defp permanent?(%{type: "urn:ietf:params:acme:error:badNonce"}), do: false

  defp permanent?(%{status: status}),
    do: status in 400..499 and status not in [408, 409, 425, 429]

  defp permanent?(_), do: false

  defp checkpoint(opts, phase) do
    if hook = opts[:workflow_checkpoint], do: hook.(phase)
  end

  defp defer(order, reason, retry_at) do
    delay = min(3600, 5 * Integer.pow(2, min(div(order.attempts, 5), 9))) + :rand.uniform(5)
    retry_at = retry_at || DateTime.add(Managed.now(), delay)

    save(order, %{
      last_error: error(reason),
      next_attempt_at: DateTime.truncate(retry_at, :second)
    })

    {:snooze, max(1, DateTime.diff(retry_at, Managed.now()))}
  end

  def error(reason) when is_atom(reason), do: %{"code" => Atom.to_string(reason)}

  def error(reason) when is_map(reason) do
    Map.new(Map.take(reason, [:type, :status, :reason]), fn {key, value} ->
      {to_string(key), public_error_value(key, value)}
    end)
  end

  def error(_), do: %{"code" => "operation_failed"}

  defp public_error_value(:type, value) when is_binary(value) do
    if Regex.match?(~r/\Aurn:ietf:params:acme:error:[A-Za-z]+\z/, value),
      do: value,
      else: "remote_problem"
  end

  defp public_error_value(_, value) when is_atom(value), do: Atom.to_string(value)
  defp public_error_value(_, value) when is_integer(value), do: value
  defp public_error_value(_, _), do: "remote_problem"
end
