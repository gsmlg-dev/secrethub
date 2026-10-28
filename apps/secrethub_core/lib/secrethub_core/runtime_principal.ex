defmodule SecretHub.Core.RuntimePrincipal do
  @moduledoc "Core-derived runtime identity; socket identity must come from the trusted mTLS endpoint."
  import Ecto.Query
  alias SecretHub.Core.{AccessAudit, Agents, Audit, Repo}
  alias SecretHub.Core.PKI.CertificateIdentity
  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.Schemas.{Agent, AppCertificate, Certificate}
  alias SecretHub.Shared.Schemas.Application, as: App

  defstruct [
    :agent_id,
    :agent_public_id,
    :agent_certificate_id,
    :application_id,
    :certificate_id,
    :fingerprint,
    :local_auth_version
  ]

  @doc "Resolves only the Agent identity supplied by the trusted runtime socket."
  def resolve_agent_runtime_principal(identity, correlation \\ %{})

  def resolve_agent_runtime_principal(identity, correlation) when is_map(identity) do
    result =
      with agent_public_id when is_binary(agent_public_id) <- identity[:agent_id],
           certificate_id when is_binary(certificate_id) <- identity[:certificate_id],
           :ok <- Agents.authorize_runtime(agent_public_id, certificate_id),
           %Agent{} = agent <- Repo.get_by(Agent, agent_id: agent_public_id),
           %Certificate{} = certificate <- Repo.get(Certificate, certificate_id),
           true <- certificate.entity_type == "agent",
           true <- live?(certificate.valid_from, certificate.valid_until) do
        {:ok,
         %__MODULE__{
           agent_id: agent.id,
           agent_public_id: agent.agent_id,
           agent_certificate_id: certificate.id
         }}
      else
        {:error, :certificate_revoked} -> {:error, :revoked}
        {:error, :certificate_expired} -> {:error, :expired}
        _ -> {:error, :invalid_agent}
      end

    case result do
      {:ok, _} -> result
      {:error, reason} -> record_denial(identity, nil, reason, correlation)
    end
  end

  def resolve_agent_runtime_principal(_, _), do: {:error, :invalid_principal}

  def resolve_runtime_principal(identity, app_claim, fingerprint, correlation \\ %{})

  def resolve_runtime_principal(identity, app_claim, fingerprint, correlation)
      when is_map(identity) do
    result =
      with {:ok, _} <- CertificateIdentity.decode_fingerprint(fingerprint),
           {:ok, app_id} <- cast_app_id(app_claim),
           agent_public_id when is_binary(agent_public_id) <- identity[:agent_id],
           agent_certificate_id when is_binary(agent_certificate_id) <- identity[:certificate_id],
           :ok <- Agents.authorize_runtime(agent_public_id, agent_certificate_id),
           %Agent{} = agent <- Repo.get_by(Agent, agent_id: agent_public_id),
           [{certificate, association, app}] <-
             Repo.all(
               from(c in Certificate,
                 join: ac in AppCertificate,
                 on: ac.certificate_id == c.id,
                 join: a in App,
                 on: a.id == ac.app_id,
                 where: c.canonical_fingerprint == ^fingerprint,
                 select: {c, ac, a}
               )
             ),
           true <- app.id == app_id and app.agent_id == agent.id and app.status == "active",
           true <-
             certificate.cert_type == :app_client and certificate.entity_type == "app" and
               certificate.entity_id == app.id,
           false <- certificate.revoked,
           true <- is_nil(association.revoked_at),
           true <-
             live?(certificate.valid_from, certificate.valid_until) and
               live?(association.issued_at, association.expires_at) do
        {:ok,
         %__MODULE__{
           agent_id: agent.id,
           agent_public_id: agent.agent_id,
           agent_certificate_id: agent_certificate_id,
           application_id: app.id,
           certificate_id: certificate.id,
           fingerprint: fingerprint
         }}
      else
        {:error, :invalid_fingerprint} -> {:error, :invalid_fingerprint}
        {:error, :invalid_application} -> {:error, :invalid_application}
        {:error, _} -> {:error, :invalid_agent}
        _ -> {:error, :invalid_principal}
      end

    case result do
      {:ok, _} -> result
      {:error, reason} -> record_denial(identity, fingerprint, reason, correlation)
    end
  end

  def resolve_runtime_principal(_, _, _, _), do: {:error, :invalid_principal}

  defp record_denial(identity, fingerprint, reason, correlation) do
    canonical =
      case CertificateIdentity.decode_fingerprint(fingerprint) do
        {:ok, _} -> fingerprint
        _ -> nil
      end

    reason = denial_reason(identity, canonical, reason)

    application_id =
      if canonical do
        Repo.one(
          from(c in Certificate,
            join: ac in AppCertificate,
            on: ac.certificate_id == c.id,
            where: c.canonical_fingerprint == ^canonical,
            select: ac.app_id,
            limit: 1
          )
        )
      end

    attrs = %{
      event_type: "secret.accessed",
      access_granted: false,
      actor_type: if(application_id, do: "application", else: "agent"),
      actor_id: application_id || identity[:agent_id],
      agent_id: identity[:agent_id],
      event_data: %{
        agent_id: identity[:agent_id],
        certificate_fingerprint: canonical,
        reason: Atom.to_string(reason)
      }
    }

    Repo.transaction(fn ->
      # Failed identity resolution cannot assign the claimed application's ID.
      with {:ok, _} <-
             AccessAudit.record_core(%{
               phase: "core_decision",
               outcome: "denied",
               reason_code: Event.reason(reason),
               agent_id: identity[:agent_id],
               application_id: nil,
               identity_status: "unverified",
               attribution: "none",
               request_id: correlation[:request_id],
               attempt_id: correlation[:attempt_id]
             }),
           {:ok, _} <- Audit.log_event(attrs) do
        {:error, reason}
      else
        _ -> Repo.rollback(:audit_unavailable)
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, _} -> {:error, :audit_unavailable}
    end
  rescue
    _ in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :audit_unavailable}
  catch
    :exit, _ -> {:error, :audit_unavailable}
  end

  defp denial_reason(identity, fingerprint, fallback) do
    agent = if identity[:agent_id], do: Repo.get_by(Agent, agent_id: identity[:agent_id])

    bound =
      if fingerprint do
        Repo.one(
          from(c in Certificate,
            join: ac in AppCertificate,
            on: ac.certificate_id == c.id,
            join: a in App,
            on: a.id == ac.app_id,
            where: c.canonical_fingerprint == ^fingerprint,
            select: {c, ac, a},
            limit: 1
          )
        )
      end

    identity_denial_reason(agent, bound, fallback)
  end

  defp identity_denial_reason(agent, bound, fallback) do
    case {agent, bound} do
      {%{status: :revoked}, _} ->
        :revoked

      {%{status: status}, _} when status in [:suspended, :rejected] ->
        :disabled

      {_, {%{revoked: true}, _, _}} ->
        :revoked

      {_, {_, %{revoked_at: revoked}, _}} when not is_nil(revoked) ->
        :revoked

      {_, {_, _, %{status: status}}} when status != "active" ->
        :disabled

      {_, {certificate, association, _}} ->
        certificate_denial_reason(certificate, association, fallback)

      _ ->
        fallback
    end
  end

  defp certificate_denial_reason(certificate, association, fallback) do
    if live?(certificate.valid_from, certificate.valid_until) and
         live?(association.issued_at, association.expires_at),
       do: fallback,
       else: :expired
  end

  defp cast_app_id(claim) when is_binary(claim) do
    if Regex.match?(~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/, claim),
      do: {:ok, claim},
      else: {:error, :invalid_application}
  end

  defp cast_app_id(_), do: {:error, :invalid_application}

  defp live?(%DateTime{} = first, %DateTime{} = last),
    do:
      DateTime.compare(first, DateTime.utc_now()) != :gt and
        DateTime.compare(last, DateTime.utc_now()) == :gt

  defp live?(_, _), do: false
end
