defmodule SecretHub.Core.PKI.ClientAuth.Authority do
  @moduledoc """
  Manages the lifecycle of the singleton Client Authentication CA Authority.

  Handles authority initialization, self-signed CA generation, master key encryption,
  and authority state inspection.
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.{Audit, Repo}
  alias SecretHub.Core.PKI.CertificateIdentity
  alias SecretHub.Core.PKI.ClientAuth.{CRLManager, Notifier}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption

  alias SecretHub.Shared.Schemas.{
    Certificate,
    ClientAuthAuthority,
    ClientAuthCrl,
    ClientAuthIdentity
  }

  alias X509.Certificate.Extension, as: CertExtension
  alias X509.Certificate.Validity

  @default_ca_cn "SecretHub Client Authentication CA"
  @default_ca_org "SecretHub"
  @default_ca_validity_days 1825
  @default_client_ttl_seconds 2_592_000
  @default_max_ttl_seconds 7_776_000
  @clock_skew_seconds 300

  @doc """
  Initializes the singleton Client Authentication CA and initial CRL.
  Fails if already initialized, or if Vault is sealed / unavailable.
  """
  @spec initialize(map(), keyword()) ::
          {:ok,
           %{
             authority: ClientAuthAuthority.t(),
             ca_certificate: Certificate.t(),
             initial_crl: ClientAuthCrl.t()
           }}
          | {:error, :authority_already_initialized | :vault_sealed | :vault_unavailable | term()}
  def initialize(attrs \\ %{}, opts \\ []) do
    with :ok <- check_unsealed(),
         {:ok, master_key} <- get_pki_master_key() do
      transact_initialization(attrs, master_key, opts)
    end
  end

  @doc """
  Returns the public status of the Client Authentication CA.
  Safe to call even when the Vault is sealed.
  """
  @spec status() ::
          {:ok, map()}
          | {:error, :authority_not_initialized}
  def status do
    query =
      from(a in ClientAuthAuthority,
        where: a.slug == "client-auth",
        preload: [:ca_certificate, :current_crl]
      )

    case Repo.one(query) do
      nil ->
        {:error, :authority_not_initialized}

      %ClientAuthAuthority{} = authority ->
        {:ok, build_status_map(authority)}
    end
  end

  @doc """
  Retrieves the active authority, CA certificate record, and decrypted CA private key.
  Requires an unsealed Vault.
  """
  @spec get_active_ca_and_key() ::
          {:ok,
           %{authority: ClientAuthAuthority.t(), ca_certificate: Certificate.t(), ca_key: term()}}
          | {:error, :authority_not_initialized | :vault_sealed | :vault_unavailable}
  def get_active_ca_and_key do
    query =
      from(a in ClientAuthAuthority,
        where: a.slug == "client-auth" and a.status == "active",
        preload: [:ca_certificate, :current_crl]
      )

    with %ClientAuthAuthority{ca_certificate: %Certificate{} = ca_cert} = authority <-
           Repo.one(query),
         :ok <- check_unsealed(),
         {:ok, master_key} <- get_pki_master_key(),
         {:ok, key_pem} <- Encryption.decrypt_from_blob(ca_cert.private_key_encrypted, master_key) do
      {:ok,
       %{
         authority: authority,
         ca_certificate: ca_cert,
         ca_key: X509.PrivateKey.from_pem!(key_pem)
       }}
    else
      nil -> {:error, :authority_not_initialized}
      {:error, :vault_sealed} -> {:error, :vault_sealed}
      {:error, _} -> {:error, :vault_unavailable}
    end
  rescue
    _ -> {:error, :vault_unavailable}
  end

  # Helpers

  defp transact_initialization(attrs, master_key, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    name = Map.get(attrs, "name") || Map.get(attrs, :name) || @default_ca_cn
    key_algo = Map.get(attrs, "key_algorithm") || Map.get(attrs, :key_algorithm) || "ecdsa_p384"

    ca_validity_days =
      Map.get(attrs, "ca_validity_days") || Map.get(attrs, :ca_validity_days) ||
        @default_ca_validity_days

    default_ttl =
      Map.get(attrs, "default_ttl_seconds") || Map.get(attrs, :default_ttl_seconds) ||
        @default_client_ttl_seconds

    max_ttl =
      Map.get(attrs, "max_ttl_seconds") || Map.get(attrs, :max_ttl_seconds) ||
        @default_max_ttl_seconds

    Repo.transaction(fn ->
      # Check if authority already exists
      existing =
        Repo.one(
          from(a in ClientAuthAuthority,
            where: a.slug == "client-auth",
            lock: "FOR UPDATE"
          )
        )

      if existing do
        Repo.rollback(:authority_already_initialized)
      end

      # Generate CA keypair
      private_key = generate_ca_private_key(key_algo)
      private_key_pem = X509.PrivateKey.to_pem(private_key)

      {:ok, encrypted_key} = Encryption.encrypt_to_blob(private_key_pem, master_key)

      not_before = DateTime.add(now, -@clock_skew_seconds, :second)
      not_after = DateTime.add(now, ca_validity_days * 86_400, :second)

      # Build self-signed CA certificate
      subject_str = "/O=#{@default_ca_org}/CN=#{name}"

      ca_extensions = [
        basic_constraints: CertExtension.basic_constraints(true),
        key_usage: CertExtension.key_usage([:keyCertSign, :cRLSign])
      ]

      hash_algo = if key_algo == "ecdsa_p384", do: :sha384, else: :sha256

      ca_cert_struct =
        X509.Certificate.self_signed(
          private_key,
          subject_str,
          template: :root_ca,
          extensions: ca_extensions,
          hash: hash_algo,
          validity: Validity.new(not_before, not_after)
        )

      ca_cert_pem = X509.Certificate.to_pem(ca_cert_struct)
      ca_cert_der = X509.Certificate.to_der(ca_cert_struct)
      canonical_fingerprint = CertificateIdentity.canonical_fingerprint_from_der(ca_cert_der)
      legacy_fingerprint = Certificate.fingerprint(ca_cert_der)
      serial_int = X509.Certificate.serial(ca_cert_struct)
      serial_hex = format_serial_hex(serial_int)

      ca_cert_attrs = %{
        serial_number: serial_hex,
        common_name: name,
        organization: @default_ca_org,
        subject: subject_str,
        issuer: subject_str,
        cert_type: :client_auth_ca,
        certificate_pem: ca_cert_pem,
        private_key_encrypted: encrypted_key,
        fingerprint: legacy_fingerprint,
        canonical_fingerprint: canonical_fingerprint,
        valid_from: not_before,
        valid_until: not_after,
        status: "active",
        key_usage: ["keyCertSign", "cRLSign"],
        extended_key_usage: []
      }

      ca_cert_record =
        %Certificate{}
        |> Certificate.changeset(ca_cert_attrs)
        |> Repo.insert!()

      # Create or activate Authority record
      authority_attrs = %{
        slug: "client-auth",
        name: name,
        status: "initializing",
        ca_certificate_id: ca_cert_record.id,
        current_generation: 0,
        current_crl_number: 0,
        key_algorithm: key_algo,
        default_ttl_seconds: default_ttl,
        max_ttl_seconds: max_ttl
      }

      authority_record =
        %ClientAuthAuthority{}
        |> ClientAuthAuthority.changeset(authority_attrs)
        |> Repo.insert!()

      # Update CA cert with client_auth_authority_id
      ca_cert_record =
        ca_cert_record
        |> Certificate.changeset(%{client_auth_authority_id: authority_record.id})
        |> Repo.update!()

      # Generate initial empty CRL (generation 1, crl_number 1)
      {:ok, initial_crl, active_authority} =
        CRLManager.generate_crl_locked(
          authority_record,
          private_key,
          ca_cert_record,
          now: now,
          actor: opts[:actor]
        )

      # Activate authority
      {:ok, active_authority} =
        active_authority
        |> ClientAuthAuthority.changeset(%{status: "active"})
        |> Repo.update()

      # Record audit
      actor = Keyword.get(opts, :actor, %{})

      :ok =
        record_authority_initialized_audit(active_authority, ca_cert_record, initial_crl, actor)

      %{
        authority: active_authority,
        ca_certificate: ca_cert_record,
        initial_crl: initial_crl
      }
    end)
    |> case do
      {:ok, result} ->
        Notifier.notify_bundle_updated(
          result.authority.current_generation,
          result.authority.current_crl_number,
          "authority_initialized"
        )

        {:ok, result}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp generate_ca_private_key("rsa_4096"), do: X509.PrivateKey.new_rsa(4096)
  defp generate_ca_private_key(_), do: X509.PrivateKey.new_ec(:secp384r1)

  defp format_serial_hex(serial) when is_integer(serial) do
    serial
    |> :binary.encode_unsigned()
    |> Base.encode16(case: :lower)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.join(":")
  end

  defp build_status_map(%ClientAuthAuthority{} = authority) do
    ca = authority.ca_certificate
    crl = authority.current_crl

    active_identities =
      Repo.aggregate(
        from(i in ClientAuthIdentity, where: i.status == "active"),
        :count
      )

    active_certs =
      Repo.aggregate(
        from(c in Certificate,
          where: c.client_auth_authority_id == ^authority.id,
          where: c.cert_type == :client_auth_client,
          where: c.revoked == false,
          where: c.valid_until > ^DateTime.utc_now()
        ),
        :count
      )

    revoked_certs =
      Repo.aggregate(
        from(c in Certificate,
          where: c.client_auth_authority_id == ^authority.id,
          where: c.cert_type == :client_auth_client,
          where: c.revoked == true
        ),
        :count
      )

    %{
      authority_id: authority.id,
      slug: authority.slug,
      name: authority.name,
      status: authority.status,
      generation: authority.current_generation,
      crl_number: authority.current_crl_number,
      current_generation: authority.current_generation,
      current_crl_number: authority.current_crl_number,
      key_algorithm: authority.key_algorithm,
      policy: %{
        default_ttl_seconds: authority.default_ttl_seconds,
        max_ttl_seconds: authority.max_ttl_seconds
      },
      ca:
        if(ca,
          do: %{
            id: ca.id,
            subject: ca.subject,
            common_name: ca.common_name,
            organization: ca.organization,
            canonical_fingerprint: ca.canonical_fingerprint,
            valid_from: DateTime.to_iso8601(ca.valid_from),
            valid_until: DateTime.to_iso8601(ca.valid_until)
          }
        ),
      crl:
        if(crl,
          do: %{
            id: crl.id,
            crl_number: crl.crl_number,
            generation: crl.generation,
            crl_der_sha256: crl.crl_der_sha256,
            this_update: DateTime.to_iso8601(crl.this_update),
            next_update: DateTime.to_iso8601(crl.next_update),
            revoked_count: crl.revoked_count
          }
        ),
      stats: %{
        active_identities_count: active_identities,
        active_certificates_count: active_certs,
        revoked_certificates_count: revoked_certs
      }
    }
  end

  defp get_pki_master_key do
    case Process.whereis(SealState) do
      nil ->
        if dev_pki_unsealed_fallback?(),
          do: {:ok, dev_fallback_key()},
          else: {:error, :vault_unavailable}

      _pid ->
        case SealState.get_master_key() do
          {:ok, key} ->
            {:ok, key}

          {:error, _} ->
            if dev_pki_unsealed_fallback?(),
              do: {:ok, dev_fallback_key()},
              else: {:error, :vault_sealed}
        end
    end
  end

  defp check_unsealed do
    case Process.whereis(SealState) do
      nil ->
        if dev_pki_unsealed_fallback?(), do: :ok, else: {:error, :vault_unavailable}

      _pid ->
        if SealState.sealed?() do
          if dev_pki_unsealed_fallback?(), do: :ok, else: {:error, :vault_sealed}
        else
          :ok
        end
    end
  end

  defp dev_pki_unsealed_fallback? do
    Application.get_env(:secrethub_core, :dev_pki_unsealed_fallback, false)
  end

  defp dev_fallback_key do
    :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")
  end

  defp record_authority_initialized_audit(authority, ca_cert, crl, actor) do
    actor_type = Map.get(actor, :actor_type) || Map.get(actor, "actor_type") || "admin"
    actor_id = Map.get(actor, :actor_id) || Map.get(actor, "actor_id") || "admin"
    ip_address = Map.get(actor, :client_ip) || Map.get(actor, "client_ip")

    attrs = %{
      event_type: "pki.client_auth.authority_initialized",
      actor_type: actor_type,
      actor_id: actor_id,
      ip_address: ip_address,
      access_granted: true,
      correlation_id: authority.id,
      event_data: %{
        "authority_id" => authority.id,
        "name" => authority.name,
        "ca_certificate_id" => ca_cert.id,
        "ca_canonical_fingerprint" => ca_cert.canonical_fingerprint,
        "key_algorithm" => authority.key_algorithm,
        "initial_crl_id" => crl.id,
        "initial_crl_number" => crl.crl_number
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      {:error, _} -> :ok
    end
  end
end
