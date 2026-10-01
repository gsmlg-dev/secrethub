defmodule SecretHub.Agent.CertVerifier do
  @moduledoc "Fail-closed app certificate trust, configured from persisted Core enrollment material."
  use GenServer
  alias SecretHub.Agent.UDSAuth

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  def configure_trust(chain), do: GenServer.call(__MODULE__, {:configure_trust, chain})
  def verify_app_cert_pem(pem), do: GenServer.call(__MODULE__, {:verify, pem})

  def verify_app_cert(der),
    do: verify_app_cert_pem(:public_key.pem_encode([{:Certificate, der, :not_encrypted}]))

  def load_ca_cert(path \\ "/etc/secrethub/ca.crt") do
    case File.read(path) do
      {:ok, pem} -> configure_trust(pem)
      _ -> configure_trust(nil)
    end
  end

  @impl true
  def init(_opts), do: {:ok, []}

  @impl true
  def handle_call({:configure_trust, chain}, _from, _state) do
    case parse_chain(chain) do
      {:ok, certificates} -> {:reply, :ok, certificates}
      _ -> {:reply, {:error, "CA_UNAVAILABLE"}, []}
    end
  end

  def handle_call({:verify, _pem}, _from, []), do: {:reply, {:error, "CA_UNAVAILABLE"}, []}
  def handle_call({:verify, pem}, _from, chain), do: {:reply, verify(pem, chain), chain}

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted)

  defp parse_chain(pem) when is_binary(pem) do
    entries = :public_key.pem_decode(pem)
    certificates = for {:Certificate, der, :not_encrypted} <- entries, do: der

    if certificates != [] and length(certificates) == length(entries) do
      Enum.each(certificates, &X509.Certificate.from_der!/1)
      {:ok, certificates}
    else
      {:error, "CA_UNAVAILABLE"}
    end
  rescue
    _ -> {:error, "CA_UNAVAILABLE"}
  end

  defp parse_chain(_), do: {:error, "CA_UNAVAILABLE"}

  defp verify(pem, chain) do
    with [{:Certificate, der, :not_encrypted}] <- :public_key.pem_decode(pem),
         {:ok, certificate} <- X509.Certificate.from_der(der),
         [app_id] <- X509.Certificate.subject(certificate, "CN"),
         {:ok, ^app_id} <- Ecto.UUID.cast(app_id),
         ["SecretHub Applications"] <- X509.Certificate.subject(certificate, "O"),
         [{:uniformResourceIdentifier, uri}] <-
           extension_values(certificate, :subject_alt_name, :SubjectAltName),
         true <- to_string(uri) == "urn:secrethub:app:#{app_id}",
         true <-
           {1, 3, 6, 1, 5, 5, 7, 3, 2} in extension_values(
             certificate,
             :ext_key_usage,
             :ExtKeyUsageSyntax
           ),
         {:ok, _} <-
           :public_key.pkix_path_validation(
             List.last(chain),
             Enum.reverse(Enum.drop(chain, -1)) ++ [der],
             []
           ),
         public_key = X509.Certificate.public_key(certificate),
         {:ok, _} <- UDSAuth.algorithm(public_key) do
      {:ok,
       %{
         app_id: app_id,
         canonical_fingerprint: Base.encode16(:crypto.hash(:sha256, der), case: :lower),
         public_key: public_key
       }}
    else
      _ -> {:error, "INVALID_CERTIFICATE"}
    end
  rescue
    _ -> {:error, "INVALID_CERTIFICATE"}
  end

  defp extension_values(certificate, type, der_type) do
    case X509.Certificate.extension(certificate, type) do
      {:Extension, _, _, values} when is_list(values) -> values
      {:Extension, _, _, der} when is_binary(der) -> :public_key.der_decode(der_type, der)
      _ -> []
    end
  end
end
