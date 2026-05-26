defmodule SecretHub.Agent.TLSIdentity do
  @moduledoc """
  Generates the runtime TLS client identity used by Agent enrollment.

  The TLS keypair is separate from the SSH host key. The SSH key proves host
  identity by signing the CSR proof, while this module owns the key material
  embedded in the TLS CSR and later written as the Agent client key.
  """

  defstruct [:private_key, :private_key_pem, :csr_pem]

  @type t :: %__MODULE__{
          private_key: :public_key.private_key(),
          private_key_pem: binary(),
          csr_pem: binary()
        }

  @doc """
  Generates a fresh RSA TLS keypair and a CSR matching Core-required fields.
  """
  @spec generate(map()) :: {:ok, t()} | {:error, {:csr_failed, binary()}}
  def generate(required_fields) when is_map(required_fields) do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    csr =
      X509.CSR.new(private_key, subject(required_fields),
        extension_request: extension_request(required_fields)
      )

    {:ok,
     %__MODULE__{
       private_key: private_key,
       private_key_pem: X509.PrivateKey.to_pem(private_key, wrap: true),
       csr_pem: X509.CSR.to_pem(csr)
     }}
  rescue
    e -> {:error, {:csr_failed, Exception.message(e)}}
  end

  defp subject(required_fields) do
    fields = required_fields["subject"] || %{}

    [
      {"O", Map.fetch!(fields, "O")},
      {"CN", Map.fetch!(fields, "CN")}
    ]
  end

  defp extension_request(required_fields) do
    required_fields
    |> san_extension()
    |> List.wrap()
    |> Kernel.++([
      X509.Certificate.Extension.key_usage([:digitalSignature]),
      X509.Certificate.Extension.ext_key_usage([:clientAuth])
    ])
  end

  defp san_extension(required_fields) do
    san = required_fields["san"] || %{}
    san_values = uri_sans(san) ++ dns_sans(san)

    case san_values do
      [] -> nil
      values -> X509.Certificate.Extension.subject_alt_name(values)
    end
  end

  defp uri_sans(san) do
    san
    |> Map.get("uri", [])
    |> List.wrap()
    |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})
  end

  defp dns_sans(san) do
    san
    |> Map.get("dns", [])
    |> List.wrap()
    |> Enum.map(&{:dNSName, to_charlist(&1)})
  end
end
