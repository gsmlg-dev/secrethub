defmodule SecretHub.Agent.HostKey do
  @moduledoc """
  SSH host-key discovery and CSR support for Agent enrollment.

  The Agent uses an existing SSH host key as its identity key. This module
  never generates fallback key material.
  """

  defstruct [
    :algorithm,
    :path,
    :private_key,
    :public_key,
    :fingerprint,
    :private_key_pem
  ]

  @type t :: %__MODULE__{
          algorithm: String.t(),
          path: Path.t(),
          private_key: tuple(),
          public_key: tuple(),
          fingerprint: String.t(),
          private_key_pem: binary() | nil
        }

  @default_paths [
    ecdsa: "/etc/ssh/ssh_host_ecdsa_key",
    rsa: "/etc/ssh/ssh_host_rsa_key",
    ed25519: "/etc/ssh/ssh_host_ed25519_key",
    dsa: "/etc/ssh/ssh_host_dsa_key"
  ]

  @preferred [:ecdsa, :rsa, :ed25519, :dsa]
  @supported [:ecdsa, :rsa]

  @doc """
  Finds the first usable SSH host key, preferring ECDSA and then RSA.
  """
  def discover(opts \\ []) do
    paths = Keyword.get(opts, :paths, @default_paths)

    @preferred
    |> Enum.map(fn algorithm -> {algorithm, Keyword.get(paths, algorithm)} end)
    |> Enum.reject(fn {_algorithm, path} -> is_nil(path) end)
    |> discover_first([])
  end

  @doc """
  Builds a PEM CSR using the discovered host private key and Core-required
  fields returned by the pending enrollment API.
  """
  def csr_pem(%__MODULE__{} = host_key, required_fields) do
    subject = required_fields["subject"] || %{}
    cn = subject["CN"] || subject[:CN]
    organization = subject["O"] || subject[:O] || "SecretHub Agents"

    san = required_fields["san"] || %{}

    uri_sans =
      san
      |> Map.get("uri", Map.get(san, :uri, []))
      |> List.wrap()
      |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})

    dns_sans =
      san
      |> Map.get("dns", Map.get(san, :dns, []))
      |> List.wrap()
      |> Enum.map(&{:dNSName, to_charlist(&1)})

    csr =
      X509.CSR.new(
        host_key.private_key,
        "/O=#{escape_rdn(organization)}/CN=#{escape_rdn(cn)}",
        extension_request: [
          X509.Certificate.Extension.subject_alt_name(uri_sans ++ dns_sans),
          X509.Certificate.Extension.key_usage([:digitalSignature]),
          X509.Certificate.Extension.ext_key_usage([:clientAuth])
        ]
      )

    {:ok, X509.CSR.to_pem(csr)}
  rescue
    e -> {:error, {:csr_failed, Exception.message(e)}}
  end

  def fingerprint(public_key) do
    :sha256
    |> :crypto.hash(:ssh_file.encode(public_key, :ssh2_pubkey))
    |> Base.encode64(padding: false)
    |> then(&"SHA256:#{&1}")
  end

  defp discover_first([], []), do: {:error, :no_supported_ssh_host_key}

  defp discover_first([], errors) do
    errors
    |> Enum.find(fn
      {:error, {:unsupported_host_key_algorithm, _}} -> true
      _ -> false
    end)
    |> case do
      nil -> {:error, :no_supported_ssh_host_key}
      error -> error
    end
  end

  defp discover_first([{algorithm, path} | rest], errors) do
    cond do
      algorithm not in @supported and File.exists?(path) ->
        {:error, {:unsupported_host_key_algorithm, to_string(algorithm)}}

      algorithm not in @supported ->
        discover_first(rest, errors)

      !File.exists?(path) ->
        discover_first(rest, errors)

      true ->
        case load(path, algorithm) do
          {:ok, host_key} -> {:ok, host_key}
          {:error, reason} -> discover_first(rest, [{:error, reason} | errors])
        end
    end
  end

  defp load(path, algorithm) do
    with {:ok, pem} <- File.read(path),
         {:ok, private_key} <- decode_private_key(pem),
         :ok <- ensure_algorithm(private_key, algorithm),
         public_key <- :ssh_file.extract_public_key(private_key) do
      {:ok,
       %__MODULE__{
         algorithm: to_string(algorithm),
         path: path,
         private_key: private_key,
         public_key: public_key,
         fingerprint: fingerprint(public_key),
         private_key_pem: private_key_pem(private_key)
       }}
    else
      {:error, :eacces} -> {:error, :unreadable_host_key}
      {:error, :enoent} -> {:error, :no_supported_ssh_host_key}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_private_key(pem) do
    case :ssh_file.decode_ssh_file(:private, :any, pem, :ignore) do
      {:ok, keys} ->
        keys
        |> Enum.map(fn {key, _attrs} -> key end)
        |> Enum.find(&private_key?/1)
        |> case do
          nil -> {:error, :unsupported_private_key_format}
          private_key -> {:ok, private_key}
        end

      {:error, :no_pass_phrase} ->
        {:error, :encrypted_host_key_requires_passphrase}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp private_key?({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}), do: true
  defp private_key?({:ECPrivateKey, _, _, _, _, _}), do: true
  defp private_key?(_), do: false

  defp ensure_algorithm({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}, :rsa), do: :ok
  defp ensure_algorithm({:ECPrivateKey, _, _, {:namedCurve, _}, _, _}, :ecdsa), do: :ok
  defp ensure_algorithm(_private_key, algorithm), do: {:error, {:unexpected_host_key, algorithm}}

  defp private_key_pem(private_key) do
    X509.PrivateKey.to_pem(private_key, wrap: true)
  rescue
    _e -> nil
  end

  defp escape_rdn(value) when is_binary(value) do
    String.replace(value, "/", "\\/")
  end

  defp escape_rdn(value), do: value |> to_string() |> escape_rdn()
end
