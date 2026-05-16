defmodule SecretHub.Core.PKI.RootCA do
  @moduledoc """
  Root CA access helpers for Agent PKI.
  """

  import Ecto.Query

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Certificate

  def active_ca do
    Certificate
    |> where([c], c.cert_type in [:intermediate_ca, :root_ca])
    |> where([c], c.revoked == false)
    |> where([c], c.valid_until > ^DateTime.utc_now())
    |> order_by([c], desc: c.cert_type, desc: c.inserted_at)
    |> limit(1)
    |> Repo.one()
    |> case do
      %Certificate{} = ca -> {:ok, ca}
      nil -> {:error, :no_active_ca}
    end
  end

  def ca_chain_pem do
    SecretHub.Core.PKI.CA.get_ca_chain()
  end
end
