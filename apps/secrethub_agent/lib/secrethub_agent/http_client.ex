defmodule SecretHub.Agent.HTTPClient do
  @moduledoc false

  def request(method, url, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 15_000)

    case url
         |> HTTP.fetch(opts |> Keyword.put(:method, method) |> Keyword.put_new(:timeout, timeout))
         |> HTTP.Promise.await(timeout + 1_000) do
      %HTTP.Response{} = response ->
        {:ok, %{response | body: HTTP.Response.read_all(response)}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    error in RuntimeError -> {:error, error}
  end
end
