defmodule SecretHub.Web.HTTPFetchApiClient do
  @moduledoc false
  @behaviour Swoosh.ApiClient

  @impl true
  def init do
    {:ok, _} = Application.ensure_all_started(:http_fetch)
    :ok
  end

  @impl true
  def post(url, headers, body, %Swoosh.Email{} = email) do
    options =
      Keyword.merge(email.private[:client_options] || [],
        method: :post,
        headers: [{"user-agent", "swoosh/#{Swoosh.version()}"} | headers],
        body: body
      )

    timeout = Keyword.get(options, :timeout, 15_000)

    case url
         |> IO.iodata_to_binary()
         |> HTTP.fetch(Keyword.put_new(options, :timeout, timeout))
         |> HTTP.Promise.await(timeout + 1_000) do
      %HTTP.Response{} = response ->
        headers =
          Enum.map(HTTP.Headers.to_list(response.headers), fn {name, value} ->
            {String.downcase(name), value}
          end)

        {:ok, response.status, headers, HTTP.Response.read_all(response)}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    error in RuntimeError -> {:error, error}
  end
end
