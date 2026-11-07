defmodule SecretHub.CLI.HTTPClient do
  @moduledoc false

  def get(url, opts \\ []), do: request(:get, url, opts)
  def post(url, opts \\ []), do: request(:post, url, opts)
  def delete(url, opts \\ []), do: request(:delete, url, opts)

  defp request(method, url, opts) do
    with {:ok, _} <- Application.ensure_all_started(:http_fetch) do
      timeout = Keyword.get(opts, :timeout, 15_000)

      case url
           |> HTTP.fetch(
             opts
             |> Keyword.put(:method, method)
             |> Keyword.put_new(:timeout, timeout)
           )
           |> HTTP.Promise.await(timeout + 1_000) do
        %HTTP.Response{} = response ->
          decode_response(response)

        {:error, reason} ->
          {:error, reason}
      end
    end
  rescue
    error in RuntimeError -> {:error, error}
  end

  defp decode_response(response) do
    body = HTTP.Response.read_all(response)
    {type, _} = HTTP.Response.content_type(response)

    if body != "" and (type == "application/json" or String.ends_with?(type, "+json")) do
      with {:ok, decoded} <- Jason.decode(body), do: {:ok, %{response | body: decoded}}
    else
      {:ok, %{response | body: body}}
    end
  end
end
