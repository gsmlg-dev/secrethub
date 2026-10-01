defmodule SecretHub.Web.Plugs.NoStore do
  @moduledoc "Restricts caching of secret-bearing API responses."
  import Plug.Conn

  def init(opts), do: opts
  def call(conn, _opts), do: put_resp_header(conn, "cache-control", "no-store")
end
