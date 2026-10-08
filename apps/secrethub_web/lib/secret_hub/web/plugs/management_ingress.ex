defmodule SecretHub.Web.Plugs.ManagementIngress do
  @moduledoc """
  Restricts the private management backend to the trusted proxy's transport peer.

  Caddy authenticates the operator. Forwarded identity headers, Host and old
  administrator sessions do not establish this transport boundary.
  """

  import Plug.Conn

  @loopback [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]

  # Phoenix installs socket_dispatch before endpoint plugs. Wrap the completed
  # endpoint call so WebSocket and long-poll obey the same boundary as HTTP.
  defmacro __before_compile__(_env) do
    quote do
      defoverridable call: 2

      def call(conn, opts) do
        conn = SecretHub.Web.Plugs.ManagementIngress.call(conn, __MODULE__)
        if conn.halted, do: conn, else: super(conn, opts)
      end
    end
  end

  def call(conn, endpoint) do
    conn = put_resp_header(conn, "cache-control", "no-store")

    if conn.remote_ip in endpoint.config(:trusted_proxy_ips, @loopback) and
         allowed_origin?(conn, endpoint) do
      assign(conn, :current_actor, %{type: "operator", id: "operator", external_id: "operator"})
    else
      conn |> send_resp(403, "Forbidden") |> halt()
    end
  end

  defp allowed_origin?(conn, endpoint) do
    case get_req_header(conn, "origin") do
      [] ->
        true

      [origin] ->
        case endpoint.config(:check_origin) do
          origins when is_list(origins) -> origin in origins
          _ -> origin == endpoint.url()
        end

      _ ->
        false
    end
  end
end
