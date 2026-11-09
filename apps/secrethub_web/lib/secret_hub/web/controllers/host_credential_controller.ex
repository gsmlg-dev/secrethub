defmodule SecretHub.Web.HostCredentialController do
  @moduledoc """
  Operator management of host credential reference bindings.

  Reachable only through the CSRF-protected management API behind Caddy mTLS,
  never through the Agent runtime. Responses contain binding metadata and
  source identifiers, never credential values.
  """

  use SecretHub.Web, :controller

  alias SecretHub.Core.HostCredentials.Management

  @actor "operator:management-api"
  @bind_fields ~w(namespace service authority account context username secret_id
    username_field value_field)
  @rebind_fields ~w(secret_id username_field value_field)

  def index(conn, %{"agent_id" => agent_id}),
    do: agent_id |> Management.list_bindings() |> respond(conn, :ok)

  def bind(conn, %{"agent_id" => agent_id} = params),
    do:
      agent_id
      |> Management.bind_reference(Map.take(params, @bind_fields), @actor)
      |> respond(conn, :created)

  def enable(conn, %{"id" => id}),
    do: id |> Management.enable_reference(@actor) |> respond(conn, :ok)

  def disable(conn, %{"id" => id}),
    do: id |> Management.disable_reference(@actor) |> respond(conn, :ok)

  def rebind(conn, %{"id" => id} = params),
    do:
      id
      |> Management.rebind_reference(Map.take(params, @rebind_fields), @actor)
      |> respond(conn, :ok)

  defp respond(result, conn, status) do
    conn =
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")

    case result do
      {:ok, bindings} when is_list(bindings) ->
        conn |> put_status(status) |> json(%{data: bindings})

      {:ok, binding} ->
        conn |> put_status(status) |> json(%{data: Management.describe(binding)})

      {:error, reason} ->
        conn |> put_status(error_status(reason)) |> json(%{error: error_code(reason)})
    end
  end

  defp error_status(reason) when reason in [:agent_not_found, :binding_not_found],
    do: :not_found

  defp error_status(:conflict), do: :conflict
  defp error_status(:audit_unavailable), do: :service_unavailable
  defp error_status(_), do: :unprocessable_entity

  defp error_code(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp error_code(_), do: "invalid_request"
end
