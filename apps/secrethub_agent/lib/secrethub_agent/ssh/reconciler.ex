defmodule SecretHub.Agent.SSH.Reconciler do
  @moduledoc """
  First-use identity enrollment and pull-based rotation. Core requests a
  generation; the Agent generates it locally and reports only the public key.
  """
  alias SecretHub.Agent.SSH.{Identity, KeyStore}

  def ensure_enrolled(account, request, root \\ KeyStore.root()) do
    if KeyStore.generations(account.uid, root) == [] do
      with {:ok, key} <- KeyStore.create(account.uid, 1, root), do: report(account, key, request)
    end

    :ok
  end

  def reconcile(requests, request, root \\ KeyStore.root(), account \\ &Identity.account/1)

  def reconcile(requests, request, root, account) when is_list(requests) do
    by_uid = Map.new(requests, &{&1["uid"], &1})

    for uid <- KeyStore.uids(root), {:ok, local} <- [account.(uid)] do
      reconcile_uid(local, Map.get(by_uid, uid), request, root)
    end

    :ok
  end

  def reconcile(_, _, _, _), do: :ok

  @doc "Connection entry point: reconciles after an inventory reply when signing is enabled."
  def after_inventory({:ok, reply}, connection) when is_map(reply) do
    if Application.get_env(:secrethub_agent, :ssh_signing_enabled) == true do
      request = fn operation, payload ->
        SecretHub.Agent.Connection.ssh_request(connection, operation, payload, 5000)
      end

      reconcile(SecretHub.Agent.SSH.Lookup.value(reply, "identity_generations") || [], request)
    end

    :ok
  end

  def after_inventory(_, _), do: :ok

  # A retired identity's keys are discarded without a report, so the next
  # first use after the operator deletes it enrolls a fresh generation 1.
  defp reconcile_uid(account, %{"status" => "retired"}, _request, root),
    do: KeyStore.prune(account.uid, [], root)

  # Core does not know this uid. Only generation 1 can be reported first;
  # Core would reject a later generation, so report nothing in that case.
  defp reconcile_uid(account, nil, request, root) do
    with [1] <- Enum.take(Enum.sort(KeyStore.generations(account.uid, root), :desc), 1),
         {:ok, key} <- KeyStore.load(account.uid, 1, root),
         do: report(account, key, request)
  end

  defp reconcile_uid(
         account,
         %{"requested_generation" => requested, "generations" => valid},
         request,
         root
       )
       when is_integer(requested) and is_list(valid) do
    latest = account.uid |> KeyStore.generations(root) |> Enum.max(fn -> 0 end)

    cond do
      requested > latest ->
        with {:ok, key} <- KeyStore.create(account.uid, requested, root),
             do: report(account, key, request)

      requested == latest and requested not in valid ->
        with {:ok, key} <- KeyStore.load(account.uid, requested, root),
             do: report(account, key, request)

      true ->
        :ok
    end

    if valid != [], do: KeyStore.prune(account.uid, Enum.uniq([requested | valid]), root)
  end

  defp reconcile_uid(_, _, _, _), do: :ok

  defp report(account, key, request) do
    request.("identity_report", %{
      "uid" => account.uid,
      "username" => account.username,
      "generation" => key.generation,
      "public_key" => key.public.public_line
    })
  end
end
