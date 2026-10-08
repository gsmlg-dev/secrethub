defmodule SecretHub.Human.RevealStoreTest do
  use ExUnit.Case, async: true
  alias SecretHub.Human.RevealStore

  defp actor,
    do: %{
      user_id: Ecto.UUID.generate(),
      session_id: Ecto.UUID.generate(),
      device_id: Ecto.UUID.generate()
    }

  defp lease,
    do: %{
      id: Ecto.UUID.generate(),
      expires_at: DateTime.add(DateTime.utc_now(), 600),
      status: "active"
    }

  test "atomic redemption is single-use and bound to user, session and device" do
    server = start_supervised!({RevealStore, name: nil})
    actor = actor()
    credentials = %{username: "temporary", password: "ephemeral-only"}
    assert {:ok, %{token: token}} = RevealStore.put(actor, lease(), credentials, server: server)

    for changed <- [
          %{actor | user_id: Ecto.UUID.generate()},
          %{actor | session_id: Ecto.UUID.generate()},
          %{actor | device_id: Ecto.UUID.generate()}
        ] do
      assert {:error, :invalid_reveal} = RevealStore.redeem(token, changed, server: server)
    end

    replies =
      1..8
      |> Enum.map(fn _ ->
        Task.async(fn -> RevealStore.redeem(token, actor, server: server) end)
      end)
      |> Enum.map(&Task.await/1)

    assert [{:ok, %{credentials: ^credentials}}] = Enum.filter(replies, &match?({:ok, _}, &1))
    assert Enum.count(replies, &(&1 == {:error, :invalid_reveal})) == 7
    refute inspect(:sys.get_state(server)) =~ credentials.password
    assert {:error, :invalid_reveal} = RevealStore.redeem(token, actor, server: server)
  end

  test "expiry, capacity and restart all fail closed" do
    clock = start_supervised!({Agent, fn -> 0 end})

    server =
      start_supervised!(
        {RevealStore,
         name: nil, max_entries: 1, ttl_seconds: 30, clock: fn -> Agent.get(clock, & &1) end}
      )

    owner = actor()

    assert {:ok, %{token: token, expires_in: 30}} =
             RevealStore.put(owner, lease(), %{password: "ephemeral"}, server: server)

    assert {:error, :reveal_limit} =
             RevealStore.put(owner, lease(), %{password: "other"}, server: server)

    Agent.update(clock, fn _ -> 30_001 end)
    assert {:error, :invalid_reveal} = RevealStore.redeem(token, owner, server: server)

    assert {:ok, %{token: replacement}} =
             RevealStore.put(owner, lease(), %{password: "other"}, server: server)

    other_store = start_supervised!({RevealStore, name: nil}, id: make_ref())
    assert {:error, :invalid_reveal} = RevealStore.redeem(replacement, owner, server: other_store)
  end

  test "bounds credentials and enforces per-session issuance limits" do
    server = start_supervised!({RevealStore, name: nil, per_session: 1})
    owner = actor()

    assert {:error, :invalid_credentials} =
             RevealStore.put(owner, lease(), %{password: String.duplicate("a", 20_000)},
               server: server
             )

    assert {:ok, _} = RevealStore.put(owner, lease(), %{password: "valid"}, server: server)

    assert {:error, :reveal_limit} =
             RevealStore.put(owner, lease(), %{password: "second"}, server: server)
  end
end
