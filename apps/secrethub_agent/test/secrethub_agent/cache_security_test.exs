defmodule SecretHub.Agent.CacheSecurityTest do
  use ExUnit.Case, async: false
  alias SecretHub.Agent.Cache

  setup do
    start_supervised!(Cache)
    :ok
  end

  test "scoped entries preserve metadata, expiry is bounded, and offline fallback is disabled" do
    key = {"app-1", "fingerprint", "prod.db.password"}
    Cache.put(key, %{"value" => "private-marker"}, revision: 9, version: 7)
    assert {:ok, %{version: 7, revision: 9}} = Cache.get_entry(key)
    assert {:error, :not_found} = Cache.get_entry({"app-2", "fingerprint", "prod.db.password"})
    assert {:error, :not_found} = Cache.get_with_fallback(key)
    Cache.put(key, %{"value" => "expired-marker"}, ttl: 0, revision: 9, version: 7)
    assert {:error, :not_found} = Cache.get_entry(key)
  end

  test "revision tombstone rejects delayed older responses and survives reconnect clearing" do
    key = {"app-1", "fingerprint", "prod.db.password"}
    Cache.put(key, %{"value" => "old-marker"}, revision: 9)
    Cache.invalidate_path("prod.db.password", 10)
    Cache.clear()
    Cache.put(key, %{"value" => "old-marker"}, revision: 9)
    assert {:error, :not_found} = Cache.get_entry(key)
    Cache.put(key, %{"value" => "new-marker"}, revision: 10, version: 2)
    assert {:ok, %{revision: 10, version: 2}} = Cache.get_entry(key)
  end

  test "actual GenServer status does not reveal plaintext cache or queued messages" do
    Cache.put({"app", "fp", "path"}, %{"value" => "status-private-marker"}, revision: 1)
    assert Cache.stats().size == 1
    refute inspect(:sys.get_status(Cache)) =~ "status-private-marker"
  end
end
