defmodule SecretHub.Core.PreflightTest do
  use SecretHub.Core.DataCase, async: false
  alias SecretHub.Core.{Preflight, Repo}

  test "only the artifact's exact migration set passes schema preflight" do
    assert Preflight.schema_supported?()

    Repo.query!(
      "INSERT INTO schema_migrations (version, inserted_at) VALUES (20991001000000, now())"
    )

    refute Preflight.schema_supported?()
    Repo.query!("DELETE FROM schema_migrations WHERE version = 20991001000000")
    assert Preflight.schema_supported?()
    Repo.query!("DELETE FROM schema_migrations WHERE version = 20261001000002")
    refute Preflight.schema_supported?()
  end

  test "runtime checks return only bounded boolean results" do
    checks = Preflight.runtime_checks()
    assert Enum.all?(checks, fn {name, result} -> is_atom(name) and is_boolean(result) end)
    refute checks[:role]
    refute checks[:audit_signing_key]
  end
end
