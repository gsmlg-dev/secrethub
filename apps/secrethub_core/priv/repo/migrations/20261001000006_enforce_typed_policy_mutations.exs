defmodule SecretHub.Core.Repo.Migrations.EnforceTypedPolicyMutations do
  use Ecto.Migration

  def up do
    execute("""
    CREATE OR REPLACE FUNCTION secrethub_authorization_policy_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE subjects text[] := ARRAY[]::text[]; identifier text;
    BEGIN
      IF TG_OP <> 'INSERT' THEN subjects := subjects || OLD.entity_bindings; END IF;
      IF TG_OP <> 'DELETE' THEN subjects := subjects || NEW.entity_bindings; END IF;
      IF (TG_OP <> 'INSERT' AND cardinality(OLD.entity_bindings) = 0)
        OR (TG_OP <> 'DELETE' AND cardinality(NEW.entity_bindings) = 0)
        OR EXISTS (SELECT 1 FROM unnest(subjects) x WHERE x !~ '^(agent|application):') THEN
        UPDATE authorization_epochs SET version = version + 1 WHERE id = 1;
      END IF;
      PERFORM secrethub_bump_authorization_subjects(ARRAY(
        SELECT x FROM unnest(subjects) x WHERE x ~ '^(agent|application):'
      ));
      FOR identifier IN SELECT DISTINCT substring(x FROM 13) FROM unnest(subjects) x WHERE x LIKE 'application:%' LOOP
        UPDATE applications SET policies = ARRAY(
          SELECT name FROM policies WHERE ('application:' || identifier) = ANY(entity_bindings) ORDER BY name
        ) WHERE id::text = identifier;
      END LOOP;
      RETURN NULL;
    END $$;
    """)

    execute("""
    CREATE FUNCTION secrethub_typed_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF EXISTS(SELECT 1 FROM upgrade_gates WHERE name = 'typed_runtime_authorization') AND
        EXISTS(SELECT 1 FROM unnest(NEW.entity_bindings) x WHERE x !~ '^(agent|application):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') THEN
        RAISE EXCEPTION 'typed authorization binding required';
      END IF;
      RETURN NEW;
    END $$;
    """)

    execute(
      "CREATE TRIGGER typed_policy_guard BEFORE INSERT OR UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION secrethub_typed_policy_guard()"
    )
  end

  def down, do: raise("typed authorization must not be downgraded")
end
