defmodule SecretHub.Core.Repo.Migrations.CreateAuthorizationVersions do
  use Ecto.Migration

  def up do
    create table(:authorization_epochs, primary_key: false) do
      add(:id, :integer, primary_key: true)
      add(:version, :bigint, null: false, default: 1)
      add(:minimum_uds_auth_version, :integer, null: false, default: 1)
    end

    create(
      constraint(:authorization_epochs, :authorization_epoch_singleton,
        check: "id = 1 AND version > 0 AND minimum_uds_auth_version IN (1, 2)"
      )
    )

    create table(:authorization_subject_versions, primary_key: false) do
      add(:subject, :text, primary_key: true)
      add(:version, :bigint, null: false, default: 1)
    end

    create(
      constraint(:authorization_subject_versions, :authorization_subject_shape,
        check:
          "subject ~ '^(agent|application):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND version > 0"
      )
    )

    execute("INSERT INTO authorization_epochs(id) VALUES (1)")

    execute(
      "INSERT INTO authorization_subject_versions(subject) SELECT 'agent:' || id::text FROM agents UNION ALL SELECT 'application:' || id::text FROM applications"
    )

    execute("""
    CREATE FUNCTION secrethub_authorization_write_lock() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      PERFORM id FROM authorization_epochs WHERE id = 1 FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'authorization epoch unavailable'; END IF;
      RETURN NULL;
    END $$;
    """)

    execute("""
    CREATE FUNCTION secrethub_authorization_floor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' OR NEW.id <> OLD.id OR NEW.minimum_uds_auth_version < OLD.minimum_uds_auth_version THEN
        RAISE EXCEPTION 'authorization floor cannot be lowered or removed';
      END IF;
      RETURN NEW;
    END $$;
    """)

    execute("""
    CREATE TRIGGER authorization_floor_guard BEFORE UPDATE OR DELETE ON authorization_epochs
      FOR EACH ROW EXECUTE FUNCTION secrethub_authorization_floor_guard();
    """)

    execute("""
    CREATE FUNCTION secrethub_bump_authorization_subjects(subjects text[]) RETURNS void LANGUAGE plpgsql AS $$
    DECLARE subject_key text;
    BEGIN
      FOR subject_key IN SELECT DISTINCT x FROM unnest(subjects) x WHERE x IS NOT NULL
        ORDER BY x LOOP
        UPDATE authorization_subject_versions SET version = version + 1 WHERE subject = subject_key;
        IF NOT FOUND THEN RAISE EXCEPTION 'authorization subject unavailable'; END IF;
      END LOOP;
    END $$;
    """)

    execute("""
    CREATE FUNCTION secrethub_authorization_entity_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE subjects text[]; identifier uuid;
    BEGIN
      identifier := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
      IF TG_OP = 'INSERT' THEN
        INSERT INTO authorization_subject_versions(subject) VALUES
          ((CASE WHEN TG_TABLE_NAME = 'agents' THEN 'agent:' ELSE 'application:' END) || identifier::text);
      ELSIF TG_TABLE_NAME = 'agents' THEN
        IF TG_OP = 'DELETE' OR OLD.status IS DISTINCT FROM NEW.status OR OLD.certificate_id IS DISTINCT FROM NEW.certificate_id THEN
          PERFORM secrethub_bump_authorization_subjects(ARRAY['agent:' || identifier::text]);
        END IF;
      ELSE
        IF TG_OP = 'DELETE' OR OLD.status IS DISTINCT FROM NEW.status OR OLD.agent_id IS DISTINCT FROM NEW.agent_id THEN
          subjects := ARRAY['agent:' || OLD.agent_id::text, 'application:' || identifier::text];
          IF TG_OP <> 'DELETE' THEN subjects := subjects || ARRAY['agent:' || NEW.agent_id::text]; END IF;
          PERFORM secrethub_bump_authorization_subjects(subjects);
        END IF;
      END IF;
      RETURN NULL;
    END $$;
    """)

    execute("""
    CREATE FUNCTION secrethub_authorization_certificate_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE certificate_key uuid; subjects text[];
    BEGIN
      certificate_key := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
      SELECT array_agg(subject) INTO subjects FROM (
        SELECT 'agent:' || a.id::text AS subject FROM agents a WHERE a.certificate_id = certificate_key
        UNION SELECT 'application:' || a.app_id::text FROM app_certificates a WHERE a.certificate_id = certificate_key
      ) affected;
      PERFORM secrethub_bump_authorization_subjects(subjects);
      RETURN NULL;
    END $$;
    """)

    execute("""
    CREATE FUNCTION secrethub_authorization_association_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP <> 'INSERT' THEN PERFORM secrethub_bump_authorization_subjects(ARRAY['application:' || OLD.app_id::text]); END IF;
      IF TG_OP <> 'DELETE' AND (TG_OP = 'INSERT' OR OLD.app_id IS DISTINCT FROM NEW.app_id) THEN
        PERFORM secrethub_bump_authorization_subjects(ARRAY['application:' || NEW.app_id::text]);
      END IF;
      RETURN NULL;
    END $$;
    """)

    execute("""
    CREATE FUNCTION secrethub_authorization_policy_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE subjects text[] := ARRAY[]::text[]; identifier text;
    BEGIN
      IF TG_OP <> 'INSERT' THEN subjects := subjects || OLD.entity_bindings; END IF;
      IF TG_OP <> 'DELETE' THEN subjects := subjects || NEW.entity_bindings; END IF;
      IF (TG_OP <> 'INSERT' AND cardinality(OLD.entity_bindings) = 0)
        OR (TG_OP <> 'DELETE' AND cardinality(NEW.entity_bindings) = 0)
        OR EXISTS (SELECT 1 FROM unnest(subjects) x WHERE x !~ '^(agent|application):') THEN
        UPDATE authorization_epochs SET version = version + 1 WHERE id = 1;
      ELSE
        PERFORM secrethub_bump_authorization_subjects(subjects);
      END IF;
      FOR identifier IN SELECT DISTINCT substring(x FROM 13) FROM unnest(subjects) x WHERE x LIKE 'application:%' LOOP
        UPDATE applications SET policies = ARRAY(
          SELECT name FROM policies WHERE ('application:' || identifier) = ANY(entity_bindings) ORDER BY name
        ) WHERE id::text = identifier;
      END LOOP;
      RETURN NULL;
    END $$;
    """)

    for table <- ~w(agents applications certificates app_certificates policies) do
      execute(
        "CREATE TRIGGER #{table}_authorization_write_lock BEFORE INSERT OR UPDATE OR DELETE ON #{table} FOR EACH STATEMENT EXECUTE FUNCTION secrethub_authorization_write_lock()"
      )
    end

    for table <- ~w(agents applications) do
      execute(
        "CREATE TRIGGER #{table}_authorization_changed AFTER INSERT OR UPDATE OR DELETE ON #{table} FOR EACH ROW EXECUTE FUNCTION secrethub_authorization_entity_changed()"
      )
    end

    execute(
      "CREATE TRIGGER certificates_authorization_changed AFTER UPDATE OR DELETE ON certificates FOR EACH ROW EXECUTE FUNCTION secrethub_authorization_certificate_changed()"
    )

    execute(
      "CREATE TRIGGER app_certificates_authorization_changed AFTER INSERT OR UPDATE OR DELETE ON app_certificates FOR EACH ROW EXECUTE FUNCTION secrethub_authorization_association_changed()"
    )

    execute(
      "CREATE TRIGGER policies_authorization_changed AFTER INSERT OR UPDATE OR DELETE ON policies FOR EACH ROW EXECUTE FUNCTION secrethub_authorization_policy_changed()"
    )
  end

  def down do
    raise "authorization versions and authentication floor are irreversible"
  end
end
