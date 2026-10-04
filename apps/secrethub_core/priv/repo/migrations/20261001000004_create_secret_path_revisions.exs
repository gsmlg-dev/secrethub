defmodule SecretHub.Core.Repo.Migrations.CreateSecretPathRevisions do
  use Ecto.Migration

  def up do
    create table(:secret_path_revisions, primary_key: false) do
      add(:secret_path, :text, primary_key: true)
      add(:revision, :bigint, null: false, default: 1)
    end

    create(constraint(:secret_path_revisions, :positive_path_revision, check: "revision > 0"))
    execute("INSERT INTO secret_path_revisions(secret_path) SELECT secret_path FROM secrets")

    execute("""
    CREATE FUNCTION secrethub_secret_path_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE path text;
    BEGIN
      FOR path IN SELECT DISTINCT x FROM unnest(ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.secret_path END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.secret_path END
      ]) x WHERE x IS NOT NULL ORDER BY x LOOP
        INSERT INTO secret_path_revisions(secret_path, revision) VALUES(path, 1)
        ON CONFLICT(secret_path) DO UPDATE SET revision = secret_path_revisions.revision + 1;
      END LOOP;
      RETURN NULL;
    END $$;
    """)

    execute("""
    CREATE TRIGGER secrets_authorization_write_lock BEFORE INSERT OR UPDATE OR DELETE ON secrets
      FOR EACH STATEMENT EXECUTE FUNCTION secrethub_authorization_write_lock();
    """)

    execute("""
    CREATE TRIGGER secrets_path_revision_changed AFTER INSERT OR UPDATE OR DELETE ON secrets
      FOR EACH ROW EXECUTE FUNCTION secrethub_secret_path_changed();
    """)
  end

  def down, do: raise("retained path revisions must not be dropped")
end
