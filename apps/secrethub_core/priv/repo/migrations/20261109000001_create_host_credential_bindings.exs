defmodule SecretHub.Core.Repo.Migrations.CreateHostCredentialBindings do
  use Ecto.Migration

  # Additive host credential storage. Bindings hold lookup metadata and an
  # association to existing encrypted Secret storage; never plaintext values.
  def up do
    create table(:host_credential_bindings, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:owner_agent_id, references(:agents, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:namespace, :text, null: false)
      add(:service, :text, null: false)
      add(:authority, :text, null: false, default: "")
      add(:account, :text, null: false, default: "")
      add(:context, :text, null: false, default: "")
      add(:username, :text)
      add(:source_kind, :text, null: false)
      # Nullable live association; deleting a source never cascades to bindings.
      add(:secret_id, references(:secrets, type: :binary_id, on_delete: :nilify_all))
      # Retained original source identity. A recreated path never retargets it.
      add(:source_secret_id, :binary_id, null: false)
      add(:username_field, :text)
      add(:value_field, :text, null: false)
      add(:state, :text, null: false, default: "active")
      add(:revision, :bigint, null: false, default: 1)
      timestamps(type: :utc_datetime_usec)
    end

    create(
      constraint(:host_credential_bindings, :host_credential_namespace,
        check: "namespace IN ('git', 'docker', 'generic')"
      )
    )

    create(
      constraint(:host_credential_bindings, :host_credential_source_kind,
        check: "source_kind IN ('owned', 'reference')"
      )
    )

    create(
      constraint(:host_credential_bindings, :host_credential_state,
        check: "state IN ('active', 'disabled')"
      )
    )

    create(
      constraint(:host_credential_bindings, :host_credential_revision, check: "revision > 0")
    )

    # Owned entries are never disabled; erase removes them.
    create(
      constraint(:host_credential_bindings, :host_credential_owned_active,
        check: "source_kind = 'reference' OR state = 'active'"
      )
    )

    # Disabled references keep occupying their identity, so an ordinary store
    # cannot silently replace or reactivate them.
    create(
      unique_index(
        :host_credential_bindings,
        [:owner_agent_id, :namespace, :service, :authority, :account, :context],
        name: :host_credential_bindings_identity
      )
    )

    create(index(:host_credential_bindings, [:secret_id]))
    create(index(:host_credential_bindings, [:source_secret_id]))

    # Binding changes alter runtime authorization: serialize with other writers.
    execute("""
    CREATE TRIGGER host_credential_bindings_authorization_write_lock
      BEFORE INSERT OR UPDATE OR DELETE ON host_credential_bindings
      FOR EACH STATEMENT EXECUTE FUNCTION secrethub_authorization_write_lock();
    """)
  end

  def down do
    drop(table(:host_credential_bindings))
  end
end
