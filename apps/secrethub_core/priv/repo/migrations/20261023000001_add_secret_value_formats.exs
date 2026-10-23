defmodule SecretHub.Core.Repo.Migrations.AddSecretValueFormats do
  use Ecto.Migration

  def up do
    alter(table(:secrets), do: add(:value_format, :text))
    alter(table(:secret_versions), do: add(:value_format, :text))

    for table <- [:secrets, :secret_versions] do
      create(
        constraint(table, :"#{table}_value_format",
          check: "value_format IS NULL OR value_format IN ('text', 'structured')"
        )
      )
    end

    execute("DROP TRIGGER managed_material_update ON secrets")

    execute(
      "CREATE TRIGGER managed_material_update BEFORE UPDATE OF encrypted_data,value_format,version,secret_path,engine_type,secret_type,rotation_enabled ON secrets FOR EACH ROW EXECUTE FUNCTION secrethub_managed_material_guard()"
    )
  end

  def down do
    execute("DROP TRIGGER managed_material_update ON secrets")

    execute(
      "CREATE TRIGGER managed_material_update BEFORE UPDATE OF encrypted_data,version,secret_path,engine_type,secret_type,rotation_enabled ON secrets FOR EACH ROW EXECUTE FUNCTION secrethub_managed_material_guard()"
    )

    drop(constraint(:secrets, :secrets_value_format))
    drop(constraint(:secret_versions, :secret_versions_value_format))
    alter(table(:secret_versions), do: remove(:value_format))
    alter(table(:secrets), do: remove(:value_format))
  end
end
