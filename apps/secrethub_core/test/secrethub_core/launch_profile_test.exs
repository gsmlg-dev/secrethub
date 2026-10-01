defmodule SecretHub.Core.LaunchProfileTest do
  use ExUnit.Case, async: false

  alias SecretHub.Core.Engines.Dynamic.{AWSSTS, PostgreSQL, Redis}
  alias SecretHub.Shared.LaunchProfile

  setup do
    previous_profile = Application.get_env(:secrethub_core, :launch_profile)
    previous_features = Application.get_env(:secrethub_core, :enabled_features)
    Application.put_env(:secrethub_core, :launch_profile, :single_operator)
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets, :client_auth_pki])

    on_exit(fn ->
      Application.put_env(:secrethub_core, :launch_profile, previous_profile)
      Application.put_env(:secrethub_core, :enabled_features, previous_features)
    end)

    :ok
  end

  test "single-operator launch enables only its supported feature set" do
    assert LaunchProfile.enabled?(:static_secrets)
    assert LaunchProfile.enabled?(:client_auth_pki)
    refute LaunchProfile.enabled?(:dynamic_secrets)
    refute LaunchProfile.enabled?(:rotation)
  end

  test "invalid launch feature configuration fails closed without crashing callers" do
    Application.put_env(:secrethub_core, :enabled_features, nil)
    refute LaunchProfile.enabled?(:dynamic_secrets)
    assert {:error, :feature_unavailable} = LaunchProfile.check(:dynamic_secrets)
  end

  test "development keeps the existing features available" do
    Application.put_env(:secrethub_core, :launch_profile, :development)
    assert LaunchProfile.enabled?(:dynamic_secrets)
    assert LaunchProfile.enabled?(:rotation)
  end

  test "direct dynamic engine issuance is unavailable before parsing connection configuration" do
    for engine <- [PostgreSQL, Redis, AWSSTS] do
      assert {:error, :feature_unavailable} = engine.generate_credentials("blocked", [])
      assert {:error, :feature_unavailable} = engine.renew_lease("blocked", [])
    end
  end

  test "lease mutations cannot bypass the launch gate when no process exists" do
    assert {:error, :feature_unavailable} = SecretHub.Core.LeaseManager.create_lease(%{})
    assert {:error, :feature_unavailable} = SecretHub.Core.LeaseManager.renew_lease("blocked")
    assert {:error, :feature_unavailable} = SecretHub.Core.LeaseManager.revoke_lease("blocked")
  end

  test "rotation execution and scheduling are blocked before loading data or enqueueing jobs" do
    rotator = %SecretHub.Shared.Schemas.SecretRotator{id: Ecto.UUID.generate()}

    assert {:error, :feature_unavailable} =
             SecretHub.Core.RotationManager.perform_rotation(rotator)

    assert {:error, :feature_unavailable} =
             SecretHub.Core.Workers.RotationWorker.schedule_rotation(rotator)

    assert {:discard, :feature_unavailable} =
             SecretHub.Core.Workers.RotationWorker.perform(%Oban.Job{
               args: %{"rotator_id" => rotator.id}
             })
  end

  test "Core supervision excludes dynamic lease work but retains required PKI refresh" do
    previous_env = Application.get_env(:secrethub_core, :env)
    Application.put_env(:secrethub_core, :env, :prod)

    try do
      children = SecretHub.Core.Application.children()
      refute SecretHub.Core.LeaseManager in children
      assert SecretHub.Core.Workers.ClientAuthCRLRefresher in children
    after
      Application.put_env(:secrethub_core, :env, previous_env)
    end
  end
end
