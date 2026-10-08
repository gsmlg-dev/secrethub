defmodule SecretHub.Human.Health do
  alias SecretHub.Human.Repo

  @moduledoc "Independent Human readiness without credentials or database configuration in responses."
  def checks do
    %{
      repo: repo_ready?(),
      core: match?({:ok, _}, SecretHub.Access.human_health()),
      reveal_store: is_pid(Process.whereis(SecretHub.Human.RevealStore)),
      notifications: is_pid(Process.whereis(SecretHub.Human.PubSub))
    }
  end

  defp repo_ready? do
    match?({:ok, _}, Repo.query("SELECT 1", [], log: false, timeout: 1000))
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end
end
