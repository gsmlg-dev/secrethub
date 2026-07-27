defmodule Mix.Tasks.Secrethub.Upgrade.Verify do
  @moduledoc """
  Runs and records a registered SecretHub upgrade preflight.

      mix secrethub.upgrade.verify app_certificate_v2 --actor operator@example.com

  Preflight modules are registered under
  `:secrethub_core, :upgrade_gate_preflights`. A missing registration fails
  closed. Only public finding identifiers and kinds are printed.
  """

  use Mix.Task

  alias SecretHub.Core.UpgradeGates

  @shortdoc "Verify and persist a zero-finding upgrade gate"
  @requirements ["app.start"]

  @impl Mix.Task
  def run(args) do
    {opts, positional, invalid} =
      OptionParser.parse(args,
        strict: [actor: :string],
        aliases: [a: :actor]
      )

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    gate = parse_gate!(positional)
    actor_id = Keyword.get(opts, :actor) || System.get_env("SECRET_HUB_UPGRADE_VERIFIED_BY")
    preflight = registered_preflight!(gate)
    initial_report = run_preflight!(preflight, gate)

    handle_initial_report(initial_report, preflight, gate, actor_id)
  end

  defp handle_initial_report(initial_report, preflight, gate, actor_id) do
    case report_findings(initial_report) do
      findings when is_list(findings) and findings != [] ->
        print_findings(findings)

        Mix.raise(
          "upgrade gate #{gate} preflight reported #{length(findings)} unresolved " <>
            finding_word(findings)
        )

      _zero_or_invalid ->
        persist_zero_report(preflight, gate, actor_id)
    end
  end

  defp persist_zero_report(preflight, gate, actor_id) do
    case UpgradeGates.verify(
           gate,
           fn -> run_preflight!(preflight, gate) end,
           actor_id: actor_id
         ) do
      {:ok, persisted_gate} ->
        Mix.shell().info(
          "verified #{gate} generation=#{persisted_gate.verification_generation} " <>
            "report_hash=#{persisted_gate.report_hash}"
        )

        :ok

      {:error, :nonzero_findings} ->
        Mix.raise("upgrade gate #{gate} preflight changed and now has unresolved findings")

      {:error, reason} ->
        Mix.raise("could not verify upgrade gate #{gate}: #{inspect(reason)}")
    end
  end

  defp parse_gate!([gate]) do
    if gate in UpgradeGates.gates() do
      gate
    else
      Mix.raise(
        "unknown upgrade gate #{inspect(gate)}; expected one of " <>
          Enum.join(UpgradeGates.gates(), ", ")
      )
    end
  end

  defp parse_gate!(_args) do
    Mix.raise("usage: mix secrethub.upgrade.verify <gate> --actor <public-operator-id>")
  end

  defp registered_preflight!(gate) do
    preflights = Application.get_env(:secrethub_core, :upgrade_gate_preflights, %{})

    case Map.get(preflights, gate) || safe_existing_atom_lookup(preflights, gate) do
      nil ->
        Mix.raise("no preflight is registered for upgrade gate #{gate}")

      module when is_atom(module) ->
        module

      other ->
        Mix.raise("invalid preflight registration for #{gate}: #{inspect(other)}")
    end
  end

  defp run_preflight!(module, gate) do
    cond do
      function_exported?(module, :report, 1) ->
        module.report(gate)

      function_exported?(module, :report, 0) ->
        module.report()

      true ->
        Mix.raise(
          "registered preflight #{inspect(module)} does not implement report/1 or report/0"
        )
    end
  end

  defp report_findings(report) when is_map(report) do
    Map.get(report, "findings") || Map.get(report, :findings)
  end

  defp report_findings(_report), do: nil

  defp print_findings(findings) do
    sanitized =
      Enum.map(findings, fn
        finding when is_map(finding) ->
          %{
            "identifier" =>
              Map.get(finding, "identifier") || Map.get(finding, :identifier) || "unidentified",
            "kind" => Map.get(finding, "kind") || Map.get(finding, :kind) || "unclassified"
          }

        _finding ->
          %{"identifier" => "unidentified", "kind" => "invalid_finding"}
      end)

    Mix.shell().info(
      Jason.encode!(%{
        "finding_count" => length(findings),
        "findings" => sanitized
      })
    )
  end

  defp safe_existing_atom_lookup(map, key) do
    Map.get(map, String.to_existing_atom(key))
  rescue
    ArgumentError -> nil
  end

  defp finding_word([_finding]), do: "finding"
  defp finding_word(_findings), do: "findings"
end
