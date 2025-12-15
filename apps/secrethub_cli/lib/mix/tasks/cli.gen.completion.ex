defmodule Mix.Tasks.Cli.Gen.Completion do
  @moduledoc """
  Generate shell completion scripts for SecretHub CLI.

  ## Usage

      mix cli.gen.completion bash
      mix cli.gen.completion zsh
      mix cli.gen.completion all

  This task generates completion scripts and saves them to the `priv/completion/` directory.

  ## Examples

      # Generate Bash completion
      mix cli.gen.completion bash

      # Generate Zsh completion
      mix cli.gen.completion zsh

      # Generate both
      mix cli.gen.completion all

  After generating, you can install the completions by following the instructions
  displayed after the task completes.
  """

  use Mix.Task

  alias SecretHub.CLI.Completion

  @shortdoc "Generate shell completion scripts"

  @impl Mix.Task
  def run([]), do: run(["all"])

  def run(["bash"]) do
    generate_completion(:bash)
  end

  def run(["zsh"]) do
    generate_completion(:zsh)
  end

  def run(["all"]) do
    generate_completion(:bash)
    generate_completion(:zsh)
  end

  def run(_) do
    Mix.shell().error("""
    Invalid argument. Usage:

        mix cli.gen.completion bash
        mix cli.gen.completion zsh
        mix cli.gen.completion all
    """)
  end

  defp generate_completion(shell) do
    output_dir = Path.join(["apps", "secrethub_cli", "priv", "completion"])
    File.mkdir_p!(output_dir)

    filename = if shell == :bash, do: "secrethub.bash", else: "_secrethub"
    output_path = Path.join(output_dir, filename)

    case Completion.generate(shell) do
      {:ok, script} ->
        File.write!(output_path, script)

        Mix.shell().info([
          :green,
          "* ",
          :reset,
          "Generated #{shell} completion: ",
          :bright,
          output_path
        ])

        Mix.shell().info("\n" <> Completion.installation_instructions(shell))

      {:error, reason} ->
        Mix.shell().error("Failed to generate #{shell} completion: #{reason}")
    end
  end
end
