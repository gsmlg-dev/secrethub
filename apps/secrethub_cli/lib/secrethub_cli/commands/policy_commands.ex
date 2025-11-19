defmodule SecretHub.CLI.Commands.PolicyCommands do
  @moduledoc """
  Policy management command implementations.
  """

  alias SecretHub.CLI.{Auth, Config, Output}

  @doc """
  Executes policy commands.
  """
  # execute/3 clauses (grouped together)
  def execute(:list, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, policies} <- list_policies(opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(policies, format: format)
    end
  end

  def execute(:create, _args, opts) do
    template = Keyword.get(opts, :from_template)
    name = Keyword.get(opts, :name)

    cond do
      is_nil(template) && is_nil(name) ->
        {:error, "Missing required option: --from-template or --name"}

      template ->
        create_from_template(template, opts)

      true ->
        {:error, "Interactive policy creation not yet implemented. Use --from-template"}
    end
  end

  def execute(:templates, _args, opts) do
    with {:ok, templates} <- list_templates(opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(templates, format: format)
    end
  end

  # execute/4 clauses (grouped together)
  def execute(:get, name, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, policy} <- get_policy(name, opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(policy, format: format)
    end
  end

  def execute(:update, name, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, _policy} <- update_policy(name, opts) do
      Output.success("Policy updated: #{name}")
      {:ok, "Policy updated"}
    end
  end

  def execute(:delete, name, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         :ok <- delete_policy(name, opts) do
      Output.success("Policy deleted: #{name}")
      {:ok, "Policy deleted"}
    end
  end

  def execute(:simulate, name, _args, opts) do
    with {:ok, _token} <- Auth.ensure_authenticated(),
         {:ok, simulation} <- simulate_policy(name, opts) do
      format = Keyword.get(opts, :format, Config.get_output_format())
      Output.format(simulation, format: format)
    end
  end

  ## Private API Functions

  defp list_policies(_opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/policies"
    headers = Auth.auth_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        policies = Map.get(body, "data", [])
        {:ok, policies}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp get_policy(name, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/policies/#{URI.encode(name)}"
    headers = Auth.auth_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Map.get(body, "data", %{})}

      {:ok, %{status: 404}} ->
        {:error, "Policy not found: #{name}"}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp create_from_template(template_name, opts) do
    name = Keyword.get(opts, :name)

    if is_nil(name) do
      {:error, "Missing required option: --name"}
    else
      server = Config.get_server_url()
      url = "#{server}/v1/policies"
      headers = Auth.auth_headers() ++ [{"content-type", "application/json"}]

      body =
        Jason.encode!(%{
          template: template_name,
          name: name
        })

      case Req.post(url, body: body, headers: headers) do
        {:ok, %{status: 201, body: body}} ->
          Output.success("Policy created from template: #{name}")
          {:ok, Map.get(body, "data", %{})}

        {:ok, %{status: status, body: body}} ->
          {:error, "API error #{status}: #{inspect(body)}"}

        {:error, reason} ->
          {:error, "HTTP request failed: #{inspect(reason)}"}
      end
    end
  end

  defp update_policy(_name, _opts) do
    {:error, "Policy update not yet implemented"}
  end

  defp delete_policy(name, _opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/policies/#{URI.encode(name)}"
    headers = Auth.auth_headers()

    case Req.delete(url, headers: headers) do
      {:ok, %{status: 204}} ->
        :ok

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp simulate_policy(name, opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/policies/#{URI.encode(name)}/simulate"
    headers = Auth.auth_headers() ++ [{"content-type", "application/json"}]

    # Extract simulation context from opts
    context = build_simulation_context(opts)
    body = Jason.encode!(context)

    case Req.post(url, body: body, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Map.get(body, "data", %{})}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp list_templates(_opts) do
    server = Config.get_server_url()
    url = "#{server}/v1/policies/templates"
    headers = Auth.auth_headers()

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        templates = Map.get(body, "data", [])
        {:ok, templates}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp build_simulation_context(opts) do
    %{
      entity_id: Keyword.get(opts, :entity_id, "test-entity"),
      secret_path: Keyword.get(opts, :secret_path, "test.secret"),
      operation: Keyword.get(opts, :operation, "read"),
      ip_address: Keyword.get(opts, :ip_address),
      timestamp: Keyword.get(opts, :timestamp)
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end
end
