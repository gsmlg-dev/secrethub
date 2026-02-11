defmodule SecretHub.Agent.TemplateRenderer do
  @moduledoc """
  Template rendering engine with variable substitution from cached secrets.

  Provides high-level template rendering workflow that:
  1. Maps template variables to secret paths
  2. Fetches secrets from cache
  3. Renders templates with variable substitution
  4. Handles missing/expired secrets gracefully

  ## Configuration

  Templates reference secrets using variable bindings. Each variable can be:
  - A direct secret path: `secret_path: "prod.db.password"`
  - A nested secret with path extraction: `secret_path: "prod.db"`, use `<%= secret.password %>`

  ## Usage

  ```elixir
  # Define variable bindings (variable name -> secret path)
  bindings = %{
    "database" => "prod.db.password",
    "api_key" => "prod.api.key"
  }

  # Render template with secrets
  case TemplateRenderer.render("DB_PASS=<%= database %>", bindings) do
    {:ok, rendered} ->
      {:ok, rendered}  # "DB_PASS=mysecretpassword"

    {:error, reason} ->
      {:error, reason}  # Error with context
  end
  ```

  ## Error Handling

  Returns detailed error information:

  ```elixir
  {:error, %{
    type: :missing_secret,
    variable: "database",
    secret_path: "prod.db.password",
    message: "Secret not found in cache"
  }}
  ```

  Supported error types:
  - `:missing_secret` - Secret not found in cache
  - `:expired_secret` - Secret expired and fallback disabled
  - `:compilation_error` - Template syntax error
  - `:render_error` - Template rendering error
  - `:internal_error` - Other errors
  """

  require Logger

  alias SecretHub.Agent.{Cache, Template}

  @type template_string :: String.t()
  @type secret_path :: String.t()
  @type variable_bindings :: %{String.t() => secret_path()}
  @type render_result :: {:ok, String.t()} | {:error, map()}

  @doc """
  Render a template with variable substitution from cached secrets.

  ## Parameters

    - `template_string` - Template with EEx syntax (e.g., "DB=<%= db_password %>")
    - `bindings` - Map of variable names to secret paths
    - `opts` - Options (e.g., use_fallback, allow_missing)

  ## Options

    - `:use_fallback` - Use stale cache if available (default: false)
    - `:allow_missing` - Allow missing secrets with empty values (default: false)

  ## Returns

    - `{:ok, rendered}` - Successfully rendered template
    - `{:error, reason}` - Rendering failed with error context

  ## Examples

      iex> bindings = %{"password" => "prod.db.password"}
      iex> TemplateRenderer.render("PASS=<%= password %>", bindings)
      {:ok, "PASS=mysecret"}

      iex> TemplateRenderer.render("MISSING=<%= unknown %>", %{})
      {:error, %{type: :render_error, ...}}
  """
  @spec render(template_string(), variable_bindings(), keyword()) :: render_result()
  def render(template_string, bindings, opts \\ [])
      when is_binary(template_string) and is_map(bindings) do
    use_fallback = Keyword.get(opts, :use_fallback, false)
    allow_missing = Keyword.get(opts, :allow_missing, false)

    with :ok <- validate_template(template_string),
         {:ok, variables} <- fetch_variables(bindings, use_fallback, allow_missing) do
      Template.render_string(template_string, variables)
    else
      {:error, reason} -> {:error, reason}
    end
  rescue
    e ->
      Logger.error("Template rendering failed with exception",
        error: inspect(e),
        template_excerpt: String.slice(template_string, 0, 100)
      )

      {:error,
       %{
         type: :internal_error,
         message: Exception.message(e)
       }}
  end

  @doc """
  Render a template, failing early if any secret is missing.

  More strict than `render/3` - will fail immediately on any missing secret.

  ## Parameters

    - `template_string` - Template with EEx syntax
    - `bindings` - Map of variable names to secret paths

  ## Returns

    - `{:ok, rendered}` - Successfully rendered template
    - `{:error, reason}` - First missing secret or rendering error
  """
  @spec render_strict(template_string(), variable_bindings()) :: render_result()
  def render_strict(template_string, bindings) do
    render(template_string, bindings, allow_missing: false)
  end

  @doc """
  Render a template, using fallback secrets if available.

  Gracefully handles expired secrets by using stale cache data if available.

  ## Parameters

    - `template_string` - Template with EEx syntax
    - `bindings` - Map of variable names to secret paths

  ## Returns

    - `{:ok, rendered}` - Successfully rendered template (may use stale data)
    - `{:error, reason}` - Rendering failed
  """
  @spec render_with_fallback(template_string(), variable_bindings()) :: render_result()
  def render_with_fallback(template_string, bindings) do
    render(template_string, bindings, use_fallback: true)
  end

  @doc """
  Validate a template and extract variable references.

  Checks template syntax without requiring variables to be available.

  ## Parameters

    - `template_string` - Template with EEx syntax

  ## Returns

    - `{:ok, variables}` - List of variable names referenced in template
    - `{:error, reason}` - Template syntax error
  """
  @spec extract_variables(template_string()) :: {:ok, [String.t()]} | {:error, map()}
  def extract_variables(template_string) when is_binary(template_string) do
    Template.extract_vars(template_string)
  end

  @doc """
  Validate that all required secrets are available.

  Useful for pre-flight checks before rendering.

  ## Parameters

    - `bindings` - Map of variable names to secret paths
    - `opts` - Options (use_fallback, etc.)

  ## Returns

    - `:ok` - All secrets are available
    - `{:error, reason}` - One or more secrets missing
  """
  @spec validate_secrets(variable_bindings(), keyword()) :: :ok | {:error, map()}
  def validate_secrets(bindings, opts \\ []) when is_map(bindings) do
    use_fallback = Keyword.get(opts, :use_fallback, false)

    bindings
    |> Enum.reduce_while(:ok, fn {var_name, secret_path}, _acc ->
      case fetch_secret(secret_path, use_fallback) do
        {:ok, _data} ->
          {:cont, :ok}

        {:error, reason} ->
          {:halt,
           {:error,
            %{
              type: :missing_secret,
              variable: var_name,
              secret_path: secret_path,
              message: format_error_message(reason)
            }}}
      end
    end)
  end

  ## Private Functions

  defp validate_template(template_string) do
    case Template.validate(template_string) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_variables(bindings, use_fallback, allow_missing) do
    result =
      bindings
      |> Enum.reduce_while({:ok, %{}}, fn {var_name, secret_path}, {:ok, variables} ->
        case fetch_secret(secret_path, use_fallback) do
          {:ok, data} ->
            # Store the secret data with the variable name as key
            {:cont, {:ok, Map.put(variables, var_name, data)}}

          {:error, reason} ->
            if allow_missing do
              Logger.warning("Secret missing, using empty value",
                variable: var_name,
                secret_path: secret_path
              )

              {:cont, {:ok, Map.put(variables, var_name, "")}}
            else
              {:halt,
               {:error,
                %{
                  type: :missing_secret,
                  variable: var_name,
                  secret_path: secret_path,
                  message: format_error_message(reason)
                }}}
            end
        end
      end)

    result
  end

  defp fetch_secret(secret_path, use_fallback) do
    if use_fallback do
      Cache.get_with_fallback(secret_path)
    else
      case Cache.get(secret_path) do
        {:ok, data} ->
          {:ok, data}

        {:error, :expired} ->
          {:error, :expired}

        {:error, :not_found} ->
          {:error, :not_found}
      end
    end
  rescue
    e ->
      Logger.error("Error fetching secret from cache",
        secret_path: secret_path,
        error: inspect(e)
      )

      {:error, :internal_error}
  end

  defp format_error_message(reason) when is_atom(reason) do
    case reason do
      :not_found -> "Secret not found in cache"
      :expired -> "Secret expired in cache"
      :internal_error -> "Failed to fetch secret from cache"
      other -> "Secret fetch error: #{inspect(other)}"
    end
  end

  defp format_error_message(reason), do: inspect(reason)
end
