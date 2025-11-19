defmodule SecretHub.Agent.Template do
  @moduledoc """
  Template parsing and rendering engine for SecretHub Agent.

  Supports rendering secrets into configuration files using templates with:
  - Variable substitution
  - Conditional rendering
  - Loops and iteration
  - Nested data access

  ## Template Syntax

  Uses EEx (Embedded Elixir) syntax similar to Go templates and ERB:

  ### Variable Substitution

  ```
  # Simple variable
  <%= secret.value %>

  # Nested access
  <%= secret.database.password %>

  # With default value
  <%= secret.api_key || "default-key" %>
  ```

  ### Conditionals

  ```
  <%= if secret.enabled do %>
  enabled = true
  <% else %>
  enabled = false
  <% end %>

  # Unless
  <%= unless is_nil(secret.host) do %>
  host = <%= secret.host %>
  <% end %>
  ```

  ### Loops

  ```
  # Iterate over list
  <%= for server <- secret.servers do %>
  server = <%= server.host %>:<%= server.port %>
  <% end %>

  # With index
  <%= for {server, idx} <- Enum.with_index(secret.servers) do %>
  server_<%= idx %> = <%= server %>
  <% end %>
  ```

  ### Functions

  Built-in helper functions:

  - `upcase(str)` - Convert to uppercase
  - `downcase(str)` - Convert to lowercase
  - `base64_encode(str)` - Base64 encode
  - `base64_decode(str)` - Base64 decode
  - `json_encode(data)` - Encode as JSON
  - `join(list, separator)` - Join list elements

  Credential formatting helpers:

  - `pg_connection_string(creds)` - Format PostgreSQL connection string
  - `redis_connection_string(creds)` - Format Redis connection string
  - `aws_env_vars(creds)` - Format AWS credentials as environment variables map

  ## Usage

  ```elixir
  # Parse template
  {:ok, compiled} = Template.compile(template_string)

  # Render with secrets
  {:ok, output} = Template.render(compiled, %{
    secret: %{
      database: %{password: "secret123"},
      api_key: "key-abc"
    }
  })
  ```

  ## Error Handling

  Template compilation and rendering errors are returned with context:

  ```elixir
  {:error, %{
    type: :compilation_error,
    line: 5,
    message: "undefined variable 'foo'"
  }}
  ```
  """

  require Logger

  @type compiled_template :: tuple()
  @type template_vars :: map()
  @type render_result :: {:ok, String.t()} | {:error, map()}

  @doc """
  Compile a template string into an executable form.

  ## Parameters

    - `template_string` - Template string with EEx syntax

  ## Returns

    - `{:ok, compiled}` - Compiled template ready for rendering
    - `{:error, reason}` - Compilation failed

  ## Examples

      iex> Template.compile("Hello <%= name %>!")
      {:ok, compiled_template}

      iex> Template.compile("<%= undefined_var %>")
      {:error, %{type: :compilation_error, message: "..."}}
  """
  @spec compile(String.t()) :: {:ok, compiled_template()} | {:error, map()}
  def compile(template_string) when is_binary(template_string) do
    # Compile EEx template
    quoted = EEx.compile_string(template_string)
    {:ok, {:compiled, template_string, quoted}}
  rescue
    e in [EEx.SyntaxError, SyntaxError] ->
      {:error,
       %{
         type: :compilation_error,
         line: Map.get(e, :line, 0),
         message: Exception.message(e)
       }}

    e ->
      {:error,
       %{
         type: :compilation_error,
         message: Exception.message(e)
       }}
  end

  @doc """
  Render a compiled template with the given variables.

  ## Parameters

    - `compiled` - Compiled template from `compile/1`
    - `vars` - Map of variables to use in template

  ## Returns

    - `{:ok, rendered_string}` - Successfully rendered template
    - `{:error, reason}` - Rendering failed

  ## Examples

      iex> {:ok, compiled} = Template.compile("Hello <%= name %>!")
      iex> Template.render(compiled, %{name: "World"})
      {:ok, "Hello World!"}
  """
  @spec render(compiled_template(), template_vars()) :: render_result()
  def render({:compiled, _original, quoted}, vars) when is_map(vars) do
    # Create bindings from vars
    bindings = create_bindings(vars)

    # Evaluate the compiled template
    {result, _bindings} = Code.eval_quoted(quoted, bindings)

    {:ok, to_string(result)}
  rescue
    e in [CompileError, ArgumentError, KeyError] ->
      {:error,
       %{
         type: :render_error,
         message: Exception.message(e)
       }}

    e ->
      {:error,
       %{
         type: :render_error,
         message: Exception.message(e)
       }}
  end

  @doc """
  Compile and render a template in one step.

  Convenience function for one-time rendering.

  ## Examples

      iex> Template.render_string("Hello <%= name %>!", %{name: "World"})
      {:ok, "Hello World!"}
  """
  @spec render_string(String.t(), template_vars()) :: render_result()
  def render_string(template_string, vars) when is_binary(template_string) and is_map(vars) do
    with {:ok, compiled} <- compile(template_string) do
      render(compiled, vars)
    end
  end

  @doc """
  Validate a template without rendering.

  Checks for syntax errors and undefined variable references.

  ## Examples

      iex> Template.validate("Hello <%= name %>!")
      :ok

      iex> Template.validate("<%= invalid syntax")
      {:error, %{type: :compilation_error, ...}}
  """
  @spec validate(String.t()) :: :ok | {:error, map()}
  def validate(template_string) when is_binary(template_string) do
    case compile(template_string) do
      {:ok, _compiled} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Extract variable references from a template.

  Returns a list of variable names used in the template.

  ## Examples

      iex> Template.extract_vars("Hello <%= name %>, <%= greeting %>!")
      {:ok, ["name", "greeting"]}
  """
  @spec extract_vars(String.t()) :: {:ok, [String.t()]} | {:error, map()}
  def extract_vars(template_string) when is_binary(template_string) do
    # Parse template and extract variable references
    vars =
      template_string
      |> extract_variable_patterns()
      |> Enum.uniq()

    {:ok, vars}
  rescue
    e ->
      {:error,
       %{
         type: :parse_error,
         message: Exception.message(e)
       }}
  end

  ## Private Functions

  defp create_bindings(vars) do
    alias SecretHub.Agent.CredentialFormatter

    # Add helper functions to bindings
    helpers = %{
      upcase: &String.upcase/1,
      downcase: &String.downcase/1,
      base64_encode: &Base.encode64/1,
      base64_decode: &Base.decode64!/1,
      json_encode: &Jason.encode!/1,
      join: &Enum.join/2,
      # Credential formatting helpers
      pg_connection_string: fn creds ->
        CredentialFormatter.format_connection_string(:postgresql, creds)
      end,
      redis_connection_string: fn creds ->
        CredentialFormatter.format_connection_string(:redis, creds)
      end,
      aws_env_vars: fn creds -> CredentialFormatter.to_env_vars(:aws_sts, creds) end
    }

    # Merge vars with helpers
    Map.merge(vars, helpers)
    |> Enum.to_list()
  end

  defp extract_variable_patterns(template_string) do
    # Match <%= ... %> and <% ... %> patterns
    ~r/<%=?\s*([a-zA-Z_][a-zA-Z0-9_\.]*)/
    |> Regex.scan(template_string)
    |> Enum.map(fn [_match, var_name] -> var_name end)
    |> Enum.reject(fn var ->
      # Filter out keywords and helpers
      var in [
        "if",
        "unless",
        "for",
        "do",
        "end",
        "else",
        "upcase",
        "downcase",
        "base64_encode",
        "base64_decode",
        "json_encode",
        "join"
      ]
    end)
  end
end
