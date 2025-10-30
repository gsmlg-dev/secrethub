defmodule SecretHub.WebWeb.EngineSetupWizardLive do
  @moduledoc """
  LiveView wizard for setting up new dynamic secret engines.

  Supports:
  - Redis ACL engine configuration
  - AWS STS engine configuration
  - Connection testing
  - Multi-step wizard flow
  """

  use SecretHub.WebWeb, :live_view
  require Logger
  alias SecretHub.Core.EngineConfigurations

  @impl true
  def mount(%{"type" => type}, _session, socket) do
    engine_type = String.to_existing_atom(type)

    if engine_type not in [:redis, :aws] do
      socket = put_flash(socket, :error, "Unsupported engine type: #{type}")
      {:ok, push_navigate(socket, to: ~p"/admin/engines")}
    else
      socket =
        socket
        |> assign(:engine_type, engine_type)
        |> assign(:step, 1)
        |> assign(:form_data, initial_form_data(engine_type))
        |> assign(:testing, false)
        |> assign(:test_result, nil)
        |> assign(:errors, %{})

      {:ok, socket}
    end
  end

  @impl true
  def handle_event("next_step", params, socket) do
    form_data = Map.merge(socket.assigns.form_data, params)

    case validate_step(socket.assigns.engine_type, socket.assigns.step, form_data) do
      {:ok, validated_data} ->
        socket =
          socket
          |> assign(:form_data, validated_data)
          |> assign(:step, socket.assigns.step + 1)
          |> assign(:errors, %{})

        {:noreply, socket}

      {:error, errors} ->
        {:noreply, assign(socket, :errors, errors)}
    end
  end

  @impl true
  def handle_event("prev_step", _params, socket) do
    {:noreply, assign(socket, :step, max(socket.assigns.step - 1, 1))}
  end

  @impl true
  def handle_event("test_connection", _params, socket) do
    send(self(), :perform_connection_test)
    {:noreply, assign(socket, :testing, true)}
  end

  @impl true
  def handle_info(:perform_connection_test, socket) do
    config = build_config(socket.assigns.engine_type, socket.assigns.form_data)

    result =
      case EngineConfigurations.test_connection(socket.assigns.engine_type, config) do
        :ok -> {:success, "Connection successful!"}
        {:error, reason} -> {:error, reason}
      end

    socket =
      socket
      |> assign(:testing, false)
      |> assign(:test_result, result)

    {:noreply, socket}
  end

  @impl true
  def handle_event("save_configuration", _params, socket) do
    config = build_config(socket.assigns.engine_type, socket.assigns.form_data)

    attrs = %{
      name: socket.assigns.form_data["name"],
      engine_type: socket.assigns.engine_type,
      description: socket.assigns.form_data["description"],
      enabled: true,
      config: config
    }

    case EngineConfigurations.create_configuration(attrs) do
      {:ok, _config} ->
        socket =
          socket
          |> put_flash(:info, "Engine configuration created successfully")
          |> push_navigate(to: ~p"/admin/engines")

        {:noreply, socket}

      {:error, changeset} ->
        errors = extract_errors(changeset)
        {:noreply, assign(socket, :errors, errors)}
    end
  end

  # Private helpers

  defp initial_form_data(engine_type) do
    case engine_type do
      :redis ->
        %{
          "name" => "",
          "description" => "",
          "hostname" => "localhost",
          "port" => "6379",
          "password" => "",
          "database" => "0",
          "use_tls" => "false"
        }

      :aws ->
        %{
          "name" => "",
          "description" => "",
          "region" => "us-east-1",
          "role_arn" => "",
          "session_duration" => "3600"
        }
    end
  end

  defp validate_step(_engine_type, 1, form_data) do
    errors = %{}

    errors =
      if String.trim(form_data["name"] || "") == "" do
        Map.put(errors, :name, "Name is required")
      else
        errors
      end

    if map_size(errors) == 0 do
      {:ok, form_data}
    else
      {:error, errors}
    end
  end

  defp validate_step(:redis, 2, form_data) do
    errors = %{}

    errors =
      if String.trim(form_data["hostname"] || "") == "" do
        Map.put(errors, :hostname, "Hostname is required")
      else
        errors
      end

    errors =
      case Integer.parse(form_data["port"] || "") do
        {port, ""} when port > 0 and port < 65536 -> errors
        _ -> Map.put(errors, :port, "Invalid port number")
      end

    if map_size(errors) == 0 do
      {:ok, form_data}
    else
      {:error, errors}
    end
  end

  defp validate_step(:aws, 2, form_data) do
    errors = %{}

    errors =
      if String.trim(form_data["region"] || "") == "" do
        Map.put(errors, :region, "Region is required")
      else
        errors
      end

    errors =
      if String.trim(form_data["role_arn"] || "") == "" do
        Map.put(errors, :role_arn, "Role ARN is required")
      else
        errors
      end

    if map_size(errors) == 0 do
      {:ok, form_data}
    else
      {:error, errors}
    end
  end

  defp validate_step(_engine_type, _step, form_data), do: {:ok, form_data}

  defp build_config(:redis, form_data) do
    %{
      hostname: form_data["hostname"],
      port: String.to_integer(form_data["port"]),
      password: form_data["password"],
      database: String.to_integer(form_data["database"] || "0"),
      use_tls: form_data["use_tls"] == "true"
    }
  end

  defp build_config(:aws, form_data) do
    %{
      region: form_data["region"],
      role_arn: form_data["role_arn"],
      session_duration: String.to_integer(form_data["session_duration"] || "3600")
    }
  end

  defp extract_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6 max-w-4xl">
      <div class="mb-6">
        <h1 class="text-3xl font-bold">
          Setup <%= String.capitalize(to_string(@engine_type)) %> Engine
        </h1>
        <p class="text-gray-600 mt-1">Configure a new dynamic secret engine</p>
      </div>

      <!-- Progress Steps -->
      <div class="mb-8">
        <ul class="steps steps-horizontal w-full">
          <li class={"step #{if @step >= 1, do: "step-primary", else: ""}"}>Basic Info</li>
          <li class={"step #{if @step >= 2, do: "step-primary", else: ""}"}>Connection</li>
          <li class={"step #{if @step >= 3, do: "step-primary", else: ""}"}>Test & Save</li>
        </ul>
      </div>

      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <%= if @step == 1 do %>
            <!-- Step 1: Basic Info -->
            <h2 class="card-title mb-4">Basic Information</h2>

            <form phx-submit="next_step">
              <div class="form-control mb-4">
                <label class="label">
                  <span class="label-text">Engine Name *</span>
                </label>
                <input
                  type="text"
                  name="name"
                  value={@form_data["name"]}
                  placeholder="my-redis-engine"
                  class={"input input-bordered #{if @errors[:name], do: "input-error", else: ""}"}
                  required
                />
                <%= if @errors[:name] do %>
                  <label class="label">
                    <span class="label-text-alt text-error"><%= @errors[:name] %></span>
                  </label>
                <% end %>
              </div>

              <div class="form-control mb-4">
                <label class="label">
                  <span class="label-text">Description</span>
                </label>
                <textarea
                  name="description"
                  value={@form_data["description"]}
                  placeholder="Enter a description for this engine"
                  class="textarea textarea-bordered"
                  rows="3"
                />
              </div>

              <div class="card-actions justify-end">
                <.link navigate={~p"/admin/engines"} class="btn btn-outline">
                  Cancel
                </.link>
                <button type="submit" class="btn btn-primary">
                  Next
                </button>
              </div>
            </form>
          <% end %>

          <%= if @step == 2 and @engine_type == :redis do %>
            <!-- Step 2: Redis Connection -->
            <h2 class="card-title mb-4">Redis Connection Settings</h2>

            <form phx-submit="next_step">
              <div class="grid grid-cols-2 gap-4 mb-4">
                <div class="form-control">
                  <label class="label">
                    <span class="label-text">Hostname *</span>
                  </label>
                  <input
                    type="text"
                    name="hostname"
                    value={@form_data["hostname"]}
                    placeholder="localhost"
                    class={"input input-bordered #{if @errors[:hostname], do: "input-error", else: ""}"}
                    required
                  />
                  <%= if @errors[:hostname] do %>
                    <label class="label">
                      <span class="label-text-alt text-error"><%= @errors[:hostname] %></span>
                    </label>
                  <% end %>
                </div>

                <div class="form-control">
                  <label class="label">
                    <span class="label-text">Port *</span>
                  </label>
                  <input
                    type="number"
                    name="port"
                    value={@form_data["port"]}
                    placeholder="6379"
                    class={"input input-bordered #{if @errors[:port], do: "input-error", else: ""}"}
                    required
                  />
                  <%= if @errors[:port] do %>
                    <label class="label">
                      <span class="label-text-alt text-error"><%= @errors[:port] %></span>
                    </label>
                  <% end %>
                </div>
              </div>

              <div class="form-control mb-4">
                <label class="label">
                  <span class="label-text">Password</span>
                </label>
                <input
                  type="password"
                  name="password"
                  value={@form_data["password"]}
                  placeholder="Optional"
                  class="input input-bordered"
                />
              </div>

              <div class="grid grid-cols-2 gap-4 mb-4">
                <div class="form-control">
                  <label class="label">
                    <span class="label-text">Database</span>
                  </label>
                  <input
                    type="number"
                    name="database"
                    value={@form_data["database"]}
                    placeholder="0"
                    class="input input-bordered"
                  />
                </div>

                <div class="form-control">
                  <label class="label">
                    <span class="label-text">Use TLS</span>
                  </label>
                  <select name="use_tls" class="select select-bordered">
                    <option value="false" selected={@form_data["use_tls"] == "false"}>No</option>
                    <option value="true" selected={@form_data["use_tls"] == "true"}>Yes</option>
                  </select>
                </div>
              </div>

              <div class="card-actions justify-end">
                <button type="button" phx-click="prev_step" class="btn btn-outline">
                  Back
                </button>
                <button type="submit" class="btn btn-primary">
                  Next
                </button>
              </div>
            </form>
          <% end %>

          <%= if @step == 2 and @engine_type == :aws do %>
            <!-- Step 2: AWS Connection -->
            <h2 class="card-title mb-4">AWS STS Configuration</h2>

            <form phx-submit="next_step">
              <div class="form-control mb-4">
                <label class="label">
                  <span class="label-text">AWS Region *</span>
                </label>
                <input
                  type="text"
                  name="region"
                  value={@form_data["region"]}
                  placeholder="us-east-1"
                  class={"input input-bordered #{if @errors[:region], do: "input-error", else: ""}"}
                  required
                />
                <%= if @errors[:region] do %>
                  <label class="label">
                    <span class="label-text-alt text-error"><%= @errors[:region] %></span>
                  </label>
                <% end %>
              </div>

              <div class="form-control mb-4">
                <label class="label">
                  <span class="label-text">Role ARN *</span>
                </label>
                <input
                  type="text"
                  name="role_arn"
                  value={@form_data["role_arn"]}
                  placeholder="arn:aws:iam::123456789012:role/MyRole"
                  class={"input input-bordered #{if @errors[:role_arn], do: "input-error", else: ""}"}
                  required
                />
                <%= if @errors[:role_arn] do %>
                  <label class="label">
                    <span class="label-text-alt text-error"><%= @errors[:role_arn] %></span>
                  </label>
                <% end %>
              </div>

              <div class="form-control mb-4">
                <label class="label">
                  <span class="label-text">Session Duration (seconds)</span>
                </label>
                <input
                  type="number"
                  name="session_duration"
                  value={@form_data["session_duration"]}
                  placeholder="3600"
                  class="input input-bordered"
                />
                <label class="label">
                  <span class="label-text-alt">Default: 3600 seconds (1 hour)</span>
                </label>
              </div>

              <div class="card-actions justify-end">
                <button type="button" phx-click="prev_step" class="btn btn-outline">
                  Back
                </button>
                <button type="submit" class="btn btn-primary">
                  Next
                </button>
              </div>
            </form>
          <% end %>

          <%= if @step == 3 do %>
            <!-- Step 3: Test & Save -->
            <h2 class="card-title mb-4">Test Connection & Save</h2>

            <div class="mb-6">
              <p class="text-sm text-gray-600 mb-4">
                Test the connection to ensure everything is configured correctly before saving.
              </p>

              <%= if @test_result do %>
                <%= case @test_result do %>
                  <% {:success, message} -> %>
                    <div class="alert alert-success">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        class="stroke-current shrink-0 h-6 w-6"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                      <span><%= message %></span>
                    </div>
                  <% {:error, message} -> %>
                    <div class="alert alert-error">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        class="stroke-current shrink-0 h-6 w-6"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                      <span><%= message %></span>
                    </div>
                <% end %>
              <% end %>
            </div>

            <div class="card-actions justify-end">
              <button type="button" phx-click="prev_step" class="btn btn-outline">
                Back
              </button>
              <button
                type="button"
                phx-click="test_connection"
                class="btn btn-secondary"
                disabled={@testing}
              >
                <%= if @testing, do: "Testing...", else: "Test Connection" %>
              </button>
              <button type="button" phx-click="save_configuration" class="btn btn-primary">
                Save Configuration
              </button>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end
end
