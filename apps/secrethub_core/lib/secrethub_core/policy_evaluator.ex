defmodule SecretHub.Core.PolicyEvaluator do
  @moduledoc """
  Advanced policy evaluation engine with support for:
  - Time-based restrictions (time of day, day of week, date ranges)
  - IP-based restrictions (IP ranges, CIDR blocks)
  - Request quota limits
  - TTL restrictions
  - Policy simulation and testing
  """

  require Logger
  import Bitwise

  alias SecretHub.Shared.Schemas.Policy

  @doc """
  Evaluates if a policy allows access given a context.

  ## Context

  - `:entity_id` - ID of the entity requesting access
  - `:secret_path` - Path of the secret being accessed
  - `:operation` - Operation type (read, write, renew, etc.)
  - `:ip_address` - IP address of the requester
  - `:timestamp` - When the request was made (defaults to now)
  - `:requested_ttl` - TTL being requested for dynamic secrets

  ## Returns

  - `{:allow, reason}` - Access allowed with reason
  - `{:deny, reason}` - Access denied with reason
  """
  def evaluate(policy, context) do
    with {:ok, _} <- check_entity_binding(policy, context),
         {:ok, _} <- check_secret_path(policy, context),
         {:ok, _} <- check_operation(policy, context),
         {:ok, _} <- check_time_restrictions(policy, context),
         {:ok, _} <- check_ip_restrictions(policy, context),
         {:ok, _} <- check_ttl_restrictions(policy, context) do
      if policy.deny_policy do
        {:deny, "Explicit deny policy"}
      else
        {:allow, "All conditions satisfied"}
      end
    else
      {:error, reason} -> {:deny, reason}
    end
  end

  @doc """
  Simulates policy evaluation with detailed step-by-step results.

  Returns a map with:
  - `:result` - :allow or :deny
  - `:reason` - Overall reason
  - `:steps` - List of evaluation steps with results
  """
  def simulate(policy, context) do
    steps = [
      {"Entity Binding", check_entity_binding(policy, context)},
      {"Secret Path Match", check_secret_path(policy, context)},
      {"Operation Allowed", check_operation(policy, context)},
      {"Time Restrictions", check_time_restrictions(policy, context)},
      {"IP Restrictions", check_ip_restrictions(policy, context)},
      {"TTL Restrictions", check_ttl_restrictions(policy, context)}
    ]

    final_result =
      if Enum.all?(steps, fn {_name, result} -> match?({:ok, _}, result) end) do
        if policy.deny_policy, do: :deny, else: :allow
      else
        :deny
      end

    failed_step =
      Enum.find(steps, fn {_name, result} -> match?({:error, _}, result) end)

    reason =
      case {final_result, failed_step} do
        {:deny, {name, {:error, msg}}} -> "Failed: #{name} - #{msg}"
        {:deny, nil} -> "Explicit deny policy"
        {:allow, _} -> "All conditions satisfied"
      end

    %{
      result: final_result,
      reason: reason,
      steps: format_simulation_steps(steps),
      policy_name: policy.name,
      evaluated_at: DateTime.utc_now()
    }
  end

  ## Check Functions

  defp check_entity_binding(policy, context) do
    entity_id = Map.get(context, :entity_id)

    cond do
      policy.entity_bindings == [] ->
        {:ok, "No entity bindings (applies to all)"}

      entity_id in policy.entity_bindings ->
        {:ok, "Entity #{entity_id} is bound to policy"}

      true ->
        {:error, "Entity #{entity_id} not bound to this policy"}
    end
  end

  defp check_secret_path(policy, context) do
    secret_path = Map.get(context, :secret_path)
    allowed_secrets = get_in(policy.policy_document, ["allowed_secrets"]) || []

    if Enum.any?(allowed_secrets, &path_matches?(secret_path, &1)) do
      {:ok, "Secret path matches allowed patterns"}
    else
      {:error, "Secret path #{secret_path} not allowed by policy"}
    end
  end

  defp check_operation(policy, context) do
    operation = Map.get(context, :operation)
    allowed_operations = get_in(policy.policy_document, ["allowed_operations"]) || ["read"]

    operation_str = to_string(operation)

    if operation_str in allowed_operations do
      {:ok, "Operation #{operation} is allowed"}
    else
      {:error, "Operation #{operation} not allowed. Allowed: #{inspect(allowed_operations)}"}
    end
  end

  defp check_time_restrictions(policy, context) do
    conditions = get_in(policy.policy_document, ["conditions"]) || %{}
    timestamp = Map.get(context, :timestamp, DateTime.utc_now())

    cond do
      # Check time of day restriction
      time_range = Map.get(conditions, "time_of_day") ->
        check_time_of_day(timestamp, time_range)

      # Check day of week restriction
      allowed_days = Map.get(conditions, "days_of_week") ->
        check_day_of_week(timestamp, allowed_days)

      # Check date range restriction
      date_range = Map.get(conditions, "date_range") ->
        check_date_range(timestamp, date_range)

      true ->
        {:ok, "No time restrictions"}
    end
  end

  defp check_ip_restrictions(policy, context) do
    conditions = get_in(policy.policy_document, ["conditions"]) || %{}
    ip_address = Map.get(context, :ip_address)

    case Map.get(conditions, "ip_ranges") do
      nil ->
        {:ok, "No IP restrictions"}

      ip_ranges when is_list(ip_ranges) ->
        if ip_address && ip_in_ranges?(ip_address, ip_ranges) do
          {:ok, "IP #{ip_address} is in allowed ranges"}
        else
          {:error, "IP #{ip_address || "unknown"} not in allowed ranges: #{inspect(ip_ranges)}"}
        end

      _ ->
        {:ok, "Invalid IP ranges configuration"}
    end
  end

  defp check_ttl_restrictions(policy, context) do
    requested_ttl = Map.get(context, :requested_ttl)

    max_ttl =
      policy.max_ttl_seconds || get_in(policy.policy_document, ["conditions", "max_ttl_seconds"])

    cond do
      is_nil(requested_ttl) ->
        {:ok, "No TTL requested"}

      is_nil(max_ttl) ->
        {:ok, "No TTL restrictions"}

      requested_ttl <= max_ttl ->
        {:ok, "Requested TTL #{requested_ttl}s within limit #{max_ttl}s"}

      true ->
        {:error, "Requested TTL #{requested_ttl}s exceeds maximum #{max_ttl}s"}
    end
  end

  ## Helper Functions

  defp path_matches?(secret_path, pattern) do
    # Convert glob pattern to regex
    # Supports: * (any segment), ** (any segments), exact match
    regex_pattern =
      pattern
      |> String.replace(".", "\\.")
      |> String.replace("**", "___DOUBLE_STAR___")
      |> String.replace("*", "[^.]+")
      |> String.replace("___DOUBLE_STAR___", ".*")
      |> then(&"^#{&1}$")

    Regex.match?(Regex.compile!(regex_pattern), secret_path)
  end

  defp check_time_of_day(timestamp, time_range) do
    # Format: "09:00-17:00"
    case String.split(time_range, "-") do
      [start_time, end_time] ->
        current_time = Calendar.strftime(timestamp, "%H:%M")

        if time_in_range?(current_time, start_time, end_time) do
          {:ok, "Current time #{current_time} is within allowed range #{time_range}"}
        else
          {:error, "Current time #{current_time} outside allowed range #{time_range}"}
        end

      _ ->
        {:error, "Invalid time_of_day format: #{time_range}"}
    end
  end

  defp check_day_of_week(timestamp, allowed_days) do
    # Format: ["monday", "tuesday", "wednesday", "thursday", "friday"]
    current_day =
      timestamp
      |> DateTime.to_date()
      |> Date.day_of_week()
      |> day_of_week_to_name()

    if current_day in allowed_days do
      {:ok, "Current day #{current_day} is allowed"}
    else
      {:error, "Current day #{current_day} not in allowed days: #{inspect(allowed_days)}"}
    end
  end

  defp check_date_range(timestamp, date_range) do
    # Format: "2024-01-01,2024-12-31"
    case String.split(date_range, ",") do
      [start_date_str, end_date_str] ->
        current_date = DateTime.to_date(timestamp)

        with {:ok, start_date} <- Date.from_iso8601(start_date_str),
             {:ok, end_date} <- Date.from_iso8601(end_date_str) do
          if Date.compare(current_date, start_date) in [:gt, :eq] &&
               Date.compare(current_date, end_date) in [:lt, :eq] do
            {:ok, "Current date within allowed range"}
          else
            {:error, "Current date #{current_date} outside range #{date_range}"}
          end
        else
          _ -> {:error, "Invalid date_range format: #{date_range}"}
        end

      _ ->
        {:error, "Invalid date_range format: #{date_range}"}
    end
  end

  defp time_in_range?(current, start_time, end_time) do
    current >= start_time && current <= end_time
  end

  defp day_of_week_to_name(1), do: "monday"
  defp day_of_week_to_name(2), do: "tuesday"
  defp day_of_week_to_name(3), do: "wednesday"
  defp day_of_week_to_name(4), do: "thursday"
  defp day_of_week_to_name(5), do: "friday"
  defp day_of_week_to_name(6), do: "saturday"
  defp day_of_week_to_name(7), do: "sunday"

  defp ip_in_ranges?(ip_address, ip_ranges) do
    Enum.any?(ip_ranges, fn range ->
      case parse_cidr(range) do
        {:ok, network, prefix_len} ->
          ip_in_cidr?(ip_address, network, prefix_len)

        {:error, _} ->
          # Try exact match
          ip_address == range
      end
    end)
  end

  defp parse_cidr(cidr) when is_binary(cidr) do
    case String.split(cidr, "/") do
      [ip, prefix] ->
        with {:ok, addr} <- parse_ip(ip),
             {prefix_len, ""} <- Integer.parse(prefix) do
          {:ok, addr, prefix_len}
        else
          _ -> {:error, :invalid_cidr}
        end

      [ip] ->
        # Single IP, treat as /32 (IPv4) or /128 (IPv6)
        with {:ok, addr} <- parse_ip(ip) do
          prefix_len = if tuple_size(addr) == 4, do: 32, else: 128
          {:ok, addr, prefix_len}
        end

      _ ->
        {:error, :invalid_cidr}
    end
  end

  defp parse_ip(ip_string) do
    ip_charlist = String.to_charlist(ip_string)

    case :inet.parse_address(ip_charlist) do
      {:ok, addr} -> {:ok, addr}
      {:error, _} -> {:error, :invalid_ip}
    end
  end

  defp ip_in_cidr?(ip_string, network, prefix_len) when is_binary(ip_string) do
    case parse_ip(ip_string) do
      {:ok, ip_addr} -> ip_in_cidr?(ip_addr, network, prefix_len)
      {:error, _} -> false
    end
  end

  defp ip_in_cidr?(ip_addr, network, prefix_len) when is_tuple(ip_addr) and is_tuple(network) do
    # Convert IP addresses to integers and compare with prefix mask
    ip_int = tuple_to_int(ip_addr)
    network_int = tuple_to_int(network)
    bits = tuple_size(network) * 8

    mask = bnot(bsl(1, bits - prefix_len) - 1)

    band(ip_int, mask) == band(network_int, mask)
  end

  defp tuple_to_int(ip_tuple) do
    ip_tuple
    |> Tuple.to_list()
    |> Enum.reduce(0, fn byte, acc -> bsl(acc, 8) + byte end)
  end

  defp format_simulation_steps(steps) do
    Enum.map(steps, fn {name, result} ->
      case result do
        {:ok, msg} -> %{step: name, result: :pass, message: msg}
        {:error, msg} -> %{step: name, result: :fail, message: msg}
      end
    end)
  end
end
