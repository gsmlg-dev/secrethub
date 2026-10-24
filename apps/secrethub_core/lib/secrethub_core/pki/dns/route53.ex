defmodule SecretHub.Core.PKI.DNS.Route53 do
  @moduledoc """
  Guarded Route 53 TXT RRset changes. Persist `prepare/4` before calling `present/4`.

  Callers serialize bounded mutations by credential identity, zone and owner. The
  exact DELETE/CREATE batch detects changes to the observed preimage; local locks
  cannot fence external writers. No propagation waits occur in this module.
  """
  alias SecretHub.Core.PKI.DNS.{Names, Request}
  alias SecretHub.Core.PKI.HTTP
  @base "https://route53.amazonaws.com/2013-04-01"
  @max_pages 20

  def list_zones(credentials, opts \\ []),
    do: hosted_zones(credentials, nil, [], 1, [], opts)

  defp hosted_zones(_, _, _, page, _, _) when page > @max_pages,
    do: {:error, :pagination_limit}

  defp hosted_zones(credentials, marker, seen, page, acc, opts) do
    params =
      if marker, do: %{"maxitems" => "100", "marker" => marker}, else: %{"maxitems" => "100"}

    with {:ok, xml} <-
           api(:get, "/hostedzone?" <> URI.encode_query(params), "", credentials, opts),
         true <- length(:xmerl_xpath.string(~c"/ListHostedZonesResponse/HostedZones", xml)) == 1,
         {:ok, found} <- public_hosted_zones(xml) do
      all = Enum.reverse(found, acc)
      truncated = text(xml, ~c"/ListHostedZonesResponse/IsTruncated/text()")
      next = text(xml, ~c"/ListHostedZonesResponse/NextMarker/text()")

      cond do
        truncated == "false" ->
          {:ok, Enum.reverse(all)}

        truncated == "true" and next != "" and next not in seen ->
          hosted_zones(credentials, next, [next | seen], page + 1, all, opts)

        true ->
          {:error, :invalid_provider_response}
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_provider_response}
    end
  end

  defp public_hosted_zones(xml) do
    :xmerl_xpath.string(~c"/ListHostedZonesResponse/HostedZones/HostedZone", xml)
    |> Enum.reject(&(text(&1, ~c"./Config/PrivateZone/text()") == "true"))
    |> Enum.reduce_while({:ok, []}, fn node, {:ok, acc} ->
      with "false" <- text(node, ~c"./Config/PrivateZone/text()"),
           {:ok, zone} <- discovered_zone(node) do
        {:cont, {:ok, [zone | acc]}}
      else
        _ -> {:halt, {:error, :invalid_provider_response}}
      end
    end)
    |> case do
      {:ok, zones} -> {:ok, Enum.reverse(zones)}
      error -> error
    end
  end

  defp discovered_zone(node) do
    with "/hostedzone/" <> id when id != "" <- text(node, ~c"./Id/text()"),
         {:ok, name} <- Names.normalize_identifier(text(node, ~c"./Name/text()")),
         false <- String.starts_with?(name, "*.") do
      {:ok, %{"zone_id" => id, "zone_name" => name}}
    else
      _ -> {:error, :invalid_provider_response}
    end
  end

  def validate_zone(config, credentials, opts \\ []) do
    with {:ok, xml} <- api(:get, zone_path(config), "", credentials, opts),
         :ok <- public_zone(text(xml, ~c"//HostedZone/Config/PrivateZone/text()")),
         true <- text(xml, ~c"//HostedZone/Id/text()") == "/hostedzone/" <> zone_id(config),
         true <-
           Names.canonical_owner(text(xml, ~c"//HostedZone/Name/text()")) ==
             Names.canonical_owner(config["zone_name"]) do
      {:ok,
       %{
         "zone_id" => zone_id(config),
         "zone_name" => Names.canonical_owner(config["zone_name"]),
         "public" => true
       }}
    else
      false -> {:error, :zone_mismatch}
      {:error, _} = error -> error
    end
  end

  def observe(config, credentials, owner, opts \\ []) do
    with true <- Names.within_zone?(owner, config["zone_name"]),
         {:ok, _} <- validate_zone(config, credentials, opts),
         {:ok, rrset} <-
           list(config, credentials, Names.canonical_owner(owner), nil, nil, 1, [], opts) do
      {:ok, %{rrset: rrset}}
    else
      false -> {:error, :wrong_zone}
      error -> error
    end
  end

  def prepare(config, credentials, intent, opts \\ []) do
    with {:ok, %{rrset: rrset}} <- observe(config, credentials, intent["owner"], opts) do
      {:ok, intent |> Map.put("preimage", rrset) |> Map.put("prepared", true)}
    end
  end

  def present(config, credentials, intent, opts \\ []) do
    with true <- intent["prepared"] == true and Map.has_key?(intent, "preimage"),
         {:ok, %{rrset: current}} <- observe(config, credentials, intent["owner"], opts) do
      preimage = canonical_rrset(intent["preimage"])

      cond do
        canonical_rrset(current) != preimage ->
          {:error, :record_conflict}

        current && intent["value"] in current["values"] ->
          {:ok, receipt(config, intent, "borrowed")}

        true ->
          mutate(
            config,
            credentials,
            intent,
            current,
            add_value(current, intent),
            "present",
            opts
          )
      end
    else
      false -> {:error, :intent_not_prepared}
      error -> error
    end
  end

  def reconcile(config, credentials, intent, opts \\ []) do
    with true <- intent["prepared"] == true and Map.has_key?(intent, "preimage"),
         {:ok, %{rrset: current}} <- observe(config, credentials, intent["owner"], opts) do
      preimage = canonical_rrset(intent["preimage"])
      desired = add_value(intent["preimage"], intent) |> canonical_rrset()

      cond do
        preimage && intent["value"] in preimage["values"] ->
          {:ok, receipt(config, intent, "borrowed")}

        canonical_rrset(current) == desired ->
          {:ok,
           receipt(config, intent, "ambiguous")
           |> Map.put("change_status", "UNKNOWN")
           |> Map.put("observation", "desired_state_visible")}

        canonical_rrset(current) == preimage ->
          {:error, :not_observed}

        true ->
          {:error, :unresolved_ownership}
      end
    else
      false -> {:error, :intent_not_prepared}
      error -> error
    end
  end

  def cleanup(config, credentials, receipt, opts \\ []) do
    cond do
      normalize_zone(receipt["zone_id"]) != zone_id(config) ->
        {:error, :wrong_zone}

      receipt["ownership"] == "borrowed" ->
        {:ok, Map.put(receipt, "cleanup_status", "cleaned")}

      receipt["ownership"] != "created" ->
        {:error, :unresolved_ownership}

      receipt["phase"] == "cleanup" and receipt["change_id"] ->
        poll_change(config, credentials, receipt, opts)

      true ->
        cleanup_current(config, credentials, receipt, opts)
    end
  end

  defp cleanup_current(config, credentials, receipt, opts) do
    with {:ok, %{rrset: current}} <- observe(config, credentials, receipt["owner"], opts) do
      if current == nil or receipt["value"] not in current["values"] do
        {:ok, Map.put(receipt, "cleanup_status", "cleaned")}
      else
        mutate(
          config,
          credentials,
          receipt,
          current,
          remove_value(current, receipt["value"]),
          "cleanup",
          opts
        )
      end
    end
  end

  defp remove_value(current, value) do
    remaining =
      Enum.zip(current["values"], current["raw_values"])
      |> Enum.reject(fn {existing, _} -> existing == value end)

    if remaining == [],
      do: nil,
      else: %{
        current
        | "values" => Enum.map(remaining, &elem(&1, 0)),
          "raw_values" => Enum.map(remaining, &elem(&1, 1))
      }
  end

  def poll_change(_config, credentials, receipt, opts \\ []) do
    case receipt["change_id"] do
      id when is_binary(id) ->
        with {:ok, xml} <-
               api(
                 :get,
                 "/change/" <> URI.encode_www_form(String.trim_leading(id, "/change/")),
                 "",
                 credentials,
                 opts
               ),
             status when status in ["PENDING", "INSYNC"] <-
               text(xml, ~c"//ChangeInfo/Status/text()") do
          result = Map.put(receipt, "change_status", status)

          {:ok,
           if(receipt["phase"] == "cleanup" and status == "INSYNC",
             do: Map.put(result, "cleanup_status", "cleaned"),
             else: result
           )}
        else
          {:error, _} = error -> error
          _ -> {:error, :invalid_provider_response}
        end

      _ ->
        {:ok, receipt}
    end
  end

  defp list(_, _, _, _, _, page, _, _) when page > @max_pages, do: {:error, :pagination_limit}

  defp list(config, credentials, owner, next_name, next_type, page, acc, opts) do
    query =
      URI.encode_query(%{
        "name" => next_name || owner <> ".",
        "type" => next_type || "TXT",
        "maxitems" => "100"
      })

    with {:ok, xml} <- api(:get, zone_path(config) <> "/rrset?" <> query, "", credentials, opts),
         :ok <- complete_list_response(xml),
         {:ok, found} <- parse_rrsets(xml, owner) do
      all = found ++ acc
      next = text(xml, ~c"//NextRecordName/text()")

      cond do
        text(xml, ~c"//IsTruncated/text()") == "true" and Names.canonical_owner(next) == owner ->
          next_page(config, credentials, owner, xml, page, all, opts)

        all == [] ->
          {:ok, nil}

        length(all) == 1 ->
          {:ok, hd(all)}

        true ->
          {:error, :unsupported_record_shape}
      end
    end
  end

  defp next_page(config, credentials, owner, xml, page, all, opts) do
    if text(xml, ~c"//NextRecordIdentifier/text()") != "",
      do: {:error, :unsupported_record_shape},
      else:
        list(
          config,
          credentials,
          owner,
          text(xml, ~c"//NextRecordName/text()"),
          text(xml, ~c"//NextRecordType/text()"),
          page + 1,
          all,
          opts
        )
  end

  defp public_zone("false"), do: :ok
  defp public_zone("true"), do: {:error, :private_zone}
  defp public_zone(_), do: {:error, :invalid_provider_response}

  defp complete_list_response(xml) do
    if text(xml, ~c"//IsTruncated/text()") in ["true", "false"] and
         length(:xmerl_xpath.string(~c"/ListResourceRecordSetsResponse/ResourceRecordSets", xml)) ==
           1,
       do: :ok,
       else: {:error, :invalid_provider_response}
  end

  defp parse_rrsets(xml, owner) do
    :xmerl_xpath.string(~c"//ResourceRecordSet", xml)
    |> Enum.filter(
      &(Names.canonical_owner(text(&1, ~c"./Name/text()")) == owner and
          text(&1, ~c"./Type/text()") == "TXT")
    )
    |> Enum.reduce_while({:ok, []}, fn node, {:ok, acc} ->
      case plain_rrset(node, owner) do
        {:ok, record} -> {:cont, {:ok, [record | acc]}}
        error -> {:halt, error}
      end
    end)
  end

  defp plain_rrset(node, owner) do
    child_names = :xmerl_xpath.string(~c"./*", node) |> Enum.map(&elem(&1, 1))

    raw_values =
      :xmerl_xpath.string(~c"./ResourceRecords/ResourceRecord/Value/text()", node)
      |> Enum.map(&text_value/1)

    with true <- Enum.all?(child_names, &(&1 in [:Name, :Type, :TTL, :ResourceRecords])),
         {ttl, ""} when ttl > 0 <- Integer.parse(text(node, ~c"./TTL/text()")),
         true <- raw_values != [],
         {:ok, values} <- decode_values(raw_values) do
      {:ok, %{"name" => owner, "ttl" => ttl, "values" => values, "raw_values" => raw_values}}
    else
      _ -> {:error, :unsupported_record_shape}
    end
  end

  defp decode_values(raw_values) do
    Enum.reduce_while(raw_values, {:ok, []}, fn raw, {:ok, acc} ->
      case decode_txt(raw) do
        {:ok, decoded} -> {:cont, {:ok, [decoded | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      error -> error
    end
  end

  defp decode_txt(raw) do
    segments = Regex.scan(~r/"((?:\\[0-7]{3}|\\.|[^"\\])*)"/, raw)
    remainder = Regex.replace(~r/"((?:\\[0-7]{3}|\\.|[^"\\])*)"/, raw, "") |> String.trim()

    if segments != [] and remainder == "",
      do: {:ok, Enum.map_join(segments, fn [_, value] -> decode_segment(value) end)},
      else: {:error, :unsupported_record_shape}
  end

  defp decode_segment(value) do
    Regex.replace(~r/\\([0-7]{3}|.)/, value, fn _, escaped ->
      if byte_size(escaped) == 3, do: <<String.to_integer(escaped, 8)>>, else: escaped
    end)
  end

  defp add_value(nil, intent),
    do: %{
      "name" => Names.canonical_owner(intent["owner"]),
      "ttl" => 60,
      "values" => [intent["value"]],
      "raw_values" => [quote_txt(intent["value"])]
    }

  defp add_value(current, intent) do
    current = canonical_rrset(current)

    if intent["value"] in current["values"],
      do: current,
      else: %{
        current
        | "values" => current["values"] ++ [intent["value"]],
          "raw_values" => current["raw_values"] ++ [quote_txt(intent["value"])]
      }
  end

  defp canonical_rrset(nil), do: nil

  defp canonical_rrset(rrset) do
    pairs =
      Enum.zip(rrset["values"], rrset["raw_values"] || Enum.map(rrset["values"], &quote_txt/1))
      |> Enum.sort_by(&elem(&1, 1))

    %{
      "name" => Names.canonical_owner(rrset["name"]),
      "ttl" => rrset["ttl"],
      "values" => Enum.map(pairs, &elem(&1, 0)),
      "raw_values" => Enum.map(pairs, &elem(&1, 1))
    }
  end

  defp mutate(config, credentials, intent, before_set, after_set, phase, opts) do
    changes =
      if(before_set, do: [change_xml("DELETE", before_set)], else: []) ++
        if after_set, do: [change_xml("CREATE", after_set)], else: []

    body =
      "<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Comment>SecretHub ACME #{escape(intent["intent_id"] || intent["id"])}</Comment><Changes>#{Enum.join(changes)}</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"

    base_receipt = receipt(config, intent, "created") |> Map.put("phase", phase)

    case api(:post, zone_path(config) <> "/rrset", body, credentials, opts) do
      {:ok, xml} ->
        mutation_receipt(xml, base_receipt, phase)

      {:error, :transport_unavailable} ->
        {:error,
         %{reason: :ambiguous_mutation, receipt: Map.put(base_receipt, "ownership", "ambiguous")}}

      {:error, %{reason: :provider_unavailable}} ->
        {:error,
         %{reason: :ambiguous_mutation, receipt: Map.put(base_receipt, "ownership", "ambiguous")}}

      error ->
        error
    end
  end

  defp mutation_receipt(xml, base_receipt, phase) do
    id = text(xml, ~c"//ChangeInfo/Id/text()")
    status = text(xml, ~c"//ChangeInfo/Status/text()")

    if String.starts_with?(id, "/change/") and status in ["PENDING", "INSYNC"] do
      {:ok,
       base_receipt
       |> Map.put("change_id", id)
       |> Map.put("change_status", status)
       |> Map.put(
         "cleanup_status",
         cleanup_status(phase, status)
       )}
    else
      {:error,
       %{
         reason: :ambiguous_mutation,
         receipt: Map.put(base_receipt, "ownership", "ambiguous")
       }}
    end
  end

  defp cleanup_status("cleanup", "INSYNC"), do: "cleaned"
  defp cleanup_status("cleanup", _), do: "pending_change"
  defp cleanup_status(_, _), do: "pending"

  defp change_xml(action, record) do
    raw_values = record["raw_values"] || Enum.map(record["values"], &quote_txt/1)

    values =
      Enum.map_join(raw_values, &"<ResourceRecord><Value>#{escape(&1)}</Value></ResourceRecord>")

    "<Change><Action>#{action}</Action><ResourceRecordSet><Name>#{escape(record["name"])}.</Name><Type>TXT</Type><TTL>#{record["ttl"]}</TTL><ResourceRecords>#{values}</ResourceRecords></ResourceRecordSet></Change>"
  end

  defp receipt(config, intent, ownership),
    do: %{
      "provider" => "route53",
      "zone_id" => zone_id(config),
      "owner" => Names.canonical_owner(intent["owner"]),
      "value" => intent["value"],
      "intent_id" => intent["intent_id"] || intent["id"],
      "preimage" => intent["preimage"],
      "ownership" => ownership,
      "phase" => "present",
      "cleanup_status" => "pending"
    }

  defp quote_txt(value),
    do: "\"" <> (value |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")) <> "\""

  defp escape(value),
    do:
      value
      |> to_string()
      |> String.replace("&", "&amp;")
      |> String.replace("<", "&lt;")
      |> String.replace(">", "&gt;")
      |> String.replace("\"", "&quot;")
      |> String.replace("'", "&apos;")

  defp zone_id(config), do: normalize_zone(config["zone_id"])
  defp normalize_zone(value) when is_binary(value), do: String.trim_leading(value, "/hostedzone/")
  defp normalize_zone(_), do: ""
  defp zone_path(config), do: "/hostedzone/" <> URI.encode_www_form(zone_id(config))

  defp api(method, path, body, credentials, opts) do
    with {:ok, credentials} <- credentials(credentials) do
      url = @base <> path
      headers = [{"host", "route53.amazonaws.com"}, {"content-type", "application/xml"}]

      headers =
        if credentials["session_token"],
          do: [{"x-amz-security-token", credentials["session_token"]} | headers],
          else: headers

      headers =
        :aws_signature.sign_v4(
          credentials["access_key_id"],
          credentials["secret_access_key"],
          "us-east-1",
          "route53",
          Keyword.get(opts, :datetime, :calendar.universal_time()),
          method |> Atom.to_string() |> String.upcase(),
          url,
          headers,
          body
        )
        |> Enum.map(fn {name, value} -> {String.downcase(name), value} end)

      case HTTP.request(method, url, headers, body, opts) do
        {:ok, %{status: status, body: response}} when status in 200..299 ->
          parse_xml(response)

        {:ok, %{status: status}} when status in [401, 403] ->
          {:error, %{reason: :authentication, status: status}}

        {:ok, %{status: 404}} ->
          {:error, :not_found}

        {:ok, %{status: status, headers: response_headers, body: response}} ->
          provider_error(status, response_headers, response)

        {:error, _} ->
          {:error, :transport_unavailable}
      end
    end
  end

  defp credentials(%{"access_key_id" => key, "secret_access_key" => secret} = credentials)
       when is_binary(key) and key != "" and is_binary(secret) and secret != "",
       do: {:ok, credentials}

  defp credentials(%{"mode" => mode}) when mode in ["environment", "aws_environment"] do
    credentials(%{
      "access_key_id" => System.get_env("AWS_ACCESS_KEY_ID"),
      "secret_access_key" => System.get_env("AWS_SECRET_ACCESS_KEY"),
      "session_token" => System.get_env("AWS_SESSION_TOKEN")
    })
  end

  defp credentials(_), do: {:error, :credentials_unavailable}

  defp provider_error(status, headers, body) do
    code =
      case parse_xml(body) do
        {:ok, xml} -> text(xml, ~c"//Code/text()")
        _ -> ""
      end

    cond do
      code in ["InvalidChangeBatch", "PriorRequestNotComplete"] ->
        {:error, :record_conflict}

      status == 429 or code in ["Throttling", "ThrottlingException"] ->
        {:error, %{reason: :throttled, retry_after: Request.first_header(headers, "retry-after")}}

      status >= 500 ->
        {:error, %{reason: :provider_unavailable, status: status}}

      true ->
        {:error, %{reason: :provider_rejected, status: status}}
    end
  end

  defp parse_xml(body) when is_binary(body) and byte_size(body) <= 1_048_576 do
    if Regex.match?(~r/<!\s*(DOCTYPE|ENTITY)/i, body) do
      {:error, :invalid_provider_response}
    else
      try do
        {xml, rest} =
          body |> String.to_charlist() |> :xmerl_scan.string(quiet: true, validation: false)

        if Enum.all?(rest, &(&1 in [9, 10, 13, 32])),
          do: {:ok, xml},
          else: {:error, :invalid_provider_response}
      rescue
        _ -> {:error, :invalid_provider_response}
      catch
        _, _ -> {:error, :invalid_provider_response}
      end
    end
  end

  defp parse_xml(_), do: {:error, :invalid_provider_response}
  defp text(xml, xpath), do: xpath |> :xmerl_xpath.string(xml) |> Enum.map_join(&text_value/1)
  defp text_value({:xmlText, _, _, _, value, _}), do: List.to_string(value)
end
