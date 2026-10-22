defmodule SecretHub.Core.PKI.DNS.Cloudflare do
  @moduledoc "Scoped Cloudflare TXT operations with durable per-record ownership evidence."
  alias SecretHub.Core.PKI.DNS.{Names, Request}
  @base "https://api.cloudflare.com/client/v4"
  @max_pages 20

  def validate_zone(config, credentials, opts \\ []) do
    with {:ok, %{"result" => zone}} when is_map(zone) <-
           api(:get, zone_path(config), nil, credentials, opts),
         true <- zone["id"] == config["zone_id"],
         true <-
           Names.canonical_owner(zone["name"]) == Names.canonical_owner(config["zone_name"]),
         true <- zone["status"] == "active" do
      {:ok,
       %{
         "zone_id" => zone["id"],
         "zone_name" => Names.canonical_owner(zone["name"]),
         "public" => true
       }}
    else
      false -> {:error, :zone_mismatch}
      {:error, _} = error -> error
      _ -> {:error, :invalid_provider_response}
    end
  end

  def observe(config, credentials, owner, opts \\ []) do
    if Names.within_zone?(owner, config["zone_name"]) do
      records(config, credentials, Names.canonical_owner(owner), 1, [], opts)
    else
      {:error, :wrong_zone}
    end
  end

  def present(config, credentials, intent, opts \\ []) do
    with {:ok, %{records: records}} <- observe(config, credentials, intent["owner"], opts) do
      case owned_receipt(config, intent, records) do
        {:ok, receipt} -> {:ok, receipt}
        {:error, :not_observed} -> borrow_or_create(config, credentials, intent, records, opts)
        error -> error
      end
    end
  end

  def reconcile(config, credentials, intent, opts \\ []) do
    with {:ok, %{records: records}} <- observe(config, credentials, intent["owner"], opts) do
      owned_receipt(config, intent, records)
    end
  end

  def cleanup(config, credentials, receipt, opts \\ []) do
    cond do
      receipt["zone_id"] != config["zone_id"] ->
        {:error, :wrong_zone}

      receipt["ownership"] == "borrowed" ->
        {:ok, Map.put(receipt, "cleanup_status", "cleaned")}

      receipt["ownership"] != "created" ->
        {:error, :unresolved_ownership}

      true ->
        cleanup_created(config, credentials, receipt, opts)
    end
  end

  defp cleanup_created(config, credentials, receipt, opts) do
    ids = receipt["record_ids"] || List.wrap(receipt["record_id"])

    if ids == [] do
      {:error, :unresolved_ownership}
    else
      delete_records(config, credentials, receipt, ids, opts)
    end
  end

  defp delete_records(config, credentials, receipt, ids, opts) do
    Enum.reduce_while(ids, :ok, fn id, :ok ->
      case delete_owned(config, credentials, receipt, id, opts) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
    |> case do
      :ok -> {:ok, Map.put(receipt, "cleanup_status", "cleaned")}
      error -> error
    end
  end

  defp records(_, _, _, page, _, _) when page > @max_pages, do: {:error, :pagination_limit}

  defp records(config, credentials, owner, page, acc, opts) do
    query =
      URI.encode_query(%{"type" => "TXT", "name" => owner, "page" => page, "per_page" => 100})

    case api(:get, zone_path(config) <> "/dns_records?" <> query, nil, credentials, opts) do
      {:ok, %{"result" => records} = response} when is_list(records) ->
        with {:ok, matching} <- matching_records(records, owner),
             {:ok, pages} <- page_count(response["result_info"]) do
          next_page(config, credentials, owner, page, pages, matching ++ acc, opts)
        end

      {:error, _} = error ->
        error

      _ ->
        {:error, :invalid_provider_response}
    end
  end

  defp matching_records(records, owner) do
    if Enum.all?(records, &is_map/1),
      do:
        {:ok,
         Enum.filter(
           records,
           &(&1["type"] == "TXT" and Names.canonical_owner(&1["name"]) == owner)
         )},
      else: {:error, :invalid_provider_response}
  end

  defp page_count(nil), do: {:ok, 1}
  defp page_count(info) when is_map(info), do: {:ok, info["total_pages"] || 1}
  defp page_count(_), do: {:error, :invalid_provider_response}

  defp next_page(config, credentials, owner, page, pages, acc, opts)
       when is_integer(pages) and pages >= page and pages <= @max_pages do
    if page < pages,
      do: records(config, credentials, owner, page + 1, acc, opts),
      else: {:ok, %{records: Enum.reverse(acc)}}
  end

  defp next_page(_, _, _, _, _, _, _), do: {:error, :pagination_limit}

  defp owned_receipt(config, intent, records) do
    matching =
      Enum.filter(
        records,
        &(&1["content"] == intent["value"] and &1["comment"] == marker(intent))
      )

    case matching do
      [] ->
        {:error, :not_observed}

      [record | _] ->
        if Enum.all?(matching, &(is_binary(&1["id"]) and &1["id"] != "")) do
          {:ok,
           receipt(config, intent, "created")
           |> Map.put("record_id", record["id"])
           |> Map.put("record_ids", Enum.map(matching, & &1["id"]))
           |> Map.put("record_ttls", Map.new(matching, &{&1["id"], &1["ttl"]}))}
        else
          {:error, :invalid_provider_response}
        end
    end
  end

  defp borrow_or_create(config, credentials, intent, records, opts) do
    if Enum.any?(records, &(&1["content"] == intent["value"])) do
      {:ok, receipt(config, intent, "borrowed")}
    else
      create_record(config, credentials, intent, opts)
    end
  end

  defp create_record(config, credentials, intent, opts) do
    body = %{
      "type" => "TXT",
      "name" => Names.canonical_owner(intent["owner"]),
      "content" => intent["value"],
      "ttl" => 120,
      "comment" => marker(intent)
    }

    case api(:post, zone_path(config) <> "/dns_records", body, credentials, opts) do
      {:ok, %{"result" => %{"id" => id} = record}} when is_binary(id) ->
        created_receipt(config, intent, record, id)

      {:error, :transport_unavailable} ->
        ambiguous_receipt(config, intent)

      {:error, %{reason: :provider_unavailable}} ->
        ambiguous_receipt(config, intent)

      {:error, _} = error ->
        error

      _ ->
        {:error, :invalid_provider_response}
    end
  end

  defp created_receipt(config, intent, record, id) do
    receipt = receipt(config, intent, "created") |> Map.put("record_id", id)

    if unchanged?(record, receipt, id),
      do:
        {:ok,
         receipt |> Map.put("record_ids", [id]) |> Map.put("record_ttls", %{id => record["ttl"]})},
      else: {:error, :invalid_provider_response}
  end

  defp ambiguous_receipt(config, intent),
    do: {:error, %{reason: :ambiguous_mutation, receipt: receipt(config, intent, "ambiguous")}}

  defp delete_owned(config, credentials, receipt, id, opts) do
    path = zone_path(config) <> "/dns_records/" <> URI.encode_www_form(id)

    case api(:get, path, nil, credentials, opts) do
      {:error, :not_found} ->
        :ok

      {:ok, %{"result" => record}} when is_map(record) ->
        if unchanged?(record, receipt, id),
          do: delete_record(path, credentials, opts),
          else: {:error, :ownership_conflict}

      {:error, _} = error ->
        error

      _ ->
        {:error, :invalid_provider_response}
    end
  end

  defp delete_record(path, credentials, opts) do
    case api(:delete, path, nil, credentials, opts) do
      {:ok, _} -> :ok
      {:error, :not_found} -> :ok
      error -> error
    end
  end

  defp unchanged?(record, receipt, id) do
    record["id"] == id and record["type"] == "TXT" and
      Names.canonical_owner(record["name"]) == Names.canonical_owner(receipt["owner"]) and
      record["content"] == receipt["value"] and record["comment"] == receipt["marker"] and
      (not is_map(receipt["record_ttls"]) or record["ttl"] == receipt["record_ttls"][id])
  end

  defp receipt(config, intent, ownership),
    do: %{
      "provider" => "cloudflare",
      "zone_id" => config["zone_id"],
      "owner" => Names.canonical_owner(intent["owner"]),
      "value" => intent["value"],
      "intent_id" => intent["id"],
      "marker" => marker(intent),
      "ownership" => ownership,
      "cleanup_status" => "pending"
    }

  defp marker(intent), do: "secrethub-acme:" <> intent["id"]
  defp zone_path(config), do: "/zones/" <> URI.encode_www_form(config["zone_id"])

  defp api(method, path, body, credentials, opts) do
    case credentials["api_token"] || credentials["token"] do
      token when is_binary(token) and token != "" ->
        authenticated_request(method, path, body, token, opts)

      _ ->
        {:error, :credentials_unavailable}
    end
  end

  defp authenticated_request(method, path, body, token, opts) do
    headers = [{"authorization", "Bearer " <> token}, {"content-type", "application/json"}]

    with {:ok, response} <-
           Request.request(
             method,
             @base <> path,
             headers,
             if(body, do: JSON.encode!(body), else: ""),
             opts
           ) do
      case JSON.decode(response.body) do
        {:ok, decoded} -> decode_response(decoded)
        {:error, _} -> {:error, :invalid_provider_response}
      end
    end
  end

  defp decode_response(%{"success" => true} = decoded), do: {:ok, decoded}
  defp decode_response(%{"success" => false}), do: {:error, :provider_rejected}
  defp decode_response(_), do: {:error, :invalid_provider_response}
end
