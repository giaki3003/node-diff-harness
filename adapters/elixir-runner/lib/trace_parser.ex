defmodule ElixirRunner.TraceParser do
  @moduledoc """
  Parses binary traces into Elixir data structures.
  
  This module handles parsing the bincode-serialized traces sent from
  the Rust fuzzer into Elixir maps that can be executed.
  """

  @doc """
  Parse a binary trace into an Elixir map.
  
  Expected format (bincode serialized):
  - seed: u64
  - ops: Vec<Operation>
  
  Where Operation is an enum with variants:
  - Ping{temporal_height, temporal_slot, rooted_height, rooted_slot, timestamp_ms}
  - TxPool{txs: Vec<Vec<u8>>}
  - Peers{ips: Vec<String>}
  - ProcessTx{tx_data: Vec<u8>, is_special_meeting: bool}
  - SerializeMessage{msg_type: MessageType, payload: Vec<u8>}
  """
  def parse(trace_binary) do
    try do
      # For now, use a simple JSON-based approach for testing
      # In production, we'd implement proper bincode deserialization
      case parse_simple_format(trace_binary) do
        {:ok, trace} -> {:ok, trace}
        {:error, _} -> parse_fallback_format(trace_binary)
      end
    rescue
      e -> {:error, "parse_exception: #{Exception.message(e)}"}
    end
  end
  
  # Try parsing as JSON first (for testing/debugging)
  defp parse_simple_format(binary) do
    case Jason.decode(binary) do
      {:ok, data} -> {:ok, normalize_trace(data)}
      {:error, _} -> {:error, :not_json}
    end
  end
  
  # Fallback: try parsing as Erlang term format
  defp parse_fallback_format(binary) do
    try do
      case :erlang.binary_to_term(binary, [:safe]) do
        term when is_map(term) -> {:ok, normalize_trace(term)}
        term -> {:error, "invalid_term: #{inspect(term)}"}
      end
    rescue
      _ -> {:error, :not_etf}
    end
  end
  
  # Normalize parsed data into consistent format
  defp normalize_trace(data) when is_map(data) do
    %{
      seed: Map.get(data, "seed", Map.get(data, :seed, 0)),
      ops: parse_operations(Map.get(data, "ops", Map.get(data, :ops, [])))
    }
  end
  
  defp normalize_trace(_), do: %{seed: 0, ops: []}
  
  defp parse_operations(ops) when is_list(ops) do
    Enum.map(ops, &parse_operation/1)
  end
  
  defp parse_operations(_), do: []
  
  defp parse_operation(%{"Ping" => ping_data}) do
    %{
      type: :ping,
      temporal_height: get_field(ping_data, "temporal_height", 0),
      temporal_slot: get_field(ping_data, "temporal_slot", 0),
      rooted_height: get_field(ping_data, "rooted_height", 0),  
      rooted_slot: get_field(ping_data, "rooted_slot", 0),
      timestamp_ms: get_field(ping_data, "timestamp_ms", 0)
    }
  end
  
  defp parse_operation(%{"TxPool" => txpool_data}) do
    %{
      type: :txpool,
      txs: get_field(txpool_data, "txs", [])
    }
  end
  
  defp parse_operation(%{"Peers" => peers_data}) do
    %{
      type: :peers,
      ips: get_field(peers_data, "ips", [])
    }
  end
  
  defp parse_operation(%{"PeersV2" => peers_v2_data}) do
    %{
      type: :peers_v2,
      anrs: get_field(peers_v2_data, "anrs", [])
    }
  end
  
  defp parse_operation(%{"ProcessTx" => tx_data}) do
    %{
      type: :process_tx,
      tx_data: get_field(tx_data, "tx_data", []),
      is_special_meeting: get_field(tx_data, "is_special_meeting", false)
    }
  end
  
  defp parse_operation(%{"SerializeMessage" => msg_data}) do
    %{
      type: :serialize_message,
      msg_type: parse_message_type(get_field(msg_data, "msg_type", "Ping")),
      payload: get_field(msg_data, "payload", [])
    }
  end
  
  # Handle Elixir atom-keyed maps
  defp parse_operation(%{type: type} = op) when is_atom(type), do: op
  
  # Handle other formats
  defp parse_operation(data) when is_map(data) do
    # Try to infer operation type from keys
    cond do
      Map.has_key?(data, "temporal_height") or Map.has_key?(data, :temporal_height) ->
        %{
          type: :ping,
          temporal_height: get_field(data, "temporal_height", 0),
          temporal_slot: get_field(data, "temporal_slot", 0),
          rooted_height: get_field(data, "rooted_height", 0),
          rooted_slot: get_field(data, "rooted_slot", 0),
          timestamp_ms: get_field(data, "timestamp_ms", 0)
        }
      Map.has_key?(data, "txs") or Map.has_key?(data, :txs) ->
        %{type: :txpool, txs: get_field(data, "txs", [])}
      Map.has_key?(data, "ips") or Map.has_key?(data, :ips) ->
        %{type: :peers, ips: get_field(data, "ips", [])}
      Map.has_key?(data, "tx_data") or Map.has_key?(data, :tx_data) ->
        %{
          type: :process_tx,
          tx_data: get_field(data, "tx_data", []),
          is_special_meeting: get_field(data, "is_special_meeting", false)
        }
      true ->
        %{type: :unknown, data: data}
    end
  end
  
  defp parse_operation(_), do: %{type: :unknown}
  
  defp parse_message_type("Ping"), do: :ping
  defp parse_message_type("Pong"), do: :pong  
  defp parse_message_type("TxPool"), do: :txpool
  defp parse_message_type("Peers"), do: :peers
  defp parse_message_type(_), do: :ping
  
  defp get_field(map, key, default) when is_map(map) do
    case Map.get(map, key) do
      nil -> Map.get(map, String.to_atom(key), default)
      value -> value
    end
  end
  
  defp get_field(_, _, default), do: default
end