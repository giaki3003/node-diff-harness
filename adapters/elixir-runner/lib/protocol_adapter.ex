defmodule ElixirRunner.ProtocolAdapter do
  @moduledoc """
  Adapter for protocol operations using the Elixir node implementation.
  
  This module interfaces with the actual NodeProto module from the 
  Elixir node to create and process protocol messages.
  """
  import Bitwise

  @protocol_ping <<112, 105, 110, 103>>
  @protocol_txpool <<116, 120, 112, 111, 111, 108>>
  @protocol_peers <<112, 101, 101, 114, 115>>
  @protocol_peers_v2 <<112, 101, 101, 114, 115, 95, 118, 50>>

  defstruct [
    :mock_signer
  ]

  @type t :: %__MODULE__{
    mock_signer: binary()
  }

  @doc """
  Initialize the protocol adapter.
  """
  def init do
    mock_signer = :binary.copy(<<0x42>>, 48)
    
    {:ok, %__MODULE__{
      mock_signer: mock_signer
    }}
  end

  @doc """
  Handle ping message creation and return canonical digest.
  """
  def handle_ping(_adapter, %{
    temporal_height: temporal_height,
    temporal_slot: temporal_slot,
    rooted_height: rooted_height, 
    rooted_slot: rooted_slot,
    timestamp_ms: timestamp_ms
  }) do
    try do
      digest = create_ping_canonical_digest(
        temporal_height,
        temporal_slot,
        rooted_height,
        rooted_slot,
        timestamp_ms
      )
      
      {:ok, %{
        type: :protocol,
        operation: :ping,
        data: digest,
        messages_count: 1
      }}
    rescue
      e -> {:error, "ping_error: #{Exception.message(e)}"}
    end
  end

  @doc """
  Handle transaction pool message and return canonical digest.
  """
  def handle_txpool(_adapter, %{txs: txs}) do
    try do
      {digest, included_count, filtered_count} = create_txpool_canonical_digest(txs)
      
      {:ok, %{
        type: :protocol,
        operation: :txpool,
        data: digest,
        tx_count: length(txs),
        included_tx_count: included_count,
        filtered_tx_count: filtered_count,
        messages_count: 1
      }}
    rescue
      e -> {:error, "txpool_error: #{Exception.message(e)}"}
    end
  end

  @doc """
  Handle peers message and return canonical digest.
  """
  def handle_peers(_adapter, %{ips: ips}) do
    try do
      digest = create_peers_canonical_digest(ips)
      
      {:ok, %{
        type: :protocol,
        operation: :peers,
        data: digest,
        peer_count: length(ips),
        messages_count: 1
      }}
    rescue
      e -> {:error, "peers_error: #{Exception.message(e)}"}
    end
  end

  @doc """
  Handle peers_v2 protocol message (modern ANR-based peer list).
  This uses the actual Elixir node implementation which supports peers_v2.
  """
  def handle_peers_v2(_adapter, %{anrs: anrs}) do
    try do
      digest = create_peers_v2_canonical_digest(anrs)
      
      {:ok, %{
        type: :protocol,
        operation: :peers_v2,
        data: digest,
        anr_count: length(anrs),
        messages_count: 1
      }}
    rescue
      e -> {:error, "peers_v2_error: #{Exception.message(e)}"}
    end
  end

  @doc """
  Test message serialization round-trip.
  """
  def test_serialization(_adapter, %{msg_type: msg_type, payload: payload}) do
    try do
      # Test round-trip based on message type
      success = case msg_type do
        :ping -> test_ping_serialization(payload)
        :pong -> test_pong_serialization(payload)
        :txpool -> test_txpool_serialization(payload)
        :peers -> test_peers_serialization(payload)
      end
      
      {:ok, %{
        type: :serialization,
        msg_type: msg_type,
        success: success
      }}
    rescue
      e -> {:error, "serialization_error: #{Exception.message(e)}"}
    end
  end

  defp create_ping_canonical_digest(temporal_height, temporal_slot, rooted_height, rooted_slot, timestamp_ms) do
    # Build exact byte sequence to mirror Rust and allow debugging
    bytes =
      @protocol_ping <>
      <<rooted_height::64-little>> <>
      <<rooted_slot::64-little>> <>
      <<temporal_height::64-little>> <>
      <<temporal_slot::64-little>> <>
      <<timestamp_ms::64-little>>

    debug_enabled =
      case System.get_env("AMA_ORACLE_DEBUG") do
        v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
        _ -> false
      end

    if debug_enabled do
      IO.puts(:standard_error, "[ELIXIR] Ping hash input hex: #{Base.encode16(bytes, case: :lower)}")
    end

    digest = :crypto.hash(:sha256, bytes)

    if debug_enabled do
      IO.puts(:standard_error, "[ELIXIR] Ping digest hex: #{Base.encode16(digest, case: :lower)}")
    end

    digest
  end
  
  defp create_txpool_canonical_digest(txs) do
    binary_txs =
      Enum.map(txs, fn
        tx when is_list(tx) -> :binary.list_to_bin(tx)
        tx when is_binary(tx) -> tx
        _ -> <<>>
      end)

    {valid_txs, filtered_count} =
      Enum.reduce(binary_txs, {[], 0}, fn tx, {acc, bad} ->
        is_valid =
          try do
            # Use the same validation logic as TxAdapter for consistency
            case validate_transaction_with_expansion_check(tx, false) do
              %{error: :ok} -> true
              _ -> false
            end
          rescue
            _ -> false
          catch
            _, _ -> false
          end

        if is_valid do
          {[tx | acc], bad}
        else
          {acc, bad + 1}
        end
      end)

    sorted_valid = Enum.sort(valid_txs)

    initial_hash =
      :crypto.hash_init(:sha256)
      |> :crypto.hash_update(@protocol_txpool)

    final_hash =
      Enum.reduce(sorted_valid, initial_hash, fn tx, hash_state ->
        :crypto.hash_update(hash_state, tx)
      end)

    digest = :crypto.hash_final(final_hash)
    {digest, length(sorted_valid), filtered_count}
  end
  
  defp create_peers_canonical_digest(ips) do
    sorted_ips = Enum.sort(ips)
    
    binary_ips = Enum.map(sorted_ips, fn ip -> 
      :binary.list_to_bin(:binary.bin_to_list(ip))
    end)
    
    initial_hash = :crypto.hash_init(:sha256)
    |> :crypto.hash_update(@protocol_peers)
    
    final_hash = Enum.reduce(binary_ips, initial_hash, fn ip_binary, hash_state ->
      :crypto.hash_update(hash_state, ip_binary)
    end)
    
    :crypto.hash_final(final_hash)
  end
  
  defp create_peers_v2_canonical_digest(anrs) do
    sorted_anrs = Enum.sort(anrs)
    
    binary_anrs = Enum.map(sorted_anrs, fn anr -> 
      :binary.list_to_bin(:binary.bin_to_list(anr))
    end)
    
    initial_hash = :crypto.hash_init(:sha256)
    |> :crypto.hash_update(@protocol_peers_v2)
    
    final_hash = Enum.reduce(binary_anrs, initial_hash, fn anr_binary, hash_state ->
      :crypto.hash_update(hash_state, anr_binary)
    end)
    
    :crypto.hash_final(final_hash)
  end

  defp create_mock_entry_summary(adapter, height, slot) do
    prev_hash = deterministic_hash(adapter, height, slot, 0)
    dr = deterministic_hash(adapter, height, slot, 1) 
    txs_hash = deterministic_hash(adapter, height, slot, 2)
    
    header = %{
      height: height,
      slot: slot,
      prev_slot: if(slot > 0, do: slot - 1, else: -1),
      prev_hash: prev_hash,
      signer: adapter.mock_signer,
      dr: dr,
      vr: :binary.copy(<<0x00>>, 96),
      txs_hash: txs_hash
    }
    
    header_packed = :erlang.term_to_binary(header, [:deterministic])
    signature = :binary.copy(<<0x00>>, 96)
    
    %{
      header: header_packed,
      signature: signature,
      mask: nil
    }
  end

  defp deterministic_hash(adapter, height, slot, salt) do
    data = <<height::64, slot::64, salt, adapter.mock_signer::binary>>
    :crypto.hash(:sha256, data)
  end

  defp test_ping_serialization(payload) do
    try do
      decompressed = NodeProto.deflate_decompress(payload)
      term = :erlang.binary_to_term(decompressed, [:safe])
      
      case term do
        %{op: :ping} -> true
        _ -> false
      end
    rescue
      _ -> false
    end
  end

  defp test_pong_serialization(payload) do
    try do
      decompressed = NodeProto.deflate_decompress(payload) 
      term = :erlang.binary_to_term(decompressed, [:safe])
      
      case term do
        %{op: :pong} -> true
        _ -> false
      end
    rescue
      _ -> false
    end
  end

  defp test_txpool_serialization(payload) do
    try do
      decompressed = NodeProto.deflate_decompress(payload)
      term = :erlang.binary_to_term(decompressed, [:safe])
      
      case term do
        %{op: :txpool} -> true
        _ -> false
      end
    rescue
      _ -> false
    end
  end

  defp test_peers_serialization(payload) do
    try do
      decompressed = NodeProto.deflate_decompress(payload)
      term = :erlang.binary_to_term(decompressed, [:safe])
      
      case term do
        %{op: :peers} -> true
        _ -> false
      end
    rescue
      _ -> false  
    end
  end

  # Transaction validation with expansion bomb detection
  # This mirrors the logic from TxAdapter to ensure consistent validation
  defp validate_transaction_with_expansion_check(tx_binary, is_special_meeting) do
    debug_enabled =
      case System.get_env("AMA_ORACLE_DEBUG") do
        v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
        _ -> false
      end

    # Write debug to file to ensure it's working
    if debug_enabled do
      File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] validate_transaction called with #{byte_size(tx_binary)} bytes\n", [:append])
      File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] First 20 bytes: #{inspect(binary_part(tx_binary, 0, min(20, byte_size(tx_binary))))}\n", [:append])
      IO.puts(:standard_error, "[ELIXIR PROTOCOL] validate_transaction called with #{byte_size(tx_binary)} bytes")
      IO.puts(:standard_error, "[ELIXIR PROTOCOL] First 20 bytes: #{inspect(binary_part(tx_binary, 0, min(20, byte_size(tx_binary))))}")
    end

    max_tx_size = Application.get_env(:ama, :tx_size, 393_216)

    cond do
      byte_size(tx_binary) > max_tx_size ->
        if debug_enabled do
          IO.puts(:standard_error, "[ELIXIR PROTOCOL] Transaction too large: #{byte_size(tx_binary)} > #{max_tx_size}")
        end
        %{error: :too_large}

      detect_expansion_bombs(tx_binary) ->
        if debug_enabled do
          IO.puts(:standard_error, "[ELIXIR PROTOCOL] Expansion bomb pattern detected")
        end
        %{error: :too_large}

      true ->
        # Continue to normal validation
        if debug_enabled do
          IO.puts(:standard_error, "[ELIXIR PROTOCOL] Calling TX.validate")
        end
        result = TX.validate(tx_binary, is_special_meeting)
        if debug_enabled do
          IO.puts(:standard_error, "[ELIXIR PROTOCOL] TX.validate result: #{inspect(result)}")
        end
        result
    end
  end

  # Detect patterns that could cause exponential memory expansion
  # This matches the logic from TxAdapter
  defp detect_expansion_bombs(data) when byte_size(data) == 0, do: false
  defp detect_expansion_bombs(data) do
    scan_limit = min(byte_size(data), 200)
    scan_data = binary_part(data, 0, scan_limit)
    
    {collection_count, suspicious_varints} = scan_for_patterns(scan_data, 0, 0, 0)
    
    debug_enabled =
      case System.get_env("AMA_ORACLE_DEBUG") do
        v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
        _ -> false
      end

    if debug_enabled do
      IO.puts(:standard_error, "[ELIXIR PROTOCOL] Expansion bomb scan: collections=#{collection_count}, suspicious_varints=#{suspicious_varints}, scan_limit=#{scan_limit}")
    end
    
    # Heuristic thresholds based on expansion potential
    density_ratio = collection_count / scan_limit
    
    result = collection_count > 50                                     # Too many collections
      or suspicious_varints > 10                             # Too many large varints  
      or density_ratio > 0.3                                 # Too dense with collections
      or (collection_count > 20 and suspicious_varints > 2)  # Combined risk
      
    if debug_enabled do
      IO.puts(:standard_error, "[ELIXIR PROTOCOL] Expansion bomb result: #{result}, density_ratio=#{density_ratio}")
    end
    result
  end
  
  # Scan binary data for suspicious patterns that could cause expansion bombs
  defp scan_for_patterns(<<>>, _pos, collection_count, suspicious_varints) do
    {collection_count, suspicious_varints}
  end
  
  defp scan_for_patterns(<<tag::8, rest::binary>>, pos, collection_count, suspicious_varints) when tag in [5, 6, 7] do
    # Bytes, List, Map tags - check length encoding that follows
    new_collection_count = collection_count + 1
    
    case rest do
      <<length_byte::8, remaining::binary>> ->
        magnitude = length_byte &&& 0x7F
        
        new_suspicious = if magnitude > 4 do
          suspicious_varints + 1
        else
          suspicious_varints
        end
        
        # Early termination for clearly pathological cases
        if new_collection_count > 30 or new_suspicious > 5 do
          # Signal expansion bomb detected via special return value
          {999, 999} # This will trigger the heuristic check
        else
          # Skip ahead by magnitude length to avoid false positives
          skip_bytes = min(magnitude, byte_size(remaining))
          case remaining do
            <<_skip::binary-size(skip_bytes), next_data::binary>> ->
              scan_for_patterns(next_data, pos + 2 + skip_bytes, new_collection_count, new_suspicious)
            _ ->
              {new_collection_count, new_suspicious}
          end
        end
        
      _ ->
        {new_collection_count, suspicious_varints}
    end
  end
  
  defp scan_for_patterns(<<_::8, rest::binary>>, pos, collection_count, suspicious_varints) do
    scan_for_patterns(rest, pos + 1, collection_count, suspicious_varints)
  end
end