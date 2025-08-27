defmodule ElixirRunner.Normalizer do
  @moduledoc """
  Normalizer for execution results to ensure consistent comparison
  between Rust and Elixir implementations.
  """

  defstruct []

  @type t :: %__MODULE__{}

  @doc """
  Initialize the normalizer.
  """
  def init do
    {:ok, %__MODULE__{}}
  end

  @doc """
  Compute a normalized digest from operation results.
  """
  def compute_digest(_normalizer, results) do
    # Use incremental hashing like Rust implementation
    initial_hash = :crypto.hash_init(:sha256)
    
    final_hash = Enum.reduce(results, initial_hash, fn result, hash_state ->
      case result do
        %{type: :protocol, data: data} ->
          # Match Rust format: "protocol:" + messages_count + canonical_digest
          # Ensure data is treated as pure binary, not UTF-8 string
          messages_count = Map.get(result, :messages_count, 1)
          
          # Ensure data is treated as raw binary, avoiding UTF-8 encoding  
          binary_data = case data do
            data when is_binary(data) -> data
            _ -> :crypto.hash(:sha256, :erlang.term_to_binary(data))
          end
          
          hash_state
          |> :crypto.hash_update(<<112, 114, 111, 116, 111, 99, 111, 108, 58>>)  # "protocol:" as explicit bytes
          |> :crypto.hash_update(<<messages_count::32-little>>)
          |> :crypto.hash_update(binary_data)
          
        %{type: :transaction, validation_result: code} ->
          # Match Rust format: "tx:" + validation_result
          hash_state
          |> :crypto.hash_update(<<116, 120, 58>>)  # "tx:" as explicit bytes
          |> :crypto.hash_update(<<code::64-little>>)
          
        %{type: :serialization, success: success} ->
          # Match Rust format: "serialize:" + success_byte
          success_byte = if success, do: <<1>>, else: <<0>>
          hash_state
          |> :crypto.hash_update(<<115, 101, 114, 105, 97, 108, 105, 122, 101, 58>>)  # "serialize:" as explicit bytes
          |> :crypto.hash_update(success_byte)
          
        _ ->
          # Unknown result type, skip
          hash_state
      end
    end)
    
    :crypto.hash_final(final_hash)
  end

  @doc """
  Serialize execution result for transmission back to fuzzer.
  """
  def serialize_result(result) do
    # Send result in extended binary format for easy parsing:
    # [ops_executed: 4 bytes big-endian] + [digest: 32 bytes SHA256] + 
    # [duration_us: 8 bytes big-endian] + [messages_processed: 4 bytes big-endian] +
    # [transactions_processed: 4 bytes big-endian]
    # Total: 52 bytes (was 36 bytes)
    
    ops_executed = Map.get(result, :ops_executed, 0)
    digest = Map.get(result, :digest, :crypto.strong_rand_bytes(32))
    
    # Ensure digest is exactly 32 bytes (SHA256)
    digest_bytes = if byte_size(digest) == 32, do: digest, else: :crypto.hash(:sha256, digest)
    
    # Extract metrics
    metrics = Map.get(result, :metrics, %{})
    duration_us = Map.get(metrics, :duration_us, 0)
    messages_processed = Map.get(metrics, :messages_processed, 0)
    transactions_processed = Map.get(metrics, :transactions_processed, 0)
    
    <<ops_executed::32-unsigned-big, 
      digest_bytes::binary,
      duration_us::64-unsigned-big,
      messages_processed::32-unsigned-big,
      transactions_processed::32-unsigned-big>>
  end

  # Normalize a single operation result for consistent hashing
  defp normalize_result(%{type: :protocol, operation: op, data: data}) do
    # Data should already be a canonical digest (32-byte SHA256), use it directly
    if byte_size(data) == 32 do
      "protocol:#{op}:#{Base.encode16(data)}"
    else
      # Fallback: hash the data if it's not already a canonical digest
      data_hash = :crypto.hash(:sha256, data)
      "protocol:#{op}:#{Base.encode16(data_hash)}"
    end
  end

  defp normalize_result(%{type: :transaction, validation_result: code}) do
    "tx:#{code}"
  end

  defp normalize_result(%{type: :serialization, msg_type: msg_type, success: success}) do
    "serialize:#{msg_type}:#{if success, do: 1, else: 0}"
  end

  defp normalize_result(result) do
    # Fallback for unknown result types
    result_hash = :crypto.hash(:sha256, :erlang.term_to_binary(result))
    "unknown:#{Base.encode16(result_hash)}"
  end
end