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
    # Build exact input bytes for hashing (for parity with Rust and debug visibility)
    bytes =
      Enum.reduce(results, <<>>, fn result, acc ->
        case result do
          %{type: :protocol, data: data} ->
            messages_count = Map.get(result, :messages_count, 1)

            binary_data =
              case data do
                bin when is_binary(bin) -> bin
                other -> :crypto.hash(:sha256, :erlang.term_to_binary(other))
              end

            acc <>
              "protocol:" <>
              <<messages_count::32-little>> <>
              binary_data

          %{type: :transaction, validation_result: code} ->
            acc <>
              "tx:" <>
              <<code::32-little>>

          %{type: :serialization, success: success} ->
            acc <>
              "serialize:" <>
              <<(if success, do: 1, else: 0)>>

          _ ->
            acc
        end
      end)

    debug_enabled =
      case System.get_env("AMA_ORACLE_DEBUG") do
        v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
        _ -> false
      end

    if debug_enabled do
      IO.puts(:standard_error, "[ELIXIR] Trace digest input bytes: #{inspect(bytes)}")
      IO.puts(:standard_error, "[ELIXIR] Trace digest input hex: #{Base.encode16(bytes, case: :lower)}")
    end

    digest = :crypto.hash(:sha256, bytes)

    if debug_enabled do
      IO.puts(:standard_error, "[ELIXIR] Final trace digest hex: #{Base.encode16(digest, case: :lower)}")
    end

    digest
  end

  @doc """
  Serialize execution result for transmission back to fuzzer.
  """
  def serialize_result(result) do
    ops_executed = Map.get(result, :ops_executed, 0)
    digest = Map.get(result, :digest, :crypto.strong_rand_bytes(32))
    
    digest_bytes = if byte_size(digest) == 32, do: digest, else: :crypto.hash(:sha256, digest)
    
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

  defp normalize_result(%{type: :protocol, operation: op, data: data}) do
    if byte_size(data) == 32 do
      "protocol:#{op}:#{Base.encode16(data)}"
    else
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
    result_hash = :crypto.hash(:sha256, :erlang.term_to_binary(result))
    "unknown:#{Base.encode16(result_hash)}"
  end
end