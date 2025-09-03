defmodule ElixirRunner.TraceExecutor do
  @moduledoc """
  Executes traces on the Elixir node implementation.
  
  This module interfaces with the actual Elixir node code to execute
  protocol operations and transaction validations.
  """

  alias ElixirRunner.{ProtocolAdapter, TxAdapter, Normalizer}

  defstruct [
    :protocol_adapter,
    :tx_adapter,
    :normalizer,
    :seed
  ]

  @type t :: %__MODULE__{
    protocol_adapter: ProtocolAdapter.t(),
    tx_adapter: TxAdapter.t(),
    normalizer: Normalizer.t(),
    seed: integer()
  }

  @doc """
  Initialize a new trace executor.
  """
  def init do
    try do
      with {:ok, protocol_adapter} <- ProtocolAdapter.init(),
           {:ok, tx_adapter} <- TxAdapter.init(),
           {:ok, normalizer} <- Normalizer.init() do
        executor = %__MODULE__{
          protocol_adapter: protocol_adapter,
          tx_adapter: tx_adapter,
          normalizer: normalizer,
          seed: 0
        }
        {:ok, executor}
      else
        {:error, reason} -> {:error, reason}
      end
    rescue
      e -> {:error, "init_exception: #{Exception.message(e)}"}
    end
  end

  @doc """
  Execute a parsed trace and return normalized results.
  """
  def execute(executor, trace) do
    try do
      :rand.seed(:exsss, {trace.seed, trace.seed + 1, trace.seed + 2})
      
      updated_executor = %{executor | seed: trace.seed}
      
      {duration_us, result} = :timer.tc(fn ->
        execute_operations(updated_executor, trace.ops, [])
      end)
      case result do
        {:ok, result_map} ->
          updated_metrics = %{result_map.metrics | duration_us: duration_us}
          {:ok, %{result_map | metrics: updated_metrics}}
        error ->
          error
      end
    rescue
      e -> {:error, "execute_exception: #{Exception.message(e)}"}
    catch
      :throw, reason -> {:error, "throw: #{inspect(reason)}"}
      :exit, reason -> {:error, "exit: #{inspect(reason)}"}
    end
  end

  defp execute_operations(executor, [], results) do
    # Reverse results to maintain chronological order (results were prepended during accumulation)
    reversed_results = Enum.reverse(results)
    
    debug_enabled = case System.get_env("AMA_ORACLE_DEBUG") do
      v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
      _ -> false
    end
    
    if debug_enabled do
      File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Final operations for digest:\n", [:append])
      Enum.with_index(reversed_results, fn result, index ->
        File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Op #{index}: #{inspect(result)}\n", [:append])
      end)
      File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Total operations: #{length(results)}\n", [:append])
    end
    
    digest = Normalizer.compute_digest(executor.normalizer, reversed_results)
    
    {:ok, %{
      digest: digest,
      ops_executed: length(results),
      error: nil,
      metrics: %{
        duration_us: 0,
        memory_bytes: nil,
        messages_processed: count_messages(results),
        transactions_processed: count_transactions(results)
      }
    }}
  end

  defp execute_operations(executor, [op | remaining_ops], results) do
    debug_enabled = case System.get_env("AMA_ORACLE_DEBUG") do
      v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
      _ -> false
    end
    
    case execute_single_operation(executor, op) do
      {:ok, %{type: :noop}} ->
        if debug_enabled do
          File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Skipping noop operation: #{inspect(op)}\n", [:append])
        end
        execute_operations(executor, remaining_ops, results)

      {:ok, result} ->
        if debug_enabled do
          File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Adding operation to results: #{inspect(op)} -> #{inspect(result)}\n", [:append])
        end
        execute_operations(executor, remaining_ops, [result | results])

      {:error, reason} ->
        # Reverse results to maintain chronological order (results were prepended during accumulation)
        digest = Normalizer.compute_digest(executor.normalizer, Enum.reverse(results))

        {:ok,
         %{
           digest: digest,
           ops_executed: length(results),
           error: reason,
           metrics: %{
             duration_us: 0,
             memory_bytes: nil,
             messages_processed: count_messages(results),
             transactions_processed: count_transactions(results)
           }
         }}
    end
  end

  defp execute_single_operation(executor, %{type: :ping} = op) do
    ProtocolAdapter.handle_ping(executor.protocol_adapter, op)
  end

  defp execute_single_operation(executor, %{type: :txpool} = op) do
    ProtocolAdapter.handle_txpool(executor.protocol_adapter, op)
  end

  defp execute_single_operation(executor, %{type: :peers} = op) do
    ProtocolAdapter.handle_peers(executor.protocol_adapter, op)
  end

  defp execute_single_operation(executor, %{type: :peers_v2} = op) do
    ProtocolAdapter.handle_peers_v2(executor.protocol_adapter, op)
  end

  defp execute_single_operation(executor, %{type: :process_tx} = op) do
    TxAdapter.validate_transaction(executor.tx_adapter, op)
  end

  defp execute_single_operation(executor, %{type: :serialize_message} = op) do
    msg_type = Map.get(op, :msg_type)
    payload = Map.get(op, :payload, [])

    is_empty =
      cond do
        is_list(payload) and payload == [] -> true
        is_binary(payload) and byte_size(payload) == 0 -> true
        true -> false
      end

    if is_empty and msg_type in [:ping, "Ping"] do
      {:ok, %{type: :noop}}
    else
      ProtocolAdapter.test_serialization(executor.protocol_adapter, op)
    end
  end

  defp execute_single_operation(_executor, %{type: :unknown}) do
    {:error, "unknown_operation"}
  end

  defp execute_single_operation(_executor, op) do
    {:error, "unhandled_operation: #{inspect(op)}"}
  end

  defp count_messages(results) do
    Enum.count(results, fn
      %{type: :protocol} -> true
      _ -> false
    end)
  end

  defp count_transactions(results) do
    Enum.count(results, fn
      %{type: :transaction} -> true
      _ -> false
    end)
  end
end