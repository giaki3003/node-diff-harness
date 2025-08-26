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
      
      # Set deterministic seed for reproducible results
      :rand.seed(:exsss, {trace.seed, trace.seed + 1, trace.seed + 2})
      
      updated_executor = %{executor | seed: trace.seed}
      
      execute_operations(updated_executor, trace.ops, [])
    rescue
      e -> {:error, "execute_exception: #{Exception.message(e)}"}
    catch
      :throw, reason -> {:error, "throw: #{inspect(reason)}"}
      :exit, reason -> {:error, "exit: #{inspect(reason)}"}
    end
  end

  defp execute_operations(executor, [], results) do
    # All operations completed successfully
    
    digest = Normalizer.compute_digest(executor.normalizer, results)
    
    {:ok, %{
      digest: digest,
      ops_executed: length(results),
      error: nil,
      metrics: %{
        duration_us: 0, # Not implemented yet
        memory_bytes: nil,
        messages_processed: count_messages(results),
        transactions_processed: count_transactions(results)
      }
    }}
  end

  defp execute_operations(executor, [op | remaining_ops], results) do
    
    case execute_single_operation(executor, op) do
      {:ok, result} ->
        execute_operations(executor, remaining_ops, [result | results])
      {:error, reason} ->
        # Return partial results with error
        digest = Normalizer.compute_digest(executor.normalizer, results)
        
        {:ok, %{
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
    ProtocolAdapter.test_serialization(executor.protocol_adapter, op)
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
      %{type: :serialization} -> true
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