defmodule ElixirRunner.CLI do
  @moduledoc """
  Command-line interface for the Elixir oracle runner.
  
  This escript runs as a persistent process that receives binary traces
  via stdin and returns execution results via stdout.
  """

  alias ElixirRunner.{TraceParser, TraceExecutor, Normalizer}
  
  def main(args) do
    # Set up error handling to prevent crashes from killing the fuzzer
    Process.flag(:trap_exit, true)
    
    # Parse command line arguments
    case parse_args(args) do
      {:ok, opts} ->
        run_oracle(opts)
      {:error, reason} ->
        IO.puts(:stderr, "Error: #{reason}")
        print_usage()
        System.halt(1)
    end
  end
  
  defp parse_args([]), do: {:ok, %{mode: :oracle}}
  defp parse_args(["--help"]), do: {:error, "help"}
  defp parse_args(["--version"]), do: {:error, "version"}  
  defp parse_args(["--test-mode"]), do: {:ok, %{mode: :test}}
  defp parse_args(_), do: {:error, "invalid arguments"}
  
  defp print_usage do
    IO.puts("""
    Elixir Oracle Runner for Amadeus Node Differential Fuzzing
    
    Usage:
      elixir_runner                 Run in oracle mode (stdin/stdout)
      elixir_runner --test-mode     Run basic self-test
      elixir_runner --help          Show this help
      elixir_runner --version       Show version
      
    Oracle Mode:
      Reads length-prefixed binary traces from stdin and writes
      length-prefixed results to stdout. Used by the Rust fuzzer.
      
    Protocol:
      Input:  [u32: length][binary: trace]
      Output: [u32: length][binary: result] | [u32: 0] (error)
    """)
  end
  
  defp run_oracle(%{mode: :test}) do
    IO.puts("Running self-test...")
    
    case run_self_test() do
      :ok ->
        IO.puts("Self-test passed!")
        System.halt(0)
      {:error, reason} ->
        IO.puts("Self-test failed: #{reason}")
        System.halt(1)
    end
  end
  
  defp run_oracle(%{mode: :oracle}) do
    IO.puts(:stderr, "Elixir oracle starting...")
    
    # Initialize the executor
    case TraceExecutor.init() do
      {:ok, executor} ->
        oracle_loop(executor)
      {:error, reason} ->
        IO.puts(:stderr, "Failed to initialize executor: #{reason}")
        System.halt(1)
    end
  end
  
  defp oracle_loop(executor) do
    case read_trace() do
      {:ok, trace_binary} ->
        result = execute_trace_safe(executor, trace_binary)
        write_result(result)
        oracle_loop(executor) # Continue the loop
        
      {:error, :eof} ->
        IO.puts(:stderr, "Oracle received EOF, shutting down")
        System.halt(0)
        
      {:error, reason} ->
        IO.puts(:stderr, "Oracle error: #{reason}")
        write_result({:error, "read_error"})
        oracle_loop(executor) # Try to continue
    end
  end
  
  defp read_trace do
    case IO.binread(:stdio, 4) do
      :eof -> 
        {:error, :eof}
        
      <<length::32-unsigned-big>> ->
        case IO.binread(:stdio, length) do
          :eof -> 
            {:error, :unexpected_eof}
          data when byte_size(data) == length ->
            {:ok, data}
          data ->
            {:error, "incomplete_read: expected #{length}, got #{byte_size(data)}"}
        end
        
      data when is_binary(data) ->
        {:error, "invalid_length_header: got #{byte_size(data)} bytes"}
        
      other ->
        {:error, "read_failed: #{inspect(other)}"}
    end
  end
  
  defp write_result({:ok, result_binary}) do
    length = byte_size(result_binary)
    IO.binwrite(:stdio, <<length::32-unsigned-big>>)
    IO.binwrite(:stdio, result_binary)
  end
  
  defp write_result({:error, _reason}) do
    # Write zero-length to indicate error
    IO.binwrite(:stdio, <<0::32-unsigned-big>>)
  end
  
  defp execute_trace_safe(executor, trace_binary) do
    try do
      case TraceParser.parse(trace_binary) do
        {:ok, trace} ->
          case TraceExecutor.execute(executor, trace) do
            {:ok, result} ->
              result_binary = Normalizer.serialize_result(result)
              {:ok, result_binary}
            {:error, reason} ->
              {:error, reason}
          end
        {:error, reason} ->
          {:error, "parse_error: #{reason}"}
      end
    rescue
      e ->
        {:error, "exception: #{Exception.message(e)}"}
    catch
      :throw, value ->
        {:error, "throw: #{inspect(value)}"}
      :exit, reason ->
        {:error, "exit: #{inspect(reason)}"}
    end
  end
  
  defp run_self_test do
    # Test basic functionality
    case TraceExecutor.init() do
      {:ok, executor} ->
        # Create a simple test trace
        test_trace = %{
          seed: 12345,
          ops: [
            %{type: :ping, temporal_height: 100, temporal_slot: 50, 
              rooted_height: 90, rooted_slot: 45, timestamp_ms: 1700000000000}
          ]
        }
        
        case TraceExecutor.execute(executor, test_trace) do
          {:ok, _result} -> :ok
          {:error, reason} -> {:error, "execution_failed: #{reason}"}
        end
      {:error, reason} ->
        {:error, "init_failed: #{reason}"}
    end
  end
end