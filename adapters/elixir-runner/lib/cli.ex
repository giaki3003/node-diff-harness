defmodule ElixirRunner.CLI do
  @moduledoc """
  Command-line interface for the Elixir oracle runner.
  
  This escript runs as a persistent process that receives binary traces
  via stdin and returns execution results via stdout.
  """

  alias ElixirRunner.{TraceParser, TraceExecutor, Normalizer}
  
  def main(args) do
    # CRITICAL: Force stdio to binary mode to prevent UTF-8 encoding corruption
    :io.setopts(:stdio, [:binary, {:encoding, :latin1}])
    
    
    # Set up comprehensive error handling to prevent stdout corruption
    Process.flag(:trap_exit, true)
    
    try do
      # Parse command line arguments
      case parse_args(args) do
        {:ok, opts} ->
          out_io = open_result_io()
          run_oracle_safe(opts, out_io)
        {:error, reason} ->
          IO.puts(:stderr, "Error: #{reason}")
          print_usage()
          System.halt(1)
      end
    catch
      kind, error ->
        IO.puts(:stderr, "Startup error: #{kind} - #{inspect(error)}")
        System.halt(1)
    end
  end
  
  defp open_result_io do
    case System.get_env("AMA_RESULT_FD") do
      nil ->
        :standard_io
      fd_str ->
        fd = String.to_integer(fd_str)
        # Use /proc/self/fd/N approach which works reliably with Elixir
        fd_path = "/proc/self/fd/#{fd}"
        case :file.open(fd_path, [:raw, :binary, :write]) do
          {:ok, io} ->
            io
          {:error, _reason} ->
            :standard_io
        end
    end
  end
  
  defp parse_args([]), do: {:ok, %{mode: :oracle}}
  defp parse_args(["--help"]), do: {:error, "help"}
  defp parse_args(["--version"]), do: {:error, "version"}  
  defp parse_args(["--test-mode"]), do: {:ok, %{mode: :test}}
  defp parse_args(_), do: {:error, "invalid arguments"}
  
  defp print_usage do
    IO.puts(:stderr, """
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
  
  defp run_oracle_safe(%{mode: :test}, _out_io) do
    IO.puts("Running self-test...")
    
    case run_self_test() do
      :ok ->
        IO.puts("Self-test passed!")
        System.halt(0)
      {:error, reason} ->
        IO.puts(:stderr, "Self-test failed: #{reason}")
        System.halt(1)
    end
  end
  
  defp run_oracle_safe(%{mode: :oracle}, out_io) do
    # CRITICAL: Force binary mode AGAIN immediately when entering oracle mode
    :io.setopts(:stdio, [:binary, {:encoding, :latin1}])
    :io.setopts(:standard_io, [:binary, {:encoding, :latin1}])
    
    # LAYER 2: Configure Logger to prevent any stdout pollution before starting applications
    Logger.configure(level: :error)
    Application.put_env(:logger, :handle_otp_reports, false)
    Application.put_env(:logger, :handle_sasl_reports, false)
    # Ensure console backend writes to stderr (not stdout)
    :ok = Logger.configure_backend(:console, device: :standard_error)
    
    # LAYER 3: Global stdout redirection - redirect ALL stdout to stderr during ama startup
    original_stdout = Process.whereis(:standard_io)
    original_stderr = Process.whereis(:standard_error) 
    if original_stdout && original_stderr do
      # Temporarily redirect stdout to stderr
      Process.unregister(:standard_io)
      Process.register(original_stderr, :standard_io)
    end
    
    IO.puts(:stderr, "Elixir oracle starting with stdout redirection...")
    
    # LAYER 4: Minimal bootstrapping - bypass ama application entirely
    case minimal_init_executor() do
      {:ok, executor} ->
        # LAYER 3: Restore stdout for binary protocol after minimal startup
        if original_stdout && original_stderr do
          Process.unregister(:standard_io)  
          Process.register(original_stdout, :standard_io)
        end
        
        IO.puts(:stderr, "Oracle initialized with minimal bootstrapping - no ama app startup")
        oracle_loop_safe(executor, out_io)
      {:error, reason} ->
        IO.puts(:stderr, "Minimal initialization failed: #{reason}")
        # Even in minimal failure, handle gracefully
        oracle_error_loop("minimal_init_failed: #{reason}", out_io)
    end
  end
  
  # LAYER 4: Minimal initialization that completely bypasses ama application
  defp minimal_init_executor do
    try do
      # LAYER 4: Set up ONLY the essential application environment variables needed for trace processing  
      # This avoids Application.ensure_all_started(:ama) and its IO.puts statements
      # but ensures all required config is present
      
      setup_minimal_config_only()
      
      case ElixirRunner.TraceExecutor.init() do
        {:ok, executor} -> 
          {:ok, executor}
        {:error, reason} -> 
          {:error, "trace_executor_init_failed: #{reason}"}
      end
    rescue
      e -> {:error, "minimal_init_exception: #{Exception.message(e)}"}
    end
  end
  
  # LAYER 4: Setup minimal configuration ONLY - no application startup, no IO.puts
  defp setup_minimal_config_only do
    # Set work_folder to a temporary location for oracle operation
    work_folder = System.tmp_dir!() |> Path.join("oracle_workdir")
    File.mkdir_p!(work_folder)
    
    # ESSENTIAL configurations from config/config.exs that trace processing requires
    Application.put_env(:ama, :work_folder, work_folder)
    Application.put_env(:ama, :version, "1.0.0-oracle")
    Application.put_env(:ama, :offline, true)
    Application.put_env(:ama, :autoupdate, false)
    Application.put_env(:ama, :snapshot_height, 0)
    
    # CRITICAL: Size configurations that ProcessTx validation requires
    Application.put_env(:ama, :entry_size, 524288)
    Application.put_env(:ama, :tx_size, 393216)        # This was missing and caused the error!
    Application.put_env(:ama, :attestation_size, 512)
    Application.put_env(:ama, :quorum, 3)
    
    # Set up minimal trainer key for any operations that need it
    mock_trainer_pk = :binary.copy(<<0x42>>, 48)
    Application.put_env(:ama, :trainer_pk, mock_trainer_pk)
    
    # Network configurations (set to safe defaults for oracle)
    Application.put_env(:ama, :http_ipv4, {0,0,0,0})   # Disable HTTP
    Application.put_env(:ama, :udp_ipv4_tuple, {0,0,0,0})  # Disable UDP
    Application.put_env(:ama, :udp_port, 0)            # Disable UDP
    
    # NOTE: NO Application.ensure_all_started(:ama) - this prevents IO.puts pollution!
  end
  
  # Safe initialization that tries to avoid full application startup
  defp safe_init_executor do
    try do
      # Set up minimal application configuration before any ama code runs
      ensure_minimal_ama_config()
      
      # Try to initialize without starting the full :ama application
      TraceExecutor.init()
    catch
      kind, error ->
        {:error, "safe_init_failed: #{kind} - #{inspect(error)}"}
    end
  end
  
  # Ensure minimal ama application configuration is available
  defp ensure_minimal_ama_config do
    # Set work_folder to a temporary location for oracle operation
    work_folder = System.tmp_dir!() |> Path.join("oracle_workdir")
    File.mkdir_p!(work_folder)
    
    # Core configuration from config/config.exs
    Application.put_env(:ama, :work_folder, work_folder)
    Application.put_env(:ama, :version, "1.0.0-oracle")
    Application.put_env(:ama, :offline, true)
    Application.put_env(:ama, :autoupdate, false)
    Application.put_env(:ama, :snapshot_height, 0)
    
    # Size configurations from config/config.exs
    Application.put_env(:ama, :entry_size, 524288)
    Application.put_env(:ama, :tx_size, 393216)
    Application.put_env(:ama, :attestation_size, 512)
    Application.put_env(:ama, :quorum, 3)
    
    # CRITICAL: Start the ama application - stdout already redirected to stderr globally
    start_result = Application.ensure_all_started(:ama)
    
    case start_result do
      {:ok, apps} -> 
        IO.puts(:stderr, "Oracle ama application started successfully: #{inspect(apps)}")
      {:error, reason} ->
        IO.puts(:stderr, "Warning: ama application start failed: #{inspect(reason)}")
    end
    
    # Verify application is running
    ama_status = Application.started_applications() |> Enum.find(fn {app, _, _} -> app == :ama end)
    IO.puts(:stderr, "AMA application status: #{inspect(ama_status)}")
    
    IO.puts(:stderr, "Oracle configured with work_folder: #{work_folder}")
  end
  
  # Fallback initialization with minimal dependencies  
  defp fallback_init_executor do
    try do
      # Create a minimal executor that doesn't depend on the full application
      {:ok, %{
        mode: :minimal,
        error_message: "running_in_minimal_mode"
      }}
    catch
      kind, error ->
        {:error, "fallback_init_failed: #{kind} - #{inspect(error)}"}
    end
  end
  
  # Enhanced oracle loop with better error handling
  defp oracle_loop_safe(executor, out_io) do
    
    try do
      case read_trace_safe() do
        {:ok, trace_binary} ->
          result = execute_trace_safe(executor, trace_binary)
          write_result_safe(result, out_io)
          oracle_loop_safe(executor, out_io) # Continue the loop
          
        {:error, :eof} ->
          IO.puts(:stderr, "Oracle received EOF, shutting down")
          System.halt(0)
          
        {:error, reason} ->
          write_result_safe({:error, "read_error: #{reason}"}, out_io)
          oracle_loop_safe(executor, out_io) # Try to continue
      end
    catch
      kind, error ->
        IO.puts(:stderr, "Oracle loop error: #{kind} - #{inspect(error)}")
        write_result_safe({:error, "loop_error: #{kind}"}, out_io)
        oracle_loop_safe(executor, out_io) # Try to continue even after errors
    end
  end
  
  # Error-only loop that maintains protocol but always returns errors
  defp oracle_error_loop(error_message, out_io) do
    IO.puts(:stderr, "Oracle running in error-only mode: #{error_message}")
    
    try do
      case read_trace_safe() do
        {:ok, _trace_binary} ->
          # Always return an error response but maintain protocol
          write_result_safe({:error, error_message}, out_io)
          oracle_error_loop(error_message, out_io) # Continue the loop
          
        {:error, :eof} ->
          IO.puts(:stderr, "Oracle received EOF, shutting down")
          System.halt(0)
          
        {:error, reason} ->
          IO.puts(:stderr, "Oracle read error in error mode: #{reason}")
          write_result_safe({:error, "#{error_message}+read_error"}, out_io)
          oracle_error_loop(error_message, out_io) # Try to continue
      end
    catch
      kind, error ->
        IO.puts(:stderr, "Error loop crashed: #{kind} - #{inspect(error)}")
        # Even the error loop crashed, but we need to keep the protocol alive
        write_result_safe({:error, "error_loop_crashed"}, out_io)
        oracle_error_loop("error_loop_crashed", out_io) # Keep trying
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
  
  # Safe trace reading with timeout and better error handling
  defp read_trace_safe do
    try do
      # Add timeout to prevent hanging
      task = Task.async(fn -> read_trace_inner() end)
      case Task.yield(task, 5000) || Task.shutdown(task) do
        {:ok, result} -> result
        nil -> {:error, "read_timeout"}
      end
    catch
      kind, error ->
        {:error, "read_exception: #{kind} - #{inspect(error)}"}
    end
  end
  
  defp read_trace_inner do
    case read_exact_bytes(4) do
      {:ok, length_bytes} ->
        case length_bytes do
          <<length::32-unsigned-big>> when length <= 1_000_000 ->
            # Reasonable size limit to prevent memory exhaustion
            case read_exact_bytes(length) do
              {:ok, data} ->
                
                # Validate that the data makes sense (basic corruption check)
                if validate_trace_data(data) do
                  {:ok, data}
                else
                  {:error, "corrupted_trace_data"}
                end
              {:error, :eof} ->
                {:error, :eof}  # Preserve EOF for proper handling
              {:error, reason} ->
                {:error, "read_data_failed: #{reason}"}
            end
            
          <<length::32-unsigned-big>> when length > 1_000_000 ->
            {:error, "request_too_large: #{length} bytes"}
            
          <<invalid::32-unsigned-big>> ->
            {:error, "invalid_length: #{invalid}"}
        end
        
      {:error, :eof} ->
        {:error, :eof}  # Preserve EOF for proper handling
      {:error, reason} ->
        {:error, "read_length_failed: #{reason}"}
    end
  end
  
  # Read exactly N bytes with validation and potential recovery
  defp read_exact_bytes(0), do: {:ok, <<>>}  # Handle zero-length reads gracefully
  defp read_exact_bytes(n) when n > 0 do
    case read_exact_bytes_inner(n, <<>>, 3) do
      {:ok, data} -> {:ok, data}
      {:error, :eof} -> 
        # EOF should propagate directly without recovery attempts
        {:error, :eof}
      {:error, reason} -> 
        IO.puts(:stderr, "Read failed: #{reason}, attempting protocol recovery")
        case attempt_protocol_recovery() do
          :failed -> {:error, :eof}  # If recovery fails, treat as EOF
          :recovered -> {:error, "recovered_but_data_lost"}
        end
    end
  end
  
  defp read_exact_bytes_inner(0, acc, _retries), do: {:ok, acc}
  defp read_exact_bytes_inner(n, acc, 0), do: {:error, "max_retries_exceeded: need #{n} more bytes"}
  defp read_exact_bytes_inner(n, acc, retries) do
    case IO.binread(:stdio, n) do
      :eof ->
        {:error, :eof}
      data when is_binary(data) ->
        received = byte_size(data)
        cond do
          received == n ->
            {:ok, acc <> data}
          received < n ->
            # Partial read - try to get remaining bytes
            read_exact_bytes_inner(n - received, acc <> data, retries - 1)
          true ->
            # Somehow got more bytes than expected - protocol corruption
            {:error, "protocol_corruption: expected #{n}, got #{received}"}
        end
      other ->
        {:error, "read_failed: #{inspect(other)}"}
    end
  end
  
  # Basic validation to detect obvious corruption
  defp validate_trace_data(data) do
    cond do
      byte_size(data) == 0 -> false
      byte_size(data) > 1_000_000 -> false
      # Check for reasonable JSON-like structure (starts with { and has basic structure)
      String.starts_with?(data, "{") and String.contains?(data, "seed") -> true
      # Could be binary serialized data - just check it's not all zeros or all 0xFF
      data != <<0>> and data != String.duplicate(<<255>>, byte_size(data)) -> true
      true -> false
    end
  end
  
  # Attempt to recover from protocol desynchronization
  defp attempt_protocol_recovery do
    # Try to find a valid length header in the next few bytes
    recovery_attempt(0, 10)
  end
  
  defp recovery_attempt(attempts, max_attempts) when attempts >= max_attempts do
    :failed
  end
  
  defp recovery_attempt(attempts, max_attempts) do
    case IO.binread(:stdio, 1) do
      :eof ->
        :failed
      <<byte>> ->
        # Try to read 3 more bytes to form a potential length header
        case IO.binread(:stdio, 3) do
          :eof -> 
            :failed
          <<b1, b2, b3>> ->
            potential_length = <<byte, b1, b2, b3>>
            case potential_length do
              <<length::32-unsigned-big>> when length > 0 and length <= 1_000_000 ->
                :recovered
              _ ->
                recovery_attempt(attempts + 1, max_attempts)
            end
          _ ->
            recovery_attempt(attempts + 1, max_attempts)
        end
      _ ->
        recovery_attempt(attempts + 1, max_attempts)
    end
  end
  
  # Safe result writing that never fails with validation
  defp write_result_safe(result, out_io) do
    try do
      case result do
        {:ok, result_binary} when is_binary(result_binary) ->
          write_binary_response(out_io, result_binary)
          
        {:error, _reason} ->
          # Write zero-length to indicate error
          write_error_response(out_io)
          
        _other ->
          # Unexpected result format - treat as error
          write_error_response(out_io)
      end
    catch
      kind, error ->
        # Even writing failed - try to write a basic error response
        IO.puts(:stderr, "Write failed: #{kind} - #{inspect(error)}")
        write_error_response_fallback(out_io)
    end
  end
  
  defp write_binary_response(out_io, result_binary) do
    length = byte_size(result_binary)
    
    # Validate response before writing
    if length > 10_000_000 do
      write_error_response(out_io)
    else
      # Create the complete message first (atomic approach)
      length_header = <<length::32-unsigned-big>>
      complete_response = length_header <> result_binary
      
      case write_exact_bytes(out_io, complete_response) do
        :ok ->
          # Validate write completed successfully
          sync_result_io(out_io)
        :error ->
          nil
      end
    end
  end
  
  defp sync_result_io(:standard_io), do: :file.datasync(:standard_io)
  defp sync_result_io(io), do: :file.datasync(io)
  
  defp write_error_response(out_io) do
    case write_exact_bytes(out_io, <<0::32-unsigned-big>>) do
      :ok -> 
        sync_result_io(out_io)
      :error -> 
        IO.puts(:stderr, "Failed to write error response")
    end
  end
  
  defp write_error_response_fallback(out_io) do
    try do
      case out_io do
        :standard_io -> 
          IO.binwrite(:stdio, <<0::32-unsigned-big>>)
          :file.datasync(:standard_io)
        io ->
          :file.write(io, <<0::32-unsigned-big>>)
          :file.datasync(io)
      end
    catch
      _, _ -> 
        # Complete I/O failure - nothing we can do
        IO.puts(:stderr, "Complete I/O failure - oracle may be unusable")
    end
  end
  
  # Write bytes with error handling
  defp write_exact_bytes(out_io, data) do
    try do
      case out_io do
        :standard_io ->
          # FORCE binary mode again before every write to ensure it sticks
          :io.setopts(:stdio, [:binary, {:encoding, :latin1}])
          :io.setopts(:standard_io, [:binary, {:encoding, :latin1}])
          
          # Try direct file writing to bypass encoding layers
          case :file.write(:standard_io, data) do
            :ok -> 
              # Force flush and sync to ensure data is written atomically
              :file.datasync(:standard_io)
              :ok
            {:error, _reason} ->
              # Fallback to IO.binwrite
              case IO.binwrite(:stdio, data) do
                :ok -> 
                  :file.datasync(:standard_io)
                  :ok
                {:error, _fallback_reason} ->
                  :error
              end
          end
        
        io ->
          # Write to FD 3 using :file.write
          case :file.write(io, data) do
            :ok ->
              :file.datasync(io)
              :ok
            {:error, _reason} ->
              :error
          end
      end
    catch
      _kind, _error ->
        :error
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
      case executor do
        %{mode: :minimal, error_message: msg} ->
          {:error, msg}
        
        _ ->
          # Add timeout to prevent hanging on problematic traces
          task = Task.async(fn -> execute_trace_with_timeout(executor, trace_binary) end)
          case Task.yield(task, 10000) || Task.shutdown(task, :brutal_kill) do
            {:ok, result} -> 
              result
            nil -> 
              {:error, "execution_timeout"}
          end
      end
    rescue
      e ->
        {:error, "exception: #{Exception.message(e)}"}
    catch
      :throw, value ->
        {:error, "throw: #{inspect(value)}"}
      :exit, reason ->
        {:error, "exit: #{inspect(reason)}"}
      kind, error ->
        {:error, "unexpected_error: #{kind} - #{inspect(error)}"}
    end
  end
  
  defp execute_trace_with_timeout(executor, trace_binary) do
    case TraceParser.parse(trace_binary) do
      {:ok, trace} ->
        # CRITICAL: Protect stdout from any application pollution
        result = with_protected_stdout(fn ->
          case TraceExecutor.execute(executor, trace) do
            {:ok, result} ->
              case safe_serialize_result(result) do
                {:ok, result_binary} -> {:ok, result_binary}
                {:error, reason} -> {:error, "serialization_failed: #{reason}"}
              end
            {:error, reason} ->
              {:error, "execution_failed: #{reason}"}
          end
        end)
        
        result
        
      {:error, reason} ->
        {:error, "parse_error: #{reason}"}
    end
  end
  
  # Protect stdout from any pollution during execution
  # Rebind :standard_io to :standard_error while running `fun` so any accidental prints
  # from libraries or application code cannot corrupt the stdout binary protocol.
  defp with_protected_stdout(fun) do
    original_stdout = Process.whereis(:standard_io)
    original_stderr = Process.whereis(:standard_error)

    try do
      if original_stdout && original_stderr do
        # Redirect all stdout to stderr
        Process.unregister(:standard_io)
        Process.register(original_stderr, :standard_io)
      end

      fun.()
    catch
      kind, _error ->
        {:error, "protected_execution_failed: #{kind}"}
    after
      # Restore original stdout binding
      if original_stdout && original_stderr do
        Process.unregister(:standard_io)
        Process.register(original_stdout, :standard_io)
      end
    end
  end
  
  defp safe_serialize_result(result) do
    try do
      result_binary = Normalizer.serialize_result(result)
      {:ok, result_binary}
    rescue
      e ->
        {:error, "serialization_exception: #{Exception.message(e)}"}
    catch
      kind, error ->
        {:error, "serialization_error: #{kind} - #{inspect(error)}"}
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