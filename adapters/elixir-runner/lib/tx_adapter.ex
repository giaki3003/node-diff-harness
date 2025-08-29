defmodule ElixirRunner.TxAdapter do
  @moduledoc """
  Adapter for transaction validation using the Elixir node implementation.
  
  This module interfaces with the TX module from the Elixir node
  to validate transactions and return consistent error codes.
  """
  import Bitwise

  # Canonical error codes for cross-implementation consistency
  # These must match the CanonErr enum values in proto/src/lib.rs
  @canon_ok           1
  @canon_too_large    122
  @canon_decode       123
  @canon_truncated    124
  @canon_overflow     125
  @canon_negative_len 126
  @canon_depth_exceeded 127
  @canon_unknown_tag  128

  defstruct []

  @type t :: %__MODULE__{}

  @doc """
  Initialize the transaction adapter.
  """
  def init do
    {:ok, %__MODULE__{}}
  end

  @doc """
  Validate a transaction and return a normalized result code.
  """
  def validate_transaction(_adapter, %{tx_data: tx_data, is_special_meeting: is_special_meeting}) do
    try do
      
      # Convert list of bytes to binary if needed
      tx_binary =
        case tx_data do
          data when is_binary(data) -> data
          data when is_list(data) -> :erlang.list_to_binary(data)
          _ -> <<>>
        end

      max_tx_size = Application.get_env(:ama, :tx_size, 393_216)

      cond do
        byte_size(tx_binary) > max_tx_size ->
          {:ok, %{type: :transaction, validation_result: @canon_too_large, tx_size: byte_size(tx_binary)}}

        vanilla_preflight_all(tx_binary) != :ok ->
          {:ok, %{type: :transaction, validation_result: @canon_too_large, tx_size: byte_size(tx_binary)}}

        true ->
          # Direct validation - let TX.validate handle all edge cases
          result = TX.validate(tx_binary, is_special_meeting)

          validation_code =
            case result do
              %{error: :ok} -> @canon_ok # Valid transaction
              %{error: error} -> map_error_to_code(error)
            end

          {:ok,
           %{
             type: :transaction,
             validation_result: validation_code,
             tx_size: byte_size(tx_binary)
           }}
      end
    rescue
      # Any decode exception → canonical decode error for consistent differential testing
      e ->
        tx_size = case tx_data do
          data when is_binary(data) -> byte_size(data)
          data when is_list(data) -> length(data)
          _ -> 0
        end
        {:ok,
         %{
           type: :transaction,
           validation_result: @canon_decode,
           tx_size: tx_size
         }}
    catch
      :throw, %{error: error} ->
        validation_code = map_error_to_code(error)
        tx_size = case tx_data do
          data when is_binary(data) -> byte_size(data)
          data when is_list(data) -> length(data)
          _ -> 0
        end

        {:ok,
         %{
           type: :transaction,
           validation_result: validation_code,
           tx_size: tx_size
         }}
    end
  end

  # Map Elixir transaction errors to canonical error codes
  # Canonical errors ensure consistency with Rust implementation
  defp map_error_to_code(error) do
    case error do
      # Canonical error mappings for cross-implementation consistency
      :too_large -> @canon_too_large
      :vanilla_ser -> @canon_decode
      :decode_error -> @canon_decode
      :malformed -> @canon_decode
      :truncated -> @canon_truncated
      :overflow -> @canon_overflow
      
      # Transaction-specific validation errors (keep existing codes)
      :tx_not_canonical -> 121
      :invalid_hash -> 102
      :invalid_signature -> 103
      :nonce_not_integer -> 104
      :nonce_too_high -> 105
      :actions_must_be_list -> 106
      :actions_length_must_be_1 -> 107
      :op_must_be_call -> 108
      :contract_must_be_binary -> 109
      :function_must_be_binary -> 110
      :args_must_be_list -> 111
      :arg_must_be_binary -> 112
      :invalid_contract_or_function -> 113
      :invalid_module_for_special_meeting -> 114
      :invalid_function_for_special_meeting -> 115
      :attached_symbol_must_be_binary -> 116
      :attached_symbol_wrong_size -> 117
      :attached_amount_must_be_binary -> 118
      :attached_amount_must_be_included -> 119
      :attached_symbol_must_be_included -> 120
      
      # Catch-all for unknown errors - map to generic decode error
      _ -> @canon_decode
    end
  end

  # VanillaSer preflight validation constants - keep identical to Rust side
  @max_tx_size 393_216
  @max_list_len 4_096
  @max_map_len 4_096
  @max_depth 16
  @max_elems 32_768

  # Allocation-free VanillaSer preflight validation
  defp vanilla_preflight_all(bin) do
    # emulate decode_all(): iterate until buffer empty
    do_preflight(bin, @max_elems)
  end

  defp do_preflight(<<>>, _elems), do: :ok
  defp do_preflight(bin, elems) do
    case walk_one(bin, 0, {elems}) do
      {:ok, {consumed, tail, {elems2}}} -> do_preflight(tail, elems2)
      {:error, reason} -> {:error, reason}
    end
  end

  defp read_len(<<b0, rest::binary>>) do
    sign = (b0 &&& 0x80) != 0
    mag_len = b0 &&& 0x7F
    cond do
      sign -> {:error, :malformed}
      mag_len > 8 -> {:error, :too_large}
      byte_size(rest) < mag_len -> {:error, :malformed}
      true ->
        <<mag::unsigned-big-integer-size(mag_len)-unit(8), tail::binary>> = rest
        {:ok, {mag, 1 + mag_len, tail}}
    end
  end
  defp read_len(<<>>), do: {:error, :malformed}

  defp walk_one(<<>>, _depth, _budget), do: {:error, :malformed}
  defp walk_one(_bin, depth, _budget) when depth > @max_depth, do: {:error, :too_large}

  defp walk_one(<<0, rest::binary>>, _depth, budget), do: {:ok, {1, rest, budget}}
  defp walk_one(<<tag, rest::binary>>, depth, budget) when tag in [1,2,3,4] do
    with {:ok, {_n, used, tail}} <- read_len(rest) do
      {:ok, {1 + used, tail, budget}}
    end
  end

  # bytes
  defp walk_one(<<5, rest::binary>>, _depth, budget) do
    with {:ok, {len, used, tail}} <- read_len(rest),
         true <- len <= @max_tx_size or {:error, :too_large},
         true <- byte_size(tail) >= len or {:error, :malformed}
    do
      <<_skip::binary-size(len), tail2::binary>> = tail
      {:ok, {1 + used + len, tail2, budget}}
    end
  end

  # list
  defp walk_one(<<6, rest::binary>>, depth, {elems}) do
    with {:ok, {len, used, tail}} <- read_len(rest),
         true <- len <= @max_list_len or {:error, :too_large},
         true <- elems >= len or {:error, :too_large}
    do
      case Enum.reduce_while(1..len, {1 + used, tail, elems - len}, fn _, {acc, bin, e} ->
             case walk_one(bin, depth + 1, {e}) do
               {:ok, {c, bin2, {e2}}} -> {:cont, {acc + c, bin2, e2}}
               err -> {:halt, err}
             end
           end) do
        {:error, _} = err -> err
        {consumed, tail2, elems2} -> {:ok, {consumed, tail2, {elems2}}}
      end
    end
  end

  # map
  defp walk_one(<<7, rest::binary>>, depth, {elems}) do
    with {:ok, {len, used, tail}} <- read_len(rest),
         true <- len <= @max_map_len or {:error, :too_large},
         needed <- len * 2,
         true <- elems >= needed or {:error, :too_large}
    do
      case Enum.reduce_while(1..len, {1 + used, tail, elems - needed}, fn _, {acc, bin, e} ->
             with {:ok, {ck, bin1, {e1}}} <- walk_one(bin, depth + 1, {e}),
                  {:ok, {cv, bin2, {e2}}} <- walk_one(bin1, depth + 1, {e1})
             do
               {:cont, {acc + ck + cv, bin2, e2}}
             else err -> {:halt, err}
             end
           end) do
        {:error, _} = err -> err
        {consumed, tail2, elems2} -> {:ok, {consumed, tail2, {elems2}}}
      end
    end
  end

  defp walk_one(_unknown, _depth, _budget), do: {:error, :malformed}

  defp suspicious_vanilla_prefix(_other, _max_tx_size), do: false

end