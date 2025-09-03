defmodule ElixirRunner.TxAdapter do
  @moduledoc """
  Adapter for transaction validation using the Elixir node implementation.
  
  This module interfaces with the TX module from the Elixir node
  to validate transactions and return consistent error codes.
  """

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

      true ->
        debug_enabled = case System.get_env("AMA_ORACLE_DEBUG") do
          v when is_binary(v) -> String.downcase(v) in ["1", "true", "yes"]
          _ -> false
        end

        if debug_enabled do
          File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] TX binary size: #{byte_size(tx_binary)}, first 20 bytes: #{inspect(Enum.take(:binary.bin_to_list(tx_binary), 20))}\n", [:append])
          File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Calling VanillaValidatorNif.validate_vanilla_ser (pre-decode checks)...\n", [:append])
        end

        case VanillaValidatorNif.validate_vanilla_ser(tx_binary) do
          {:ok, :ok} ->
            result = TX.validate(tx_binary, is_special_meeting)
            if debug_enabled do
              File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] TX.validate result: #{inspect(result)}\n", [:append])
            end
            validation_code =
              case result do
                %{error: :ok} -> @canon_ok
                %{error: error} -> map_error_to_code(error)
              end
            {:ok, %{type: :transaction, validation_result: validation_code, tx_size: byte_size(tx_binary)}}
          {:error, reason} ->
            validation_code = map_nif_error_to_code(reason)
            if debug_enabled do
              File.write("/tmp/elixir_protocol_debug.log", "[ELIXIR PROTOCOL] Pre-decode failed with #{inspect(reason)} -> code #{validation_code}\n", [:append])
            end
            {:ok, %{type: :transaction, validation_result: validation_code, tx_size: byte_size(tx_binary)}}
        end
    end
  end

  # Map NIF VanillaSer validation errors to canonical error codes
  # These must match the Rust ValidationError enum mapping exactly
  defp map_nif_error_to_code(nif_error) do
    case nif_error do
      :too_large -> @canon_too_large
      :truncated -> @canon_truncated
      :overflow -> @canon_overflow
      :negative_length -> @canon_negative_len
      :depth_exceeded -> @canon_depth_exceeded
      :unknown_tag -> @canon_unknown_tag
      :too_many_elements -> @canon_too_large
      :suspicious_length -> @canon_too_large
      :malformed -> @canon_decode
      _ -> @canon_decode
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
      :malformed -> @canon_unknown_tag
      :negative_len -> @canon_negative_len
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

      # Missing field errors - matches Rust's Missing(_) -> 101 mapping
      :missing -> 101

      # VanillaSer parsing errors at tx layer
      :trailing_data -> @canon_decode
      :unknown -> @canon_decode
      _ -> @canon_decode
    end
  end

end
