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

        suspicious_vanilla_prefix(tx_binary, max_tx_size) ->
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

  # Check for VanillaSer allocation bombs using proper format knowledge and FF flood detection
  defp suspicious_vanilla_prefix(<<tag, b0, rest::binary>>, max_tx_size) when tag in [5, 6, 7] do
    # FF flood heuristic: ≥3 FF in first 8 bytes screams "absurd length"
    ff_count =
      rest
      |> :binary.part(0, min(byte_size(rest), 8))
      |> :binary.bin_to_list()
      |> Enum.count(& &1 == 0xFF)

    if ff_count >= 3 do
      true
    else
      len_of_mag = band(b0, 0x7F)
      sign = band(b0, 0x80) != 0

      cond do
        sign or len_of_mag == 0 or len_of_mag > 8 ->
          true

        byte_size(rest) < len_of_mag ->
          true # malformed varint ⇒ suspicious

        true ->
          <<mag_bytes::binary-size(len_of_mag), _::binary>> = rest
          mag = :binary.decode_unsigned(mag_bytes)

          max =
            case tag do
              5 -> max_tx_size     # bytes length
              6 -> 4_096           # list length
              7 -> 4_096           # map length
            end

          mag > max
      end
    end
  end

  defp suspicious_vanilla_prefix(_other, _max_tx_size), do: false

end