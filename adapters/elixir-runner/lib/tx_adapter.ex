defmodule ElixirRunner.TxAdapter do
  @moduledoc """
  Adapter for transaction validation using the Elixir node implementation.
  
  This module interfaces with the TX module from the Elixir node
  to validate transactions and return consistent error codes.
  """

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
      tx_binary = case tx_data do
        data when is_binary(data) -> data
        data when is_list(data) -> :erlang.list_to_binary(data)
        _ -> <<>>
      end
      
      # Use the node's TX.validate function
      result = TX.validate(tx_binary, is_special_meeting)
      
      validation_code = case result do
        %{error: :ok} -> 1 # Valid transaction
        %{error: error} -> map_error_to_code(error)
      end
      
      {:ok, %{
        type: :transaction,
        validation_result: validation_code,
        tx_size: byte_size(tx_binary)
      }}
    rescue
      e -> {:error, "tx_validation_error: #{Exception.message(e)}"}
    catch
      :throw, %{error: error} -> 
        validation_code = map_error_to_code(error)
        {:ok, %{
          type: :transaction,
          validation_result: validation_code,
          tx_size: byte_size(tx_data || <<>>)
        }}
    end
  end

  # Map Elixir transaction errors to consistent numeric codes
  # These should match the codes used in the Rust implementation
  defp map_error_to_code(error) do
    case error do
      :too_large -> 122
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
      # Catch-all for unknown errors
      _ -> 999
    end
  end
end