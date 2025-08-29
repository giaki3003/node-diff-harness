defmodule ElixirRunner.ProtocolAdapterTest do
  use ExUnit.Case, async: true

  alias ElixirRunner.ProtocolAdapter

  setup_all do
    # Ensure TX.validate/2 can read required size config without starting :ama
    Application.put_env(:ama, :tx_size, 393_216)
    :ok
  end

  test "txpool excludes invalid all-zero txs and hashes only the prefix" do
    {:ok, adapter} = ProtocolAdapter.init()

    # Provide a single invalid tx filled with zeros (as list-of-bytes like traces do)
    zero_tx = :binary.copy(<<0>>, 64)
    zero_tx_list = :binary.bin_to_list(zero_tx)

    assert {:ok, %{type: :protocol, operation: :txpool, data: digest, included_tx_count: inc, filtered_tx_count: flt}} =
             ProtocolAdapter.handle_txpool(adapter, %{txs: [zero_tx_list]})

    assert inc == 0
    assert flt == 1

    # Expected digest is SHA256 over just the "txpool" prefix since no valid txs remain
    expected =
      :crypto.hash_init(:sha256)
      |> :crypto.hash_update("txpool")
      |> :crypto.hash_final()

    assert digest == expected
  end

  test "debug ping bytes" do
    {:ok, adapter} = ProtocolAdapter.init()
    
    # Test the exact failing case from fuzzer
    temporal_height = 1
    temporal_slot = 1
    rooted_height = 1
    rooted_slot = 1
    timestamp_ms = 1600000000000
    
    # Manually build what should be hashed
    protocol_ping = <<112, 105, 110, 103>>
    debug_bytes = protocol_ping <>
      <<rooted_height::64-little>> <>
      <<rooted_slot::64-little>> <>
      <<temporal_height::64-little>> <>
      <<temporal_slot::64-little>> <>
      <<timestamp_ms::64-little>>
    
    IO.puts("Debug: Elixir ping hash input bytes: #{inspect(:binary.bin_to_list(debug_bytes))}")
    IO.puts("Debug: Elixir ping hash input hex: #{Base.encode16(debug_bytes, case: :lower)}")
    
    # Compute expected hash manually
    expected_digest = :crypto.hash(:sha256, debug_bytes)
    IO.puts("Debug: Expected Elixir digest: #{Base.encode16(expected_digest, case: :lower)}")
    
    # Test actual function
    assert {:ok, %{type: :protocol, operation: :ping, data: actual_digest}} = 
      ProtocolAdapter.handle_ping(adapter, %{
        temporal_height: temporal_height,
        temporal_slot: temporal_slot,
        rooted_height: rooted_height,
        rooted_slot: rooted_slot,
        timestamp_ms: timestamp_ms
      })
    
    IO.puts("Debug: Actual Elixir digest: #{Base.encode16(actual_digest, case: :lower)}")
    
    assert actual_digest == expected_digest
  end
end