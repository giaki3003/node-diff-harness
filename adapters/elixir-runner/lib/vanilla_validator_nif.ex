defmodule VanillaValidatorNif do
  @moduledoc """
  NIF wrapper for Rust VanillaSer validation.
  
  This module provides the single source of truth for VanillaSer validation,
  ensuring both Rust and Elixir implementations use identical validation logic
  and return identical error codes for perfect digest consistency.
  """
  
  use Rustler, otp_app: :elixir_runner, crate: "vanilla_validator_nif"

  @doc """
  Run pre-decode VanillaSer streaming checks using Rust logic.

  Returns:
  - `{:ok, :ok}` when the binary passes streaming checks
  - `{:error, reason}` with reason in:
    `:too_large | :truncated | :overflow | :negative_length | :depth_exceeded |
     :unknown_tag | :too_many_elements | :suspicious_length | :malformed`
  """
  def validate_vanilla_ser(_data), do: :erlang.nif_error(:nif_not_loaded)
end
