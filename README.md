# Amadeus Node Differential Fuzzer

Differential fuzzing harness comparing Elixir and Rust implementations of the Amadeus node.

## Architecture

The fuzzer generates test traces and executes them on both implementations, comparing canonical digests to detect semantic differences.

```
libfuzzer → Arbitrary → JSON Trace → Rust Executor (rs_node)    → SHA256 Digest ┐
                                   ↘ Elixir Oracle (node/beam) → SHA256 Digest ┘ → Compare
```

**Key insight**: Since HashMap serialization is non-deterministic across languages, we create ordered canonical representations and hash those instead of comparing raw bytes.

## What it tests

**Protocol Operations:**
- Ping messages with temporal/rooted state
- Transaction pool operations
- Peers protocol (Rust: legacy format, Elixir: PeersV2 with ANRs)
- Individual transaction validation

## Setup

```bash
just setup     # installs cargo-fuzz, builds everything
just fuzz      # start fuzzing
```

Requires: Rust, Elixir/OTP, just, C compiler

## How it works

1. libfuzzer generates random bytes → `Arbitrary` trait creates realistic `Trace` structs
2. Both implementations execute the same trace and create canonical SHA256 digests
3. Fuzzer compares success/failure status and digest values
4. Mismatches trigger detailed crash reports saved as artifacts

## Commands

```bash
just fuzz                    # unlimited fuzzing
just fuzz-quick             # 30-second test
just replay [trace.json]    # debug specific trace
just test-all-traces        # smoke test curated traces
```

## Trace format

JSON with seed and operation list:
```json
{
  "seed": 12345,
  "ops": [
    {"Ping": {"temporal_height": 100, "temporal_slot": 5, ...}},
    {"TxPool": {"txs": [[116,101,115,116]]}},
    {"PeersV2": {"anrs": ["alice.sol"]}}
  ]
}
```

Operations: `Ping`, `TxPool`, `Peers`/`PeersV2`, `ProcessTx`

## Status

**Found bugs**: Zero-parameter Ping digest mismatch, protocol version incompatibilities
**Known TODOs**: PeersV2 support in Rust implementation

## Directory structure

```
proto/           # trace format (JSON + Arbitrary)  
fuzz/            # cargo-fuzz differential fuzzer
adapters/        # rust-step + elixir-runner
replay/          # CLI debugging tool
test-traces/     # curated test cases
rs_node/         # rust implementation (submodule)
node/            # elixir implementation (submodule)
```

