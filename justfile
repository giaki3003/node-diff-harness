# Setup
setup:
    cargo build --all
    cd adapters/elixir-runner && mix deps.get && CXXFLAGS="-include cstdint" MIX_ENV=prod mix escript.build

# Fuzzing
fuzz:
    #!/usr/bin/env bash
    if ! cargo fuzz --help > /dev/null 2>&1; then
        cargo install cargo-fuzz
    fi
    cd fuzz && cargo fuzz run fuzz_protocol -- -runs=0

fuzz-quick:
    #!/usr/bin/env bash  
    if ! cargo fuzz --help > /dev/null 2>&1; then
        cargo install cargo-fuzz
    fi
    cd fuzz && cargo fuzz run fuzz_protocol -- -max_total_time=30

# Debugging
replay TRACE:
    cargo run -p replay -- {{TRACE}}

find-crashes:
    @find fuzz/artifacts -name 'crash-*' -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort | tail -10

test-all-traces:
    #!/usr/bin/env bash
    echo "Testing all traces..."
    cargo run -p replay -- test-traces/ping_test.json || true
    cargo run -p replay -- test-traces/txpool_test.json || true  
    cargo run -p replay -- test-traces/peers_v2_test.json || true
    cargo run -p replay -- test-traces/zero_ping_test.json || true

# Maintenance  
clean:
    cargo clean
    cd adapters/elixir-runner && mix clean

test:
    cargo test --all