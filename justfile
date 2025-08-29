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
    cd fuzz && cargo fuzz run fuzz_protocol -- -runs=0 -max_total_time=300

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

rebuild-elixir:
    cd adapters/elixir-runner && CXXFLAGS="-include cstdint" MIX_ENV=prod mix escript.build

# Advanced fuzzing
fuzz-intensive:
    #!/usr/bin/env bash
    if ! cargo fuzz --help > /dev/null 2>&1; then
        cargo install cargo-fuzz
    fi
    echo "🔥 Starting intensive 30-minute fuzzing session with 4 workers..."
    cd fuzz && cargo fuzz run fuzz_protocol -- -runs=0 -max_total_time=1800 -workers=4

# Performance testing  
perf-test:
    #!/usr/bin/env bash
    echo "🚀 Running performance test (1 minute)..."
    cd fuzz && cargo fuzz run fuzz_protocol -- -max_total_time=60

# Corpus management  
clean-corpus:
    #!/usr/bin/env bash
    echo "🧹 Cleaning old corpus and crash artifacts..."
    rm -rf fuzz/corpus/fuzz_protocol/* || true
    rm -rf fuzz/artifacts/fuzz_protocol/* || true
    echo "✅ Corpus cleaned. Run fuzzer to regenerate."

# Development helpers
check:
    #!/usr/bin/env bash
    echo "🔍 Running all checks..."
    cargo check --all
    cargo clippy --all -- -D warnings
    cd adapters/elixir-runner && mix compile --warnings-as-errors

# Maintenance  
clean:
    cargo clean
    cd adapters/elixir-runner && mix clean

test:
    cargo test --all