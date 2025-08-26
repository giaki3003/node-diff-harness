# Setup
setup:
    cargo install cargo-fuzz
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
    @for trace in test-traces/*.json; do cargo run -p replay -- "$$trace" || true; done

# Maintenance  
clean:
    cargo clean
    cd adapters/elixir-runner && mix clean

test:
    cargo test --all