//! Replay tool for debugging differential fuzzing traces
//!
//! This tool can load a saved trace file and replay it on both implementations,
//! showing the differences between them for debugging purposes.

use anyhow::{Context, Result};
use arbitrary::{Arbitrary, Unstructured};
use clap::{Arg, Command};
use colored::*;
use proto::{ExecutionResult, Trace, TraceExecutor};
use rust_step::RustStepExecutor;
use std::fs;
use tabled::{Table, Tabled};

mod elixir_runner;
use elixir_runner::ElixirRunner;

#[derive(Tabled)]
struct ComparisonRow {
    #[tabled(rename = "Metric")]
    metric: String,
    #[tabled(rename = "Rust")]
    rust: String,
    #[tabled(rename = "Elixir")]
    elixir: String,
    #[tabled(rename = "Match")]
    matches: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("replay=info,warn")
        .init();

    let app = Command::new("replay")
        .version("0.1.0")
        .about("Replay differential fuzzing traces for debugging")
        .arg(
            Arg::new("trace_file")
                .help("Path to the trace file to replay")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Input format (auto, json, bincode, libfuzzer)")
                .default_value("auto"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Show verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rust-only")
                .long("rust-only")
                .help("Only run on Rust implementation")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("elixir-only")
                .long("elixir-only")
                .help("Only run on Elixir implementation")
                .action(clap::ArgAction::SetTrue),
        );

    let matches = app.get_matches();

    let trace_file = matches.get_one::<String>("trace_file").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");
    let rust_only = matches.get_flag("rust-only");
    let elixir_only = matches.get_flag("elixir-only");

    println!(
        "{}",
        "🔄 Amadeus Node Differential Trace Replay Tool"
            .cyan()
            .bold()
    );
    println!("📁 Loading trace file: {}", trace_file.yellow());

    // Load and parse the trace file
    let trace = load_trace_file(trace_file, format).context("Failed to load trace file")?;

    println!(
        "✅ Trace loaded: {} operations, seed: {}",
        trace.ops.len().to_string().green(),
        trace.seed.to_string().green()
    );

    if verbose {
        println!("\n📋 Trace Operations:");
        for (i, op) in trace.ops.iter().enumerate() {
            println!("  {}: {:?}", i + 1, op);
        }
    }

    // Execute on implementations
    let mut rust_result = None;
    let mut elixir_result = None;

    if !elixir_only {
        println!("\n🦀 Executing on Rust implementation...");
        match execute_rust(&trace) {
            Ok(result) => {
                rust_result = Some(result);
                println!("✅ Rust execution completed");
            }
            Err(e) => {
                println!("❌ Rust execution failed: {}", e.to_string().red());
                if rust_only {
                    return Err(e);
                }
            }
        }
    }

    if !rust_only {
        println!("\n💧 Executing on Elixir implementation...");
        match execute_elixir(&trace).await {
            Ok(result) => {
                elixir_result = Some(result);
                println!("✅ Elixir execution completed");
            }
            Err(e) => {
                println!("❌ Elixir execution failed: {}", e.to_string().red());
                if elixir_only {
                    return Err(e);
                }
            }
        }
    }

    // Compare results
    if let (Some(rust_res), Some(elixir_res)) = (&rust_result, &elixir_result) {
        println!("\n📊 Comparison Results:");
        compare_and_display(rust_res, elixir_res);
    } else if let Some(rust_res) = &rust_result {
        println!("\n🦀 Rust Results:");
        display_single_result("Rust", rust_res);
    } else if let Some(elixir_res) = &elixir_result {
        println!("\n💧 Elixir Results:");
        display_single_result("Elixir", elixir_res);
    }

    Ok(())
}

fn load_trace_file(path: &str, format: &str) -> Result<Trace> {
    let data = fs::read(path).with_context(|| format!("Failed to read trace file: {}", path))?;

    match format {
        "json" => load_json_trace(&data),
        "bincode" => load_bincode_trace(&data),
        "libfuzzer" => load_libfuzzer_trace(&data),
        "auto" => {
            // Try libfuzzer first (most common from fuzzer), then JSON, then bincode
            load_libfuzzer_trace(&data)
                .or_else(|_| load_json_trace(&data))
                .or_else(|_| load_bincode_trace(&data))
                .context("Could not parse trace as libfuzzer, JSON, or bincode")
        }
        _ => anyhow::bail!("Unsupported format: {}", format),
    }
}

fn load_json_trace(data: &[u8]) -> Result<Trace> {
    let json_str = std::str::from_utf8(data).context("Trace file is not valid UTF-8")?;

    serde_json::from_str(json_str).context("Failed to parse JSON trace")
}

fn load_bincode_trace(data: &[u8]) -> Result<Trace> {
    Trace::from_bytes(data).context("Failed to parse bincode trace")
}

fn load_libfuzzer_trace(data: &[u8]) -> Result<Trace> {
    let mut unstructured = Unstructured::new(data);
    Trace::arbitrary(&mut unstructured).context("Failed to parse libfuzzer trace")
}

fn execute_rust(trace: &Trace) -> Result<ExecutionResult> {
    let mut executor =
        RustStepExecutor::with_seed(trace.seed).context("Failed to create Rust executor")?;

    executor.execute_trace(trace)
}

async fn execute_elixir(trace: &Trace) -> Result<ExecutionResult> {
    let mut runner = ElixirRunner::new()
        .await
        .context("Failed to create Elixir runner")?;

    runner.execute_trace(trace).await
}

fn compare_and_display(rust_result: &ExecutionResult, elixir_result: &ExecutionResult) {
    let mut rows = Vec::new();

    // Success status
    let rust_success = rust_result.is_success();
    let elixir_success = elixir_result.is_success();
    let success_match = rust_success == elixir_success;

    rows.push(ComparisonRow {
        metric: "Success".to_string(),
        rust: format_bool(rust_success),
        elixir: format_bool(elixir_success),
        matches: format_match(success_match),
    });

    // Operations executed
    let ops_match = rust_result.ops_executed == elixir_result.ops_executed;
    rows.push(ComparisonRow {
        metric: "Operations Executed".to_string(),
        rust: rust_result.ops_executed.to_string(),
        elixir: elixir_result.ops_executed.to_string(),
        matches: format_match(ops_match),
    });

    // Digest comparison (only if both succeeded)
    if rust_success && elixir_success {
        let digest_match = rust_result.digest == elixir_result.digest;
        rows.push(ComparisonRow {
            metric: "Digest".to_string(),
            rust: format!("{}...", hex::encode(&rust_result.digest[..8])),
            elixir: format!("{}...", hex::encode(&elixir_result.digest[..8])),
            matches: format_match(digest_match),
        });

        if !digest_match {
            println!(
                "\n⚠️  {} {}",
                "DIGEST MISMATCH DETECTED!".red().bold(),
                "This indicates a differential bug.".yellow()
            );
            println!("🦀 Rust digest:   {}", hex::encode(&rust_result.digest));
            println!("💧 Elixir digest: {}", hex::encode(&elixir_result.digest));
        }
    }

    // Error messages
    match (rust_result.get_error(), elixir_result.get_error()) {
        (Some(rust_err), Some(elixir_err)) => {
            let error_match = rust_err == elixir_err;
            rows.push(ComparisonRow {
                metric: "Error".to_string(),
                rust: truncate_string(rust_err, 30),
                elixir: truncate_string(elixir_err, 30),
                matches: format_match(error_match),
            });
        }
        (Some(rust_err), None) => {
            rows.push(ComparisonRow {
                metric: "Error".to_string(),
                rust: truncate_string(rust_err, 30),
                elixir: "None".to_string(),
                matches: "❌".to_string(),
            });
        }
        (None, Some(elixir_err)) => {
            rows.push(ComparisonRow {
                metric: "Error".to_string(),
                rust: "None".to_string(),
                elixir: truncate_string(elixir_err, 30),
                matches: "❌".to_string(),
            });
        }
        (None, None) => {
            // Both succeeded, no error to show
        }
    }

    // Performance metrics (if available)
    if let (Some(rust_metrics), Some(elixir_metrics)) =
        (&rust_result.metrics, &elixir_result.metrics)
    {
        rows.push(ComparisonRow {
            metric: "Duration (μs)".to_string(),
            rust: rust_metrics.duration_us.to_string(),
            elixir: elixir_metrics.duration_us.to_string(),
            matches: "ℹ️".to_string(),
        });

        rows.push(ComparisonRow {
            metric: "Messages Processed".to_string(),
            rust: rust_metrics.messages_processed.to_string(),
            elixir: elixir_metrics.messages_processed.to_string(),
            matches: format_match(
                rust_metrics.messages_processed == elixir_metrics.messages_processed,
            ),
        });
    }

    let table = Table::new(&rows);
    println!("{}", table);
}

fn display_single_result(impl_name: &str, result: &ExecutionResult) {
    println!("Implementation: {}", impl_name.cyan().bold());
    println!("Success: {}", format_bool(result.is_success()));
    println!("Operations Executed: {}", result.ops_executed);

    if result.is_success() {
        println!("Digest: {}", hex::encode(&result.digest));
    } else if let Some(error) = result.get_error() {
        println!("Error: {}", error.red());
    }

    if let Some(metrics) = &result.metrics {
        println!("Duration: {}μs", metrics.duration_us);
        println!("Messages Processed: {}", metrics.messages_processed);
        println!("Transactions Processed: {}", metrics.transactions_processed);
    }
}

fn format_bool(b: bool) -> String {
    if b {
        "✅ Yes".to_string()
    } else {
        "❌ No".to_string()
    }
}

fn format_match(matches: bool) -> String {
    if matches {
        "✅".to_string()
    } else {
        "❌".to_string()
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}
