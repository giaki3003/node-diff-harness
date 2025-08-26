use anyhow::Result;
use proto::{Operation, Trace};
use std::fs;

fn main() -> Result<()> {
    // Create basic protocol test trace
    let trace = Trace::basic_protocol_test();

    // Save as JSON for easy inspection
    let json = serde_json::to_string_pretty(&trace)?;
    fs::write("basic_test.json", json)?;

    // Save as bincode for efficient processing
    let bytes = trace.to_bytes()?;
    fs::write("basic_test.bincode", bytes)?;

    println!("✅ Created test traces:");
    println!("  📄 basic_test.json - JSON format for inspection");
    println!("  📦 basic_test.bincode - binary format for replay");
    println!();
    println!("📋 Trace Summary:");
    println!("  🎲 Seed: {}", trace.seed);
    println!("  🔢 Operations: {}", trace.ops.len());

    for (i, op) in trace.ops.iter().enumerate() {
        let description = match op {
            Operation::Ping {
                temporal_height,
                temporal_slot,
                rooted_height,
                rooted_slot,
                timestamp_ms,
            } => {
                format!(
                    "Ping (temporal: {}/{}, rooted: {}/{}, timestamp: {})",
                    temporal_height, temporal_slot, rooted_height, rooted_slot, timestamp_ms
                )
            }
            Operation::TxPool { txs } => {
                format!(
                    "TxPool ({} transactions: {})",
                    txs.len(),
                    txs.iter()
                        .map(|tx| format!("\"{}\"", String::from_utf8_lossy(tx)))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Operation::Peers { ips } => {
                format!("Peers ({} IPs: {})", ips.len(), ips.join(", "))
            }
            Operation::PeersV2 { anrs } => {
                format!("PeersV2 ({} ANRs: {})", anrs.len(), anrs.join(", "))
            }
            Operation::ProcessTx {
                tx_data,
                is_special_meeting,
            } => {
                format!(
                    "ProcessTx ({} bytes, special_meeting: {})",
                    tx_data.len(),
                    is_special_meeting
                )
            }
            Operation::SerializeMessage { msg_type, payload } => {
                format!("SerializeMessage ({:?}, {} bytes)", msg_type, payload.len())
            }
        };
        println!("    {}. {}", i + 1, description);
    }

    println!();
    println!("🚀 Ready to run differential test:");
    println!("   cargo run --bin replay -- basic_test.json");

    Ok(())
}
