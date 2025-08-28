use std::path::PathBuf;
use std::process;

use clap::Parser;

// Import from the library crate (this crate's lib).
use plc_secure_checker_lib::parser::parse_file;
use plc_secure_checker_lib::rules::{load_policy, run_all, run_all_for_wasm, Policy};



/// plc_secure_checker — static analyzer for Siemens PLC sources (SCL/PLCOpen XML)
#[derive(Parser, Debug)]
#[command(name = "plc_secure_checker")]
#[command(version)]
#[command(about = "Static analysis for Siemens PLC code against Top 20 Secure PLC Coding Practices")]
struct Cli {
    /// Path to the Siemens PLC source file (.scl/.st or PLCOpen .xml)
    input: PathBuf,

    /// Optional path to policy.json (used by Rule 7 & Rule 10)
    #[arg(short, long)]
    policy: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    // Parse the PLC file into the unified AST
    let program = match parse_file(&cli.input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to parse '{}': {}", cli.input.display(), e);
            process::exit(1);
        }
    };

    // Load policy (Option<&Path>)
    let policy: Policy = match load_policy(cli.policy.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            process::exit(1);
        }
    };

    // Run all rules and print results in the exact required format
    run_all(&program, &policy);
    let all_results = run_all_for_wasm(&program, &policy);
    dbg!(all_results);
}
