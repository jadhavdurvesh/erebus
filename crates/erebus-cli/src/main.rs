//! EREBUS offline policy tooling.
//!
//! This CLI validates and exports policy documents. It does not install
//! firewall rules or modify the host network configuration.

use clap::{Parser, Subcommand};
use erebus_config::PolicyDocument;
use std::{fs, path::PathBuf, process::ExitCode};

#[derive(Debug, Parser)]
#[command(name = "erebus", version, about = "EREBUS network policy tooling")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and validate a policy file without applying it.
    Validate {
        /// Path to a versioned EREBUS TOML policy.
        file: PathBuf,
    },
    /// Emit canonical TOML for a validated policy.
    Export {
        /// Input policy file.
        file: PathBuf,
        /// Optional output path. Without this option, output goes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn run(arguments: Arguments) -> Result<(), String> {
    match arguments.command {
        Command::Validate { file } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let document = PolicyDocument::parse(&source)
                .map_err(|error| format!("{}: {error}", file.display()))?;

            println!("Policy is valid.");
            println!("Schema version: {}", document.schema_version);
            println!("Rules: {}", document.rule_count());
            println!("Mode: offline validation only; no host rules were changed.");
        }
        Command::Export { file, output } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let document = PolicyDocument::parse(&source)
                .map_err(|error| format!("{}: {error}", file.display()))?;
            let canonical = document
                .canonical_toml()
                .map_err(|error| format!("cannot serialize policy: {error}"))?;

            if let Some(output) = output {
                fs::write(&output, canonical)
                    .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
                eprintln!("Wrote validated canonical policy to {}.", output.display());
            } else {
                print!("{canonical}");
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("erebus: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_documents_its_offline_commands() {
        let help = Arguments::try_parse_from(["erebus", "--help"]).unwrap_err();
        let output = help.to_string();

        assert!(output.contains("validate"));
        assert!(output.contains("export"));
    }
}
