use aael::BoxedAttester;
use aael::detect_tee_type;
use aael::eventlog::*;
use aael::tdx::*;

use anyhow::*;
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use crypto::HashAlgorithm;
use log::info;
use serde::Deserialize;
use serde_json::to_string_pretty;
use std::fs;
use std::sync::Arc;

#[derive(Deserialize, Debug)]
struct EventInput {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a TEE quote and evidence.
    Quote(QuoteArgs),
    /// Parse a quote from a file and print its contents.
    Parse(ParseArgs),
}

#[derive(Args, Debug)]
struct QuoteArgs {
    /// Save the generated quote (base64) to a file.
    /// If a path is not provided, it defaults to 'quote.bin'.
    #[arg(short, long, value_name = "FILE_PATH", num_args(0..=1), default_missing_value = "quote.bin")]
    save: Option<String>,

    /// Extend the RTMR with a custom event before generating the quote.
    /// The argument should be a JSON string, e.g., '{"domain":"app","operation":"load","content":"data"}'.
    #[arg(short, long, value_name = "JSON_STRING")]
    extend: Option<String>,
}

#[derive(Args, Debug)]
struct ParseArgs {
    /// Path to the base64 encoded quote file to parse.
    #[arg(value_name = "QUOTE_FILE_PATH")]
    path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Quote(args) => {
            let tee = detect_tee_type();
            let attester: BoxedAttester = tee.try_into()?;
            let attester = Arc::new(attester);

            if let Some(extend_log) = args.extend {
                info!("Extending event log from command line argument...");
                let mut el = EventLog::new(attester.clone(), HashAlgorithm::Sha384, 17)
                    .await
                    .context("Failed to create event log")?;

                let event_input: EventInput = serde_json::from_str(&extend_log)
                    .context("Failed to parse JSON for --extend argument. Please provide a valid JSON string.")?;

                let ev = LogEntry::Event {
                    domain: event_input.domain.as_str(),
                    operation: event_input.operation.as_str(),
                    content: event_input.content.as_str().try_into()?,
                };

                el.extend_entry(ev, 17).await?;
                info!("Event log extended successfully.");

                let report_data: Vec<u8> = vec![0; 48];
                let evidence_str = attester.get_evidence(report_data).await?;
                let evidence: TdxEvidence = serde_json::from_str(&evidence_str)?;
                if evidence.quote.is_empty() {
                    bail!("TDX Quote is empty.");
                }

                if let Some(path) = args.save {
                    fs::write(&path, evidence.quote.clone())?;
                    info!("Quote saved to {}", path);
                } else {
                    println!("{}", to_string_pretty(&evidence)?);
                }
            }
        }
        Commands::Parse(args) => {
            info!("Parsing quote from file: {}", &args.path);
            let quote_b64 = fs::read_to_string(&args.path)
                .with_context(|| format!("Failed to read quote file from '{}'", &args.path))?;

            let quote_bin = base64::engine::general_purpose::STANDARD
                .decode(quote_b64.trim())
                .context("Failed to decode base64 quote")?;

            let quote = parse_tdx_quote(&quote_bin)?;

            let claims = generate_parsed_claim(quote, None, None)?;
            let readable_json = to_string_pretty(&claims)?;
            println!("{}", readable_json);
        }
    }

    Ok(())
}
