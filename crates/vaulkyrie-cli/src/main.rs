mod cmd;

use clap::Parser;

/// Vaulkyrie — Solana threshold wallet CLI
///
/// Manage vaults, run DKG ceremonies, stage policy receipts,
/// rotate quantum authorities, and orchestrate threshold spends.
#[derive(Parser)]
#[command(name = "vaulkyrie", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: cmd::Command,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = cmd::dispatch(cli.command) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
