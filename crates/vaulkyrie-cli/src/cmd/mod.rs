pub mod authority;
pub mod decode;
pub mod dkg;
pub mod inspect;
pub mod pda;
pub mod quantum;
pub mod recovery;
pub mod spend;
pub mod vault;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Vault lifecycle — init, status, lock/unlock
    #[command(subcommand)]
    Vault(vault::VaultCmd),

    /// DKG ceremonies — keygen, sign, refresh, legacy-message signing
    #[command(subcommand)]
    Dkg(dkg::DkgCmd),

    /// Quantum authority — init, rotate, proof chunks
    #[command(subcommand)]
    Authority(authority::AuthorityCmd),

    /// Quantum vault — init, split, close
    #[command(subcommand)]
    Quantum(quantum::QuantumCmd),

    /// Spend orchestration — init, commit, complete, fail
    #[command(subcommand)]
    Spend(spend::SpendCmd),

    /// Recovery flows — init recovery, complete recovery, migrate authority
    #[command(subcommand)]
    Recovery(recovery::RecoveryCmd),

    /// PDA derivation — compute PDAs for any account type
    #[command(subcommand)]
    Pda(pda::PdaCmd),

    /// Inspect on-chain account data
    #[command(subcommand)]
    Inspect(inspect::InspectCmd),

    /// Decode error codes, instruction data, or raw account bytes
    #[command(subcommand)]
    Decode(decode::DecodeCmd),

    /// Ping the program (no-op health check)
    Ping {
        /// Program ID (base58)
        #[arg(long)]
        program_id: String,
    },
}

pub fn dispatch(cmd: Command) -> Result<(), String> {
    match cmd {
        Command::Vault(sub) => vault::run(sub),
        Command::Dkg(sub) => dkg::run(sub),
        Command::Authority(sub) => authority::run(sub),
        Command::Quantum(sub) => quantum::run(sub),
        Command::Spend(sub) => spend::run(sub),
        Command::Recovery(sub) => recovery::run(sub),
        Command::Pda(sub) => pda::run(sub),
        Command::Inspect(sub) => inspect::run(sub),
        Command::Decode(sub) => decode::run(sub),
        Command::Ping { program_id } => {
            let pid = parse_pubkey(&program_id)?;
            let ix = vaulkyrie_sdk::instruction::ping(&pid);
            print_instruction_json("Ping", &ix);
            Ok(())
        }
    }
}

/// Parse a base58-encoded public key.
pub fn parse_pubkey(s: &str) -> Result<vaulkyrie_sdk::Pubkey, String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("invalid base58 pubkey: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("pubkey must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(vaulkyrie_sdk::Pubkey::from(arr))
}

/// Parse a hex-encoded 32-byte hash.
pub fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("hash must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Print an instruction as JSON for piping into `solana` CLI or other tooling.
pub fn print_instruction_json(label: &str, ix: &vaulkyrie_sdk::Instruction) {
    let program_id = bs58::encode(ix.program_id.as_ref()).into_string();
    let data_hex = hex::encode(&ix.data);

    let accounts: Vec<serde_json::Value> = ix
        .accounts
        .iter()
        .map(|meta| {
            serde_json::json!({
                "pubkey": bs58::encode(meta.pubkey.as_ref()).into_string(),
                "is_signer": meta.is_signer,
                "is_writable": meta.is_writable,
            })
        })
        .collect();

    let output = serde_json::json!({
        "instruction": label,
        "program_id": program_id,
        "data_hex": data_hex,
        "data_len": ix.data.len(),
        "accounts": accounts,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
