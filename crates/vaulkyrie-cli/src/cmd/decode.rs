use clap::Subcommand;

#[derive(Subcommand)]
pub enum DecodeCmd {
    /// Decode a Vaulkyrie error code to a human-readable description
    Error {
        /// Error code (decimal integer)
        #[arg(long)]
        code: u32,
    },
    /// Decode raw instruction data (hex) and print the discriminator tag
    Instruction {
        /// Instruction data (hex-encoded)
        #[arg(long)]
        data: String,
    },
}

pub fn run(cmd: DecodeCmd) -> Result<(), String> {
    match cmd {
        DecodeCmd::Error { code } => {
            let desc = vaulkyrie_sdk::error::decode_error(code).unwrap_or("Unknown error code");
            println!("Error {code}: {desc}");
            Ok(())
        }
        DecodeCmd::Instruction { data } => {
            let bytes = hex::decode(&data).map_err(|e| format!("invalid hex: {e}"))?;
            if bytes.is_empty() {
                return Err("instruction data is empty".into());
            }
            let tag = bytes[0];
            let name = instruction_tag_name(tag);
            println!("Instruction tag: 0x{tag:02x} ({tag}) = {name}");
            if bytes.len() > 1 {
                println!(
                    "Payload ({} bytes): {}",
                    bytes.len() - 1,
                    hex::encode(&bytes[1..])
                );
            }
            Ok(())
        }
    }
}

fn instruction_tag_name(tag: u8) -> &'static str {
    match tag {
        0 => "Ping",
        1 => "InitVaultRegistry",
        2 => "InitQuantumAuthority",
        3 => "InitQuantumVault",
        10 => "SetVaultStatus",
        11 => "RotateQuantumAuthority",
        12 => "InitAuthorityProof",
        13 => "WriteProofChunk",
        14 => "RotateAuthorityStaged",
        15 => "SplitQuantumVault",
        16 => "CloseQuantumVault",
        17 => "InitSpendOrchestration",
        18 => "CommitSpendOrchestration",
        19 => "CompleteSpendOrchestration",
        20 => "FailSpendOrchestration",
        22 => "InitRecovery",
        23 => "CompleteRecovery",
        24 => "MigrateAuthority",
        26 => "AdvanceWinterAuthority",
        27 => "InitPqcWallet",
        28 => "AdvancePqcWallet",
        _ => "Unknown",
    }
}
