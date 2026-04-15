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
        0x01 => "InitVaultRegistry",
        0x02 => "SetVaultStatus",
        0x03 => "AdvancePolicyVersion",
        0x10 => "StageReceipt",
        0x11 => "ConsumeReceipt",
        0x12 => "OpenActionSession",
        0x13 => "ActivateActionSession",
        0x14 => "ConsumeActionSession",
        0x15 => "FinalizeActionSession",
        0x16 => "StageBridgedReceipt",
        0x20 => "InitQuantumAuthority",
        0x21 => "RotateQuantumAuthority",
        0x22 => "InitAuthorityProof",
        0x23 => "WriteProofChunk",
        0x24 => "RotateAuthorityStaged",
        0x30 => "InitQuantumVault",
        0x31 => "SplitQuantumVault",
        0x32 => "CloseQuantumVault",
        0x40 => "InitSpendOrchestration",
        0x41 => "CommitSpendOrchestration",
        0x42 => "CompleteSpendOrchestration",
        0x43 => "FailSpendOrchestration",
        0x50 => "InitRecovery",
        0x51 => "CompleteRecovery",
        0x52 => "MigrateAuthority",
        _ => "Unknown",
    }
}
