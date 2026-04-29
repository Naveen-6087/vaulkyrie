use clap::Subcommand;

use super::{parse_hash, parse_pubkey, print_instruction_json};

#[derive(Subcommand)]
pub enum VaultCmd {
    /// Generate an InitVault instruction
    Init {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Wallet pubkey (hex, 32 bytes)
        #[arg(long)]
        wallet_pubkey: String,
        /// Authority hash (hex, 32 bytes)
        #[arg(long)]
        authority_hash: String,
        #[arg(long)]
        bump: u8,
    },
    /// Generate a SetVaultStatus instruction
    SetStatus {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// New status byte (1=Active, 2=Recovery, 3=Locked)
        #[arg(long)]
        status: u8,
    },
}

pub fn run(cmd: VaultCmd) -> Result<(), String> {
    match cmd {
        VaultCmd::Init {
            program_id,
            vault_registry,
            wallet_signer,
            wallet_pubkey,
            authority_hash,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let wp = parse_hash(&wallet_pubkey)?;
            let ah = parse_hash(&authority_hash)?;

            let ix = vaulkyrie_sdk::instruction::init_vault(&pid, &vault, &signer, wp, ah, bump);
            print_instruction_json("InitVault", &ix);
            Ok(())
        }
        VaultCmd::SetStatus {
            program_id,
            vault_registry,
            wallet_signer,
            status,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let ix = vaulkyrie_sdk::instruction::set_vault_status(&pid, &vault, &signer, status);
            print_instruction_json("SetVaultStatus", &ix);
            Ok(())
        }
    }
}
