use clap::Subcommand;

use super::parse_pubkey;

#[derive(Subcommand)]
pub enum PdaCmd {
    /// Derive vault registry PDA
    VaultRegistry {
        #[arg(long)]
        program_id: String,
        /// Owner wallet pubkey (base58)
        #[arg(long)]
        wallet_pubkey: String,
    },
    /// Derive policy receipt PDA
    PolicyReceipt {
        #[arg(long)]
        program_id: String,
        /// Vault ID (base58)
        #[arg(long)]
        vault_id: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
    },
    /// Derive action session PDA
    ActionSession {
        #[arg(long)]
        program_id: String,
        /// Vault ID (base58)
        #[arg(long)]
        vault_id: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
    },
    /// Derive quantum authority PDA
    QuantumAuthority {
        #[arg(long)]
        program_id: String,
        /// Vault ID (base58)
        #[arg(long)]
        vault_id: String,
    },
    /// Derive authority proof PDA
    AuthorityProof {
        #[arg(long)]
        program_id: String,
        /// Vault ID (base58)
        #[arg(long)]
        vault_id: String,
        /// Statement digest (hex, 32 bytes)
        #[arg(long)]
        statement_digest: String,
    },
    /// Derive quantum vault PDA
    QuantumVault {
        #[arg(long)]
        program_id: String,
        /// WOTS public-key hash (hex, 32 bytes)
        #[arg(long)]
        hash: String,
    },
    /// Derive spend orchestration PDA
    SpendOrchestration {
        #[arg(long)]
        program_id: String,
        /// Vault ID (base58)
        #[arg(long)]
        vault_id: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
    },
}

pub fn run(cmd: PdaCmd) -> Result<(), String> {
    match cmd {
        PdaCmd::VaultRegistry {
            program_id,
            wallet_pubkey,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let wallet = parse_pubkey(&wallet_pubkey)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_vault_registry(&wallet, &pid);
            print_pda("VaultRegistry", &addr, bump);
            Ok(())
        }
        PdaCmd::PolicyReceipt {
            program_id,
            vault_id,
            action_hash,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_id)?;
            let hash = super::parse_hash(&action_hash)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_policy_receipt(&vault, &hash, &pid);
            print_pda("PolicyReceipt", &addr, bump);
            Ok(())
        }
        PdaCmd::ActionSession {
            program_id,
            vault_id,
            action_hash,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_id)?;
            let hash = super::parse_hash(&action_hash)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_action_session(&vault, &hash, &pid);
            print_pda("ActionSession", &addr, bump);
            Ok(())
        }
        PdaCmd::QuantumAuthority {
            program_id,
            vault_id,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_id)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_quantum_authority(&vault, &pid);
            print_pda("QuantumAuthority", &addr, bump);
            Ok(())
        }
        PdaCmd::AuthorityProof {
            program_id,
            vault_id,
            statement_digest,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_id)?;
            let digest = super::parse_hash(&statement_digest)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_authority_proof(&vault, &digest, &pid);
            print_pda("AuthorityProof", &addr, bump);
            Ok(())
        }
        PdaCmd::QuantumVault { program_id, hash } => {
            let pid = parse_pubkey(&program_id)?;
            let h = super::parse_hash(&hash)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_quantum_vault(&h, &pid);
            print_pda("QuantumVault", &addr, bump);
            Ok(())
        }
        PdaCmd::SpendOrchestration {
            program_id,
            vault_id,
            action_hash,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_id)?;
            let hash = super::parse_hash(&action_hash)?;
            let (addr, bump) = vaulkyrie_sdk::pda::find_spend_orchestration(&vault, &hash, &pid);
            print_pda("SpendOrchestration", &addr, bump);
            Ok(())
        }
    }
}

fn print_pda(label: &str, addr: &solana_pubkey::Pubkey, bump: u8) {
    println!("{label} PDA:");
    println!("  address: {addr}");
    println!("  bump:    {bump}");
}
