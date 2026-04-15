use clap::Subcommand;

use super::{parse_hash, parse_pubkey, print_instruction_json};

#[derive(Subcommand)]
pub enum QuantumCmd {
    /// Initialize a quantum vault (WOTS-based)
    Init {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_account: String,
        /// WOTS public key hash (hex, 32 bytes)
        #[arg(long)]
        wots_pubkey_hash: String,
        #[arg(long)]
        bump: u8,
    },
    /// Split a quantum vault (WOTS spend)
    Split {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_account: String,
        /// Split destination account (base58)
        #[arg(long)]
        split_dest: String,
        /// Refund destination account (base58)
        #[arg(long)]
        refund_dest: String,
        /// WOTS signature bytes (hex-encoded)
        #[arg(long)]
        signature: String,
        /// Amount to split (lamports)
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        bump: u8,
    },
    /// Close a quantum vault and reclaim SOL
    Close {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_account: String,
        /// Refund destination (base58)
        #[arg(long)]
        refund_dest: String,
        /// WOTS signature bytes (hex-encoded)
        #[arg(long)]
        signature: String,
        #[arg(long)]
        bump: u8,
    },
}

pub fn run(cmd: QuantumCmd) -> Result<(), String> {
    match cmd {
        QuantumCmd::Init {
            program_id,
            vault_account,
            wots_pubkey_hash,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_account)?;
            let hash = parse_hash(&wots_pubkey_hash)?;
            let ix = vaulkyrie_sdk::instruction::init_quantum_vault(&pid, &vault, hash, bump);
            print_instruction_json("InitQuantumVault", &ix);
            Ok(())
        }
        QuantumCmd::Split {
            program_id,
            vault_account,
            split_dest,
            refund_dest,
            signature,
            amount,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_account)?;
            let split = parse_pubkey(&split_dest)?;
            let refund = parse_pubkey(&refund_dest)?;
            let sig = hex::decode(&signature).map_err(|e| format!("invalid hex signature: {e}"))?;
            let ix = vaulkyrie_sdk::instruction::split_quantum_vault(
                &pid, &vault, &split, &refund, &sig, amount, bump,
            );
            print_instruction_json("SplitQuantumVault", &ix);
            Ok(())
        }
        QuantumCmd::Close {
            program_id,
            vault_account,
            refund_dest,
            signature,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_account)?;
            let refund = parse_pubkey(&refund_dest)?;
            let sig = hex::decode(&signature).map_err(|e| format!("invalid hex signature: {e}"))?;
            let ix =
                vaulkyrie_sdk::instruction::close_quantum_vault(&pid, &vault, &refund, &sig, bump);
            print_instruction_json("CloseQuantumVault", &ix);
            Ok(())
        }
    }
}
