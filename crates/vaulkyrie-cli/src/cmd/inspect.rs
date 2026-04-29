use clap::Subcommand;

use vaulkyrie_sdk::types::{
    AUTHORITY_PROOF_DISCRIMINATOR, PQC_WALLET_DISCRIMINATOR, QUANTUM_STATE_DISCRIMINATOR,
    RECOVERY_STATE_DISCRIMINATOR, SPEND_ORCH_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
};

#[derive(Subcommand)]
pub enum InspectCmd {
    /// Decode raw account data (hex) by auto-detecting discriminator
    Account {
        /// Account data (hex-encoded)
        #[arg(long)]
        data: String,
    },
}

pub fn run(cmd: InspectCmd) -> Result<(), String> {
    match cmd {
        InspectCmd::Account { data } => {
            let bytes = hex::decode(&data).map_err(|e| format!("invalid hex data: {e}"))?;
            if bytes.len() < 8 {
                return Err("account data too short (need ≥8 bytes for discriminator)".into());
            }
            let disc: [u8; 8] = bytes[..8].try_into().unwrap();

            let name = match disc {
                VAULT_REGISTRY_DISCRIMINATOR => {
                    let acct = vaulkyrie_sdk::accounts::VaultRegistry::decode(&bytes)
                        .ok_or("failed to decode VaultRegistry")?;
                    println!("{acct:#?}");
                    "VaultRegistry"
                }
                QUANTUM_STATE_DISCRIMINATOR => {
                    let acct = vaulkyrie_sdk::accounts::QuantumAuthorityState::decode(&bytes)
                        .ok_or("failed to decode QuantumAuthorityState")?;
                    println!("{acct:#?}");
                    "QuantumAuthority"
                }
                AUTHORITY_PROOF_DISCRIMINATOR => {
                    let acct = vaulkyrie_sdk::accounts::AuthorityProofState::decode(&bytes)
                        .ok_or("failed to decode AuthorityProofState")?;
                    println!("{acct:#?}");
                    "AuthorityProof"
                }
                SPEND_ORCH_DISCRIMINATOR => {
                    let acct = vaulkyrie_sdk::accounts::SpendOrchestrationState::decode(&bytes)
                        .ok_or("failed to decode SpendOrchestrationState")?;
                    println!("{acct:#?}");
                    "SpendOrchestration"
                }
                RECOVERY_STATE_DISCRIMINATOR => {
                    let acct = vaulkyrie_sdk::accounts::RecoveryState::decode(&bytes)
                        .ok_or("failed to decode RecoveryState")?;
                    println!("{acct:#?}");
                    "RecoveryState"
                }
                PQC_WALLET_DISCRIMINATOR => {
                    let acct = vaulkyrie_sdk::accounts::PqcWalletState::decode(&bytes)
                        .ok_or("failed to decode PqcWalletState")?;
                    println!("{acct:#?}");
                    "PqcWallet"
                }
                _ => {
                    return Err(format!("unknown discriminator: {}", hex::encode(disc)));
                }
            };
            println!("\n(Account type: {name})");
            Ok(())
        }
    }
}
