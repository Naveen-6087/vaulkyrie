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
        policy_version: u64,
        #[arg(long)]
        bump: u8,
        /// Policy MXE program ID (hex, 32 bytes)
        #[arg(long)]
        policy_mxe_program: String,
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
    /// Generate an AdvancePolicyVersion instruction
    AdvancePolicy {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        #[arg(long)]
        new_policy_version: u64,
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
            policy_version,
            bump,
            policy_mxe_program,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let wp = parse_hash(&wallet_pubkey)?;
            let ah = parse_hash(&authority_hash)?;
            let mxe = parse_hash(&policy_mxe_program)?;

            let ix = vaulkyrie_sdk::instruction::init_vault(
                &pid,
                &vault,
                &signer,
                wp,
                ah,
                policy_version,
                bump,
                mxe,
            );
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
        VaultCmd::AdvancePolicy {
            program_id,
            vault_registry,
            wallet_signer: _,
            new_policy_version,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_registry)?;
            let ix = vaulkyrie_sdk::instruction::advance_policy_version(
                &pid,
                &vault,
                new_policy_version,
            );
            print_instruction_json("AdvancePolicyVersion", &ix);
            Ok(())
        }
    }
}
