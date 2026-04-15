use clap::Subcommand;

use super::{parse_hash, parse_pubkey, print_instruction_json};

#[derive(Subcommand)]
pub enum RecoveryCmd {
    /// Initiate a vault recovery flow
    Init {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        recovery_account: String,
        #[arg(long)]
        vault_registry: String,
        /// Vault pubkey bytes (hex, 32 bytes)
        #[arg(long)]
        vault_pubkey: String,
        /// Recovery commitment hash (hex, 32 bytes)
        #[arg(long)]
        recovery_commitment: String,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        new_threshold: u8,
        #[arg(long)]
        new_participant_count: u8,
        #[arg(long)]
        bump: u8,
    },
    /// Complete a recovery with new group key
    Complete {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        recovery_account: String,
        /// New group key (hex, 32 bytes)
        #[arg(long)]
        new_group_key: String,
        /// New authority hash (hex, 32 bytes)
        #[arg(long)]
        new_authority_hash: String,
    },
    /// Migrate authority after recovery
    MigrateAuthority {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        authority_account: String,
        /// New authority root hash (hex, 32 bytes)
        #[arg(long)]
        new_authority_root: String,
    },
}

pub fn run(cmd: RecoveryCmd) -> Result<(), String> {
    match cmd {
        RecoveryCmd::Init {
            program_id,
            recovery_account,
            vault_registry,
            vault_pubkey,
            recovery_commitment,
            expiry_slot,
            new_threshold,
            new_participant_count,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let recovery = parse_pubkey(&recovery_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let vk = parse_hash(&vault_pubkey)?;
            let rc = parse_hash(&recovery_commitment)?;
            let ix = vaulkyrie_sdk::instruction::init_recovery(
                &pid,
                &recovery,
                &vault,
                vk,
                rc,
                expiry_slot,
                new_threshold,
                new_participant_count,
                bump,
            );
            print_instruction_json("InitRecovery", &ix);
            Ok(())
        }
        RecoveryCmd::Complete {
            program_id,
            recovery_account,
            new_group_key,
            new_authority_hash,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let recovery = parse_pubkey(&recovery_account)?;
            let ngk = parse_hash(&new_group_key)?;
            let nah = parse_hash(&new_authority_hash)?;
            let ix = vaulkyrie_sdk::instruction::complete_recovery(&pid, &recovery, ngk, nah);
            print_instruction_json("CompleteRecovery", &ix);
            Ok(())
        }
        RecoveryCmd::MigrateAuthority {
            program_id,
            authority_account,
            new_authority_root,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let authority = parse_pubkey(&authority_account)?;
            let nar = parse_hash(&new_authority_root)?;
            let ix = vaulkyrie_sdk::instruction::migrate_authority(&pid, &authority, nar);
            print_instruction_json("MigrateAuthority", &ix);
            Ok(())
        }
    }
}
