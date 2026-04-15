use clap::Subcommand;

use super::{parse_hash, parse_pubkey, print_instruction_json};

#[derive(Subcommand)]
pub enum SpendCmd {
    /// Initialize a spend orchestration session
    Init {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        orch_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
        /// Session commitment (hex, 32 bytes)
        #[arg(long)]
        session_commitment: String,
        /// Signers commitment (hex, 32 bytes)
        #[arg(long)]
        signers_commitment: String,
        /// Signing package hash (hex, 32 bytes)
        #[arg(long)]
        signing_package_hash: String,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        participant_count: u8,
        #[arg(long)]
        bump: u8,
    },
    /// Commit a spend orchestration session
    Commit {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        orch_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
        /// Signing package hash (hex, 32 bytes)
        #[arg(long)]
        signing_package_hash: String,
    },
    /// Complete a spend orchestration with tx binding
    Complete {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        orch_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
        /// Transaction binding hash (hex, 32 bytes)
        #[arg(long)]
        tx_binding: String,
    },
    /// Fail / abort a spend orchestration
    Fail {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        orch_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
        /// Failure reason code (0-255)
        #[arg(long)]
        reason: u8,
    },
}

pub fn run(cmd: SpendCmd) -> Result<(), String> {
    match cmd {
        SpendCmd::Init {
            program_id,
            orch_account,
            vault_registry,
            wallet_signer,
            action_hash,
            session_commitment,
            signers_commitment,
            signing_package_hash,
            expiry_slot,
            threshold,
            participant_count,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let orch = parse_pubkey(&orch_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let ah = parse_hash(&action_hash)?;
            let sc = parse_hash(&session_commitment)?;
            let sigc = parse_hash(&signers_commitment)?;
            let sph = parse_hash(&signing_package_hash)?;
            let ix = vaulkyrie_sdk::instruction::init_spend_orchestration(
                &pid,
                &orch,
                &vault,
                &signer,
                ah,
                sc,
                sigc,
                sph,
                expiry_slot,
                threshold,
                participant_count,
                bump,
            );
            print_instruction_json("InitSpendOrchestration", &ix);
            Ok(())
        }
        SpendCmd::Commit {
            program_id,
            orch_account,
            vault_registry,
            wallet_signer,
            action_hash,
            signing_package_hash,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let orch = parse_pubkey(&orch_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let ah = parse_hash(&action_hash)?;
            let sph = parse_hash(&signing_package_hash)?;
            let ix = vaulkyrie_sdk::instruction::commit_spend_orchestration(
                &pid, &orch, &vault, &signer, ah, sph,
            );
            print_instruction_json("CommitSpendOrchestration", &ix);
            Ok(())
        }
        SpendCmd::Complete {
            program_id,
            orch_account,
            vault_registry,
            wallet_signer,
            action_hash,
            tx_binding,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let orch = parse_pubkey(&orch_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let ah = parse_hash(&action_hash)?;
            let txb = parse_hash(&tx_binding)?;
            let ix = vaulkyrie_sdk::instruction::complete_spend_orchestration(
                &pid, &orch, &vault, &signer, ah, txb,
            );
            print_instruction_json("CompleteSpendOrchestration", &ix);
            Ok(())
        }
        SpendCmd::Fail {
            program_id,
            orch_account,
            vault_registry,
            wallet_signer,
            action_hash,
            reason,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let orch = parse_pubkey(&orch_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let ah = parse_hash(&action_hash)?;
            let ix = vaulkyrie_sdk::instruction::fail_spend_orchestration(
                &pid, &orch, &vault, &signer, ah, reason,
            );
            print_instruction_json("FailSpendOrchestration", &ix);
            Ok(())
        }
    }
}
