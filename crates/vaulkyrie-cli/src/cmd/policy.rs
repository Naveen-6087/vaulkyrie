use clap::Subcommand;
use vaulkyrie_protocol::{PolicyReceipt, ThresholdRequirement};

use super::{parse_hash, parse_pubkey, print_instruction_json};

#[derive(Subcommand)]
pub enum PolicyCmd {
    /// Stage a policy receipt on-chain
    Stage {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        receipt_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        #[arg(long)]
        action_hash: String,
        #[arg(long)]
        policy_version: u64,
        /// Threshold (1=OneOfThree, 2=TwoOfThree, 3=ThreeOfThree, 255=RequirePqcAuth)
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        expiry_slot: u64,
    },
    /// Consume a policy receipt
    Consume {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        receipt_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        #[arg(long)]
        action_hash: String,
        #[arg(long)]
        policy_version: u64,
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        expiry_slot: u64,
    },
    /// Open a session from a policy receipt
    OpenSession {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        receipt_account: String,
        #[arg(long)]
        session_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        #[arg(long)]
        action_hash: String,
        #[arg(long)]
        policy_version: u64,
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        expiry_slot: u64,
    },
    /// Stage a bridged receipt from the policy MXE program
    StageBridged {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        receipt_account: String,
        #[arg(long)]
        wallet_signer: String,
        #[arg(long)]
        policy_eval_account: String,
        #[arg(long)]
        action_hash: String,
        #[arg(long)]
        policy_version: u64,
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        expiry_slot: u64,
    },
}

fn make_receipt(
    action_hash_hex: &str,
    policy_version: u64,
    threshold: u8,
    nonce: u64,
    expiry_slot: u64,
) -> Result<PolicyReceipt, String> {
    let action_hash = parse_hash(action_hash_hex)?;
    let threshold =
        ThresholdRequirement::try_from(threshold).map_err(|_| "invalid threshold value")?;
    Ok(PolicyReceipt {
        action_hash,
        policy_version,
        threshold,
        nonce,
        expiry_slot,
    })
}

pub fn run(cmd: PolicyCmd) -> Result<(), String> {
    match cmd {
        PolicyCmd::Stage {
            program_id,
            receipt_account,
            vault_registry,
            wallet_signer,
            action_hash,
            policy_version,
            threshold,
            nonce,
            expiry_slot,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let receipt = parse_pubkey(&receipt_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let r = make_receipt(&action_hash, policy_version, threshold, nonce, expiry_slot)?;
            let ix = vaulkyrie_sdk::instruction::stage_receipt(&pid, &vault, &receipt, &signer, &r);
            print_instruction_json("StageReceipt", &ix);
            Ok(())
        }
        PolicyCmd::Consume {
            program_id,
            receipt_account,
            vault_registry,
            wallet_signer,
            action_hash,
            policy_version,
            threshold,
            nonce,
            expiry_slot,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let receipt = parse_pubkey(&receipt_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let r = make_receipt(&action_hash, policy_version, threshold, nonce, expiry_slot)?;
            let ix =
                vaulkyrie_sdk::instruction::consume_receipt(&pid, &vault, &receipt, &signer, &r);
            print_instruction_json("ConsumeReceipt", &ix);
            Ok(())
        }
        PolicyCmd::OpenSession {
            program_id,
            receipt_account,
            session_account,
            vault_registry,
            wallet_signer,
            action_hash,
            policy_version,
            threshold,
            nonce,
            expiry_slot,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let receipt = parse_pubkey(&receipt_account)?;
            let session = parse_pubkey(&session_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let r = make_receipt(&action_hash, policy_version, threshold, nonce, expiry_slot)?;
            let ix = vaulkyrie_sdk::instruction::open_session(
                &pid, &receipt, &session, &vault, &signer, &r,
            );
            print_instruction_json("OpenSession", &ix);
            Ok(())
        }
        PolicyCmd::StageBridged {
            program_id,
            vault_registry,
            receipt_account,
            wallet_signer,
            policy_eval_account,
            action_hash,
            policy_version,
            threshold,
            nonce,
            expiry_slot,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_registry)?;
            let receipt = parse_pubkey(&receipt_account)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let eval = parse_pubkey(&policy_eval_account)?;
            let r = make_receipt(&action_hash, policy_version, threshold, nonce, expiry_slot)?;
            let ix = vaulkyrie_sdk::instruction::stage_bridged_receipt(
                &pid, &vault, &receipt, &signer, &eval, &r,
            );
            print_instruction_json("StageBridgedReceipt", &ix);
            Ok(())
        }
    }
}
