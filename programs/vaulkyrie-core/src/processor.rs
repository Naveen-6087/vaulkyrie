use pinocchio::{
    account_info::AccountInfo,
    get_account_info,
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program::invoke_signed,
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use solana_winternitz::signature::WinternitzSignature;
use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt, WotsAuthProof};

use crate::{
    error,
    instruction::{
        CommitSpendOrchestrationArgs, CompleteSpendOrchestrationArgs, CoreInstruction,
        FailSpendOrchestrationArgs, InitAuthorityArgs, InitAuthorityProofArgs,
        InitQuantumVaultArgs, InitSpendOrchestrationArgs, InitVaultArgs,
        WriteAuthorityProofChunkArgs,
    },
    pda,
    state::{
        ActionSessionState, AuthorityProofState, PolicyReceiptState, QuantumAuthorityState,
        SpendOrchestrationState, VaultRegistry, ACTION_SESSION_DISCRIMINATOR,
        AUTHORITY_PROOF_DISCRIMINATOR, POLICY_RECEIPT_DISCRIMINATOR, QUANTUM_STATE_DISCRIMINATOR,
        SPEND_ORCH_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
    },
    transition,
};

const SYSTEM_PROGRAM_ID: pinocchio::pubkey::Pubkey = [0; 32];

pub fn process(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    instruction: CoreInstruction,
) -> ProgramResult {
    match instruction {
        CoreInstruction::Ping => Ok(()),
        CoreInstruction::InitVault(args) => {
            let wallet_signer = get_account_info!(accounts, 1);
            ensure_wallet_authority(
                args.wallet_pubkey,
                *wallet_signer.key(),
                wallet_signer.is_signer(),
            )?;

            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            pda::verify_vault_registry(account.key(), &args.wallet_pubkey, args.bump, program_id)?;
            let mut data = account.try_borrow_mut_data()?;
            process_init_vault_data(&mut data, args)
        }
        CoreInstruction::InitAuthority(args) => {
            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;

            let wallet_signer = get_account_info!(accounts, 2);
            require_wallet_authority(&vault, wallet_signer)?;
            if vault.current_authority_hash != args.current_authority_hash {
                return Err(ProgramError::Custom(error::AUTHORITY_HASH_MISMATCH));
            }

            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            pda::verify_quantum_authority(
                account.key(),
                vault_account.key(),
                args.bump,
                program_id,
            )?;
            let mut data = account.try_borrow_mut_data()?;
            process_init_authority_data(&mut data, args)
        }
        CoreInstruction::InitQuantumVault(args) => {
            process_open_quantum_vault(program_id, accounts, args)
        }
        CoreInstruction::StageReceipt(receipt) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 0);
            require_program_owner(program_id, vault_account)?;

            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                let wallet_signer = get_account_info!(accounts, 2);
                require_wallet_authority(&vault, wallet_signer)?;
            }

            let vault_data = vault_account.try_borrow_data()?;

            let receipt_account = get_account_info!(accounts, 1);
            require_writable(receipt_account)?;
            require_program_owner(program_id, receipt_account)?;
            let mut receipt_data = receipt_account.try_borrow_mut_data()?;

            process_stage_receipt_data(&vault_data, &mut receipt_data, &receipt, current_slot)
        }
        CoreInstruction::ConsumeReceipt(receipt) => {
            let vault_account = get_account_info!(accounts, 0);
            require_writable(vault_account)?;
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            transition::validate_vault_active(&vault).map_err(map_transition_error)?;
            let wallet_signer = get_account_info!(accounts, 2);
            require_wallet_authority(&vault, wallet_signer)?;
            drop(vault_data);

            let mut vault_data = vault_account.try_borrow_mut_data()?;

            let receipt_account = get_account_info!(accounts, 1);
            require_writable(receipt_account)?;
            require_program_owner(program_id, receipt_account)?;
            let mut receipt_data = receipt_account.try_borrow_mut_data()?;
            process_consume_receipt_data(&mut vault_data, &mut receipt_data, &receipt)
        }
        CoreInstruction::OpenSession(receipt) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 2);
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            transition::validate_vault_for_receipt(&vault, &receipt, current_slot)
                .map_err(map_transition_error)?;
            let wallet_signer = get_account_info!(accounts, 3);
            require_wallet_authority(&vault, wallet_signer)?;

            let receipt_account = get_account_info!(accounts, 0);
            require_program_owner(program_id, receipt_account)?;
            let receipt_data = receipt_account.try_borrow_data()?;

            let session_account = get_account_info!(accounts, 1);
            require_writable(session_account)?;
            require_program_owner(program_id, session_account)?;
            let mut session_data = session_account.try_borrow_mut_data()?;

            process_open_session_data(&receipt_data, &mut session_data, &receipt, current_slot)
        }
        CoreInstruction::ActivateSession(action_hash) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            transition::validate_vault_active(&vault).map_err(map_transition_error)?;
            let wallet_signer = get_account_info!(accounts, 2);
            require_wallet_authority(&vault, wallet_signer)?;

            let session_account = get_account_info!(accounts, 0);
            require_writable(session_account)?;
            require_program_owner(program_id, session_account)?;
            let mut session_data = session_account.try_borrow_mut_data()?;
            process_activate_session_data(
                &mut session_data,
                action_hash,
                current_slot,
                vault.policy_version,
            )
        }
        CoreInstruction::ConsumeSession(action_hash) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            transition::validate_vault_active(&vault).map_err(map_transition_error)?;
            let wallet_signer = get_account_info!(accounts, 2);
            require_wallet_authority(&vault, wallet_signer)?;

            let session_account = get_account_info!(accounts, 0);
            require_writable(session_account)?;
            require_program_owner(program_id, session_account)?;
            let mut session_data = session_account.try_borrow_mut_data()?;
            process_consume_session_data(
                &mut session_data,
                action_hash,
                current_slot,
                vault.policy_version,
            )
        }
        CoreInstruction::FinalizeSession(receipt) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 2);
            require_writable(vault_account)?;
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            transition::validate_vault_active(&vault).map_err(map_transition_error)?;
            let wallet_signer = get_account_info!(accounts, 3);
            require_wallet_authority(&vault, wallet_signer)?;
            drop(vault_data);
            let mut vault_data = vault_account.try_borrow_mut_data()?;

            let receipt_account = get_account_info!(accounts, 0);
            require_writable(receipt_account)?;
            require_program_owner(program_id, receipt_account)?;
            let mut receipt_data = receipt_account.try_borrow_mut_data()?;

            let session_account = get_account_info!(accounts, 1);
            require_writable(session_account)?;
            require_program_owner(program_id, session_account)?;
            let mut session_data = session_account.try_borrow_mut_data()?;

            process_finalize_session_data(
                &mut vault_data,
                &mut receipt_data,
                &mut session_data,
                &receipt,
                current_slot,
                vault.policy_version,
            )
        }
        CoreInstruction::SetVaultStatus(status) => {
            let vault_account = get_account_info!(accounts, 0);
            require_program_owner(program_id, vault_account)?;
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                let wallet_signer = get_account_info!(accounts, 1);
                require_wallet_authority(&vault, wallet_signer)?;
            }
            require_writable(vault_account)?;
            let mut vault_data = vault_account.try_borrow_mut_data()?;
            process_set_vault_status_data(&mut vault_data, status)
        }
        CoreInstruction::RotateAuthority(args) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 0);
            require_program_owner(program_id, vault_account)?;
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                transition::validate_vault_recovery_mode(&vault).map_err(map_transition_error)?;
                let wallet_signer = get_account_info!(accounts, 2);
                require_wallet_authority(&vault, wallet_signer)?;
            }
            require_writable(vault_account)?;
            let mut vault_data = vault_account.try_borrow_mut_data()?;

            let authority_account = get_account_info!(accounts, 1);
            require_writable(authority_account)?;
            require_program_owner(program_id, authority_account)?;
            let mut authority_data = authority_account.try_borrow_mut_data()?;

            process_rotate_authority_data(
                &mut vault_data,
                &mut authority_data,
                &args.statement,
                &args.proof,
                current_slot,
            )
        }
        CoreInstruction::InitAuthorityProof(args) => {
            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            let wallet_signer = get_account_info!(accounts, 2);
            require_wallet_authority(&vault, wallet_signer)?;

            let proof_account = get_account_info!(accounts, 0);
            require_writable(proof_account)?;
            require_program_owner(program_id, proof_account)?;
            let mut proof_data = proof_account.try_borrow_mut_data()?;

            process_init_authority_proof_data(&mut proof_data, args)
        }
        CoreInstruction::WriteAuthorityProofChunk(args) => {
            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;
            let vault_data = vault_account.try_borrow_data()?;
            let vault = decode_vault_state(&vault_data)?;
            let wallet_signer = get_account_info!(accounts, 2);
            require_wallet_authority(&vault, wallet_signer)?;

            let proof_account = get_account_info!(accounts, 0);
            require_writable(proof_account)?;
            require_program_owner(program_id, proof_account)?;
            let mut proof_data = proof_account.try_borrow_mut_data()?;

            process_write_authority_proof_chunk_data(&mut proof_data, args)
        }
        CoreInstruction::RotateAuthorityStaged(statement) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 0);
            require_program_owner(program_id, vault_account)?;
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                transition::validate_vault_recovery_mode(&vault).map_err(map_transition_error)?;
                let wallet_signer = get_account_info!(accounts, 3);
                require_wallet_authority(&vault, wallet_signer)?;
            }
            require_writable(vault_account)?;
            let mut vault_data = vault_account.try_borrow_mut_data()?;

            let authority_account = get_account_info!(accounts, 1);
            require_writable(authority_account)?;
            require_program_owner(program_id, authority_account)?;
            let mut authority_data = authority_account.try_borrow_mut_data()?;

            let proof_account = get_account_info!(accounts, 2);
            require_writable(proof_account)?;
            require_program_owner(program_id, proof_account)?;
            let mut proof_data = proof_account.try_borrow_mut_data()?;

            process_rotate_authority_staged_data(
                &mut vault_data,
                &mut authority_data,
                &mut proof_data,
                &statement,
                current_slot,
            )
        }
        CoreInstruction::SplitQuantumVault(args) => {
            let vault_account = get_account_info!(accounts, 0);
            require_writable(vault_account)?;
            require_program_owner(program_id, vault_account)?;

            let split_account = get_account_info!(accounts, 1);
            require_writable(split_account)?;
            let refund_account = get_account_info!(accounts, 2);
            require_writable(refund_account)?;

            if vault_account.key() == split_account.key()
                || vault_account.key() == refund_account.key()
                || split_account.key() == refund_account.key()
            {
                return Err(ProgramError::Custom(error::DUPLICATE_ACCOUNT_KEYS));
            }

            {
                process_split_quantum_vault(
                    args.amount,
                    *split_account.key(),
                    *refund_account.key(),
                    &args.signature(),
                    args.bump,
                    *vault_account.key(),
                    *program_id,
                    vault_account.lamports(),
                )?;
            }

            {
                let mut split_lamports = split_account.try_borrow_mut_lamports()?;
                *split_lamports += args.amount;
            }
            {
                let refund_amount = vault_account.lamports().saturating_sub(args.amount);
                let mut refund_lamports = refund_account.try_borrow_mut_lamports()?;
                *refund_lamports += refund_amount;
            }

            vault_account.close()
        }
        CoreInstruction::CloseQuantumVault(args) => {
            let vault_account = get_account_info!(accounts, 0);
            require_writable(vault_account)?;
            require_program_owner(program_id, vault_account)?;

            let refund_account = get_account_info!(accounts, 1);
            require_writable(refund_account)?;
            if vault_account.key() == refund_account.key() {
                return Err(ProgramError::Custom(error::DUPLICATE_ACCOUNT_KEYS));
            }

            {
                process_close_quantum_vault(
                    *refund_account.key(),
                    &args.signature(),
                    args.bump,
                    *vault_account.key(),
                    *program_id,
                )?;
            }

            {
                let mut refund_lamports = refund_account.try_borrow_mut_lamports()?;
                *refund_lamports += vault_account.lamports();
            }

            vault_account.close()
        }
        CoreInstruction::InitSpendOrchestration(args) => {
            let current_slot = current_slot()?;
            let orch_account = get_account_info!(accounts, 0);
            require_writable(orch_account)?;
            require_program_owner(program_id, orch_account)?;

            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;
            pda::verify_spend_orchestration(
                orch_account.key(),
                vault_account.key(),
                &args.action_hash,
                args.bump,
                program_id,
            )?;

            let wallet_signer = get_account_info!(accounts, 2);
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                require_wallet_authority(&vault, wallet_signer)?;
            }

            let mut orch_data = orch_account.try_borrow_mut_data()?;
            process_init_spend_orchestration_data(&mut orch_data, args, current_slot)
        }
        CoreInstruction::CommitSpendOrchestration(args) => {
            let current_slot = current_slot()?;
            let orch_account = get_account_info!(accounts, 0);
            require_writable(orch_account)?;
            require_program_owner(program_id, orch_account)?;

            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;

            let wallet_signer = get_account_info!(accounts, 2);
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                require_wallet_authority(&vault, wallet_signer)?;
            }

            let mut orch_data = orch_account.try_borrow_mut_data()?;
            process_commit_spend_orchestration_data(&mut orch_data, args, current_slot)
        }
        CoreInstruction::CompleteSpendOrchestration(args) => {
            let current_slot = current_slot()?;
            let orch_account = get_account_info!(accounts, 0);
            require_writable(orch_account)?;
            require_program_owner(program_id, orch_account)?;

            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;

            let wallet_signer = get_account_info!(accounts, 2);
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                require_wallet_authority(&vault, wallet_signer)?;
            }

            let mut orch_data = orch_account.try_borrow_mut_data()?;
            process_complete_spend_orchestration_data(&mut orch_data, args, current_slot)
        }
        CoreInstruction::FailSpendOrchestration(args) => {
            let orch_account = get_account_info!(accounts, 0);
            require_writable(orch_account)?;
            require_program_owner(program_id, orch_account)?;

            let vault_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, vault_account)?;

            let wallet_signer = get_account_info!(accounts, 2);
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                require_wallet_authority(&vault, wallet_signer)?;
            }

            let mut orch_data = orch_account.try_borrow_mut_data()?;
            process_fail_spend_orchestration_data(&mut orch_data, args)
        }
        CoreInstruction::StageBridgedReceipt(receipt) => {
            let current_slot = current_slot()?;
            let vault_account = get_account_info!(accounts, 0);
            require_program_owner(program_id, vault_account)?;

            let receipt_account = get_account_info!(accounts, 1);
            require_writable(receipt_account)?;
            require_program_owner(program_id, receipt_account)?;

            let wallet_signer = get_account_info!(accounts, 2);
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                require_wallet_authority(&vault, wallet_signer)?;
            }

            // [3] = policy_eval account (readonly, owner validated against vault)
            let policy_eval_account = get_account_info!(accounts, 3);
            {
                let vault_data = vault_account.try_borrow_data()?;
                let vault = decode_vault_state(&vault_data)?;
                let owner_bytes: [u8; 32] = policy_eval_account
                    .owner()
                    .as_ref()
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?;
                transition::validate_eval_account_owner(&owner_bytes, &vault)
                    .map_err(|_| ProgramError::IllegalOwner)?;
            }
            let policy_eval_data = policy_eval_account.try_borrow_data()?;

            let vault_data = vault_account.try_borrow_data()?;
            let mut receipt_data = receipt_account.try_borrow_mut_data()?;
            process_stage_bridged_receipt_data(
                &vault_data,
                &mut receipt_data,
                &policy_eval_data,
                &receipt,
                current_slot,
            )
        }

        CoreInstruction::InitRecovery(args) => {
            let current_slot = current_slot()?;
            // [0] = recovery_state (writable, uninitialized PDA)
            // [1] = vault (readonly, must be in Recovery status)
            let recovery_account = get_account_info!(accounts, 0);
            let vault_account = get_account_info!(accounts, 1);

            let vault_data = vault_account.try_borrow_data()?;
            let vault = VaultRegistry::decode(&vault_data[..VaultRegistry::LEN])
                .ok_or(ProgramError::InvalidAccountData)?;

            let mut recovery_data = recovery_account.try_borrow_mut_data()?;
            process_init_recovery_data(&mut recovery_data, args, vault.status, current_slot)
        }

        CoreInstruction::CompleteRecovery(args) => {
            let current_slot = current_slot()?;
            // [0] = recovery_state (writable)
            let recovery_account = get_account_info!(accounts, 0);
            let mut recovery_data = recovery_account.try_borrow_mut_data()?;
            process_complete_recovery_data(&mut recovery_data, args, current_slot)
        }

        CoreInstruction::MigrateAuthority(args) => {
            // [0] = authority_state (writable)
            let authority_account = get_account_info!(accounts, 0);
            let mut authority_data = authority_account.try_borrow_mut_data()?;
            process_migrate_authority_data(&mut authority_data, args.new_authority_root)
        }
        CoreInstruction::AdvancePolicyVersion(args) => {
            // [0] = vault_registry (writable)
            let vault_account = get_account_info!(accounts, 0);
            let mut vault_data = vault_account.try_borrow_mut_data()?;
            process_advance_policy_version_data(&mut vault_data, args.new_version)
        }
    }
}

pub fn process_stage_bridged_receipt_data(
    vault_src: &[u8],
    receipt_dst: &mut [u8],
    policy_eval_src: &[u8],
    receipt: &PolicyReceipt,
    current_slot: u64,
) -> ProgramResult {
    transition::validate_bridged_receipt_claim(policy_eval_src, receipt, current_slot)
        .map_err(map_transition_error)?;
    process_stage_receipt_data(vault_src, receipt_dst, receipt, current_slot)
}

pub fn process_set_vault_status_data(dst: &mut [u8], status: u8) -> ProgramResult {
    if dst.len() != VaultRegistry::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut vault = VaultRegistry::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;
    let next_status = transition::parse_vault_status(status).map_err(map_transition_error)?;
    transition::update_vault_status(&mut vault, next_status).map_err(map_transition_error)?;

    if !vault.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_init_vault_data(dst: &mut [u8], args: InitVaultArgs) -> ProgramResult {
    if dst.len() != VaultRegistry::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = transition::initialize_vault(
        args.wallet_pubkey,
        args.authority_hash,
        args.policy_version,
        args.bump,
        args.policy_mxe_program,
    );

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_init_authority_data(dst: &mut [u8], args: InitAuthorityArgs) -> ProgramResult {
    if dst.len() != QuantumAuthorityState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = transition::initialize_quantum_authority(
        args.current_authority_hash,
        args.current_authority_root,
        args.bump,
    );
    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_open_quantum_vault(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    args: InitQuantumVaultArgs,
) -> ProgramResult {
    let [payer, vault, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    require_writable(payer)?;
    require_writable(vault)?;
    if system_program.key() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let lamports = Rent::get()?.minimum_balance(0);
    let bump_seed = [args.bump];
    let seeds = [Seed::from(&args.hash), Seed::from(&bump_seed)];
    let signers = [Signer::from(&seeds)];
    let account_metas = [
        AccountMeta::writable_signer(payer.key()),
        AccountMeta::writable_signer(vault.key()),
    ];
    let mut instruction_data = [0u8; 52];
    instruction_data[4..12].copy_from_slice(&lamports.to_le_bytes());
    instruction_data[12..20].copy_from_slice(&0u64.to_le_bytes());
    instruction_data[20..52].copy_from_slice(program_id);
    let instruction = Instruction {
        program_id: &SYSTEM_PROGRAM_ID,
        accounts: &account_metas,
        data: &instruction_data,
    };

    invoke_signed(&instruction, &[payer, vault], &signers)
}

pub fn process_init_authority_proof_data(
    dst: &mut [u8],
    args: InitAuthorityProofArgs,
) -> ProgramResult {
    if dst.len() != AuthorityProofState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = AuthorityProofState::new(args.statement_digest, args.proof_commitment);
    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_write_authority_proof_chunk_data(
    dst: &mut [u8],
    args: WriteAuthorityProofChunkArgs,
) -> ProgramResult {
    if dst.len() != AuthorityProofState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = AuthorityProofState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &AUTHORITY_PROOF_DISCRIMINATOR)?;
    if state.consumed != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let offset = usize::try_from(args.offset)
        .map_err(|_| ProgramError::Custom(error::PROOF_CHUNK_OFFSET_MISMATCH))?;
    let chunk = args.chunk_bytes();
    if offset != state.bytes_written as usize {
        return Err(ProgramError::Custom(error::PROOF_CHUNK_OFFSET_MISMATCH));
    }
    let end = offset
        .checked_add(chunk.len())
        .ok_or(ProgramError::Custom(error::PROOF_CHUNK_OVERFLOW))?;
    if end > WotsAuthProof::ENCODED_LEN {
        return Err(ProgramError::Custom(error::PROOF_CHUNK_TOO_LARGE));
    }

    state.proof_bytes[offset..end].copy_from_slice(chunk);
    state.bytes_written = end as u32;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_split_quantum_vault(
    amount: u64,
    split_pubkey: [u8; 32],
    refund_pubkey: [u8; 32],
    signature: &WinternitzSignature,
    bump: u8,
    vault_pubkey: [u8; 32],
    program_id: [u8; 32],
    vault_lamports: u64,
) -> ProgramResult {
    transition::validate_quantum_vault_split_amount(vault_lamports, amount)
        .map_err(map_transition_error)?;
    transition::validate_quantum_vault_split(
        signature,
        amount,
        split_pubkey,
        refund_pubkey,
        bump,
        vault_pubkey,
        program_id,
    )
    .map_err(map_transition_error)
}

pub fn process_close_quantum_vault(
    refund_pubkey: [u8; 32],
    signature: &WinternitzSignature,
    bump: u8,
    vault_pubkey: [u8; 32],
    program_id: [u8; 32],
) -> ProgramResult {
    transition::validate_quantum_vault_close(
        signature,
        refund_pubkey,
        bump,
        vault_pubkey,
        program_id,
    )
    .map_err(map_transition_error)
}

pub fn process_stage_receipt_data(
    vault_src: &[u8],
    receipt_dst: &mut [u8],
    receipt: &PolicyReceipt,
    current_slot: u64,
) -> ProgramResult {
    if vault_src.len() != VaultRegistry::LEN || receipt_dst.len() != PolicyReceiptState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(receipt_dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let vault = VaultRegistry::decode(vault_src).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;
    transition::validate_vault_for_receipt(&vault, receipt, current_slot)
        .map_err(map_transition_error)?;

    let state = transition::stage_policy_receipt(receipt);
    if !state.encode(receipt_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_consume_receipt_data(
    vault_dst: &mut [u8],
    receipt_dst: &mut [u8],
    receipt: &PolicyReceipt,
) -> ProgramResult {
    if vault_dst.len() != VaultRegistry::LEN || receipt_dst.len() != PolicyReceiptState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut vault = VaultRegistry::decode(vault_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;
    transition::validate_vault_active(&vault).map_err(map_transition_error)?;
    if vault.policy_version != receipt.policy_version {
        return Err(ProgramError::Custom(error::POLICY_VERSION_MISMATCH));
    }

    let mut state =
        PolicyReceiptState::decode(receipt_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &POLICY_RECEIPT_DISCRIMINATOR)?;
    transition::consume_policy_receipt_for_vault(&mut vault, &mut state, receipt)
        .map_err(map_transition_error)?;

    if !vault.encode(vault_dst) || !state.encode(receipt_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_open_session_data(
    receipt_src: &[u8],
    session_dst: &mut [u8],
    receipt: &PolicyReceipt,
    current_slot: u64,
) -> ProgramResult {
    if receipt_src.len() != PolicyReceiptState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if session_dst.len() != ActionSessionState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(session_dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let receipt_state =
        PolicyReceiptState::decode(receipt_src).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&receipt_state.discriminator, &POLICY_RECEIPT_DISCRIMINATOR)?;

    let state = transition::open_action_session_from_receipt(&receipt_state, receipt, current_slot)
        .map_err(map_transition_error)?;
    if !state.encode(session_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_activate_session_data(
    dst: &mut [u8],
    action_hash: [u8; 32],
    current_slot: u64,
    expected_policy_version: u64,
) -> ProgramResult {
    if dst.len() != ActionSessionState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = ActionSessionState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &ACTION_SESSION_DISCRIMINATOR)?;
    if state.policy_version != expected_policy_version {
        return Err(ProgramError::Custom(error::POLICY_VERSION_MISMATCH));
    }
    transition::mark_action_session_ready(&mut state, action_hash, current_slot)
        .map_err(map_transition_error)?;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_consume_session_data(
    dst: &mut [u8],
    action_hash: [u8; 32],
    current_slot: u64,
    expected_policy_version: u64,
) -> ProgramResult {
    if dst.len() != ActionSessionState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = ActionSessionState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &ACTION_SESSION_DISCRIMINATOR)?;
    if state.policy_version != expected_policy_version {
        return Err(ProgramError::Custom(error::POLICY_VERSION_MISMATCH));
    }
    transition::consume_action_session(&mut state, action_hash, current_slot)
        .map_err(map_transition_error)?;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_finalize_session_data(
    vault_dst: &mut [u8],
    receipt_dst: &mut [u8],
    session_dst: &mut [u8],
    receipt: &PolicyReceipt,
    current_slot: u64,
    expected_policy_version: u64,
) -> ProgramResult {
    if vault_dst.len() != VaultRegistry::LEN
        || receipt_dst.len() != PolicyReceiptState::LEN
        || session_dst.len() != ActionSessionState::LEN
    {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut vault_state =
        VaultRegistry::decode(vault_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault_state.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;
    transition::validate_vault_active(&vault_state).map_err(map_transition_error)?;
    if vault_state.policy_version != expected_policy_version
        || receipt.policy_version != expected_policy_version
    {
        return Err(ProgramError::Custom(error::POLICY_VERSION_MISMATCH));
    }

    let mut receipt_state =
        PolicyReceiptState::decode(receipt_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&receipt_state.discriminator, &POLICY_RECEIPT_DISCRIMINATOR)?;

    let mut session_state =
        ActionSessionState::decode(session_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&session_state.discriminator, &ACTION_SESSION_DISCRIMINATOR)?;
    if session_state.policy_version != expected_policy_version {
        return Err(ProgramError::Custom(error::POLICY_VERSION_MISMATCH));
    }

    transition::finalize_action_session(
        &mut vault_state,
        &mut session_state,
        &mut receipt_state,
        receipt,
        current_slot,
    )
    .map_err(map_transition_error)?;

    if !vault_state.encode(vault_dst)
        || !receipt_state.encode(receipt_dst)
        || !session_state.encode(session_dst)
    {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_rotate_authority_data(
    vault_dst: &mut [u8],
    authority_dst: &mut [u8],
    statement: &AuthorityRotationStatement,
    proof: &vaulkyrie_protocol::WotsAuthProof,
    current_slot: u64,
) -> ProgramResult {
    if vault_dst.len() != VaultRegistry::LEN || authority_dst.len() != QuantumAuthorityState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut vault = VaultRegistry::decode(vault_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;
    transition::validate_vault_recovery_mode(&vault).map_err(map_transition_error)?;

    let mut authority =
        QuantumAuthorityState::decode(authority_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&authority.discriminator, &QUANTUM_STATE_DISCRIMINATOR)?;

    transition::rotate_vault_authority(&mut vault, &mut authority, statement, proof, current_slot)
        .map_err(map_transition_error)?;

    if !vault.encode(vault_dst) || !authority.encode(authority_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_rotate_authority_staged_data(
    vault_dst: &mut [u8],
    authority_dst: &mut [u8],
    proof_dst: &mut [u8],
    statement: &AuthorityRotationStatement,
    current_slot: u64,
) -> ProgramResult {
    if vault_dst.len() != VaultRegistry::LEN
        || authority_dst.len() != QuantumAuthorityState::LEN
        || proof_dst.len() != AuthorityProofState::LEN
    {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Read header fields directly from byte slice to avoid putting the
    // full AuthorityProofState (~1360 bytes) on the stack alongside the
    // decoded WotsAuthProof (~1280 bytes), which would exceed BPF's 4 KB
    // stack limit.
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&proof_dst[..8]);
    require_discriminator(&disc, &AUTHORITY_PROOF_DISCRIMINATOR)?;

    if proof_dst[76] != 0 {
        // consumed != 0
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let mut sd = [0u8; 32];
    sd.copy_from_slice(&proof_dst[8..40]);
    if sd != statement.digest() {
        return Err(ProgramError::Custom(error::PROOF_STATEMENT_MISMATCH));
    }

    let mut pc = [0u8; 32];
    pc.copy_from_slice(&proof_dst[40..72]);

    let mut bw = [0u8; 4];
    bw.copy_from_slice(&proof_dst[72..76]);
    if u32::from_le_bytes(bw) as usize != WotsAuthProof::ENCODED_LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    // Decode proof directly from the slice; only WotsAuthProof is on the
    // stack at this point (the header fields above are small).
    validate_and_rotate_with_proof(vault_dst, authority_dst, proof_dst, &pc, statement, current_slot)
}

/// Separate function so the large `WotsAuthProof` lives in its own stack
/// frame and does not overlap with the caller's locals.
#[inline(never)]
fn validate_and_rotate_with_proof(
    vault_dst: &mut [u8],
    authority_dst: &mut [u8],
    proof_dst: &mut [u8],
    proof_commitment: &[u8; 32],
    statement: &AuthorityRotationStatement,
    current_slot: u64,
) -> ProgramResult {
    let proof_bytes = &proof_dst[AuthorityProofState::HEADER_LEN..AuthorityProofState::LEN];
    let proof = WotsAuthProof::decode(proof_bytes).ok_or(ProgramError::InvalidAccountData)?;
    if proof.commitment() != *proof_commitment {
        return Err(ProgramError::Custom(error::PROOF_COMMITMENT_MISMATCH));
    }

    process_rotate_authority_data(vault_dst, authority_dst, statement, &proof, current_slot)?;

    // Mark consumed directly in the byte slice
    proof_dst[76] = 1;

    Ok(())
}

fn require_writable(account: &AccountInfo) -> ProgramResult {
    if account.is_writable() {
        Ok(())
    } else {
        Err(ProgramError::Immutable)
    }
}

fn require_program_owner(
    program_id: &pinocchio::pubkey::Pubkey,
    account: &AccountInfo,
) -> ProgramResult {
    if account.owner() == program_id {
        Ok(())
    } else {
        Err(ProgramError::IncorrectProgramId)
    }
}

fn is_zeroed(data: &[u8]) -> bool {
    data.iter().all(|byte| *byte == 0)
}

fn require_discriminator(actual: &[u8; 8], expected: &[u8; 8]) -> ProgramResult {
    if actual == expected {
        Ok(())
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}

fn decode_vault_state(src: &[u8]) -> Result<VaultRegistry, ProgramError> {
    let vault = VaultRegistry::decode(src).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;
    Ok(vault)
}

fn ensure_wallet_authority(
    expected_wallet: [u8; 32],
    signer_wallet: [u8; 32],
    signer_present: bool,
) -> ProgramResult {
    if !signer_present {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if signer_wallet != expected_wallet {
        return Err(ProgramError::IncorrectAuthority);
    }

    Ok(())
}

fn require_wallet_authority(vault: &VaultRegistry, signer: &AccountInfo) -> ProgramResult {
    ensure_wallet_authority(vault.wallet_pubkey, *signer.key(), signer.is_signer())
}

fn current_slot() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

fn map_transition_error(error: transition::TransitionError) -> ProgramError {
    match error {
        transition::TransitionError::ReceiptAlreadyConsumed => {
            ProgramError::AccountAlreadyInitialized
        }
        transition::TransitionError::ReceiptMismatch => ProgramError::InvalidAccountData,
        transition::TransitionError::ReceiptExpired => ProgramError::Custom(error::RECEIPT_EXPIRED),
        transition::TransitionError::ReceiptNonceReplay => {
            ProgramError::Custom(error::RECEIPT_NONCE_REPLAY)
        }
        transition::TransitionError::SessionExpired => ProgramError::Custom(error::SESSION_EXPIRED),
        transition::TransitionError::AuthorityStatementExpired => {
            ProgramError::Custom(error::AUTHORITY_STATEMENT_EXPIRED)
        }
        transition::TransitionError::VaultAuthorityMismatch => {
            ProgramError::Custom(error::VAULT_AUTHORITY_MISMATCH)
        }
        transition::TransitionError::VaultPolicyMismatch => {
            ProgramError::Custom(error::VAULT_POLICY_MISMATCH)
        }
        transition::TransitionError::VaultNotActive => ProgramError::InvalidAccountData,
        transition::TransitionError::VaultNotRecovery => ProgramError::InvalidAccountData,
        transition::TransitionError::VaultStatusInvalid => ProgramError::InvalidInstructionData,
        transition::TransitionError::VaultStatusTransitionNotAllowed => {
            ProgramError::Custom(error::VAULT_STATUS_BAD_TRANSITION)
        }
        transition::TransitionError::SessionPolicyMismatch => {
            ProgramError::Custom(error::SESSION_POLICY_MISMATCH)
        }
        transition::TransitionError::SessionMismatch => {
            ProgramError::Custom(error::SESSION_MISMATCH)
        }
        transition::TransitionError::SessionNotPending => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::SessionNotReady => ProgramError::InvalidAccountData,
        transition::TransitionError::SessionRequiresPqc => {
            ProgramError::Custom(error::SESSION_REQUIRES_PQC)
        }
        transition::TransitionError::AuthorityNoOp => ProgramError::Custom(error::AUTHORITY_NO_OP),
        transition::TransitionError::AuthoritySequenceMismatch => {
            ProgramError::Custom(error::AUTHORITY_SEQUENCE_MISMATCH)
        }
        transition::TransitionError::AuthorityLeafIndexMismatch => {
            ProgramError::Custom(error::AUTHORITY_LEAF_INDEX_MISMATCH)
        }
        transition::TransitionError::AuthorityActionMismatch => {
            ProgramError::Custom(error::AUTHORITY_ACTION_MISMATCH)
        }
        transition::TransitionError::AuthorityProofInvalid => {
            ProgramError::Custom(error::AUTHORITY_PROOF_INVALID)
        }
        transition::TransitionError::AuthorityProofMismatch => {
            ProgramError::Custom(error::AUTHORITY_PROOF_MISMATCH)
        }
        transition::TransitionError::AuthorityMerkleRootMismatch => {
            ProgramError::Custom(error::AUTHORITY_MERKLE_ROOT_MISMATCH)
        }
        transition::TransitionError::AuthorityTreeExhausted => {
            ProgramError::Custom(error::AUTHORITY_TREE_EXHAUSTED)
        }
        transition::TransitionError::QuantumVaultAmountTooLarge => ProgramError::InsufficientFunds,
        transition::TransitionError::QuantumVaultPdaMismatch => {
            ProgramError::MissingRequiredSignature
        }
        transition::TransitionError::OrchestrationExpired => {
            ProgramError::Custom(error::ORCHESTRATION_EXPIRED)
        }
        transition::TransitionError::OrchestrationInvalidParams => {
            ProgramError::InvalidInstructionData
        }
        transition::TransitionError::OrchestrationActionMismatch => {
            ProgramError::Custom(error::ORCHESTRATION_ACTION_MISMATCH)
        }
        transition::TransitionError::OrchestrationNotPending => {
            ProgramError::AccountAlreadyInitialized
        }
        transition::TransitionError::OrchestrationNotCommitted => ProgramError::InvalidAccountData,
        transition::TransitionError::OrchestrationAlreadyComplete => {
            ProgramError::AccountAlreadyInitialized
        }
        transition::TransitionError::BridgedReceiptMismatch => ProgramError::InvalidAccountData,
        transition::TransitionError::RecoveryVaultNotInRecoveryMode => {
            ProgramError::InvalidAccountData
        }
        transition::TransitionError::RecoveryExpired => {
            ProgramError::Custom(error::RECOVERY_EXPIRED)
        }
        transition::TransitionError::RecoveryNotPending => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::RecoveryInvalidParams => ProgramError::InvalidInstructionData,
        transition::TransitionError::AuthorityMigrationNoOp => {
            ProgramError::Custom(error::AUTHORITY_MIGRATION_NO_OP)
        }
        transition::TransitionError::PolicyVersionNotMonotonic => {
            ProgramError::Custom(error::POLICY_VERSION_NOT_MONOTONIC)
        }
        transition::TransitionError::TxBindingMissing => ProgramError::InvalidInstructionData,
        transition::TransitionError::AuthorityStatementReplay => {
            ProgramError::Custom(error::AUTHORITY_STATEMENT_REPLAY)
        }
        transition::TransitionError::BridgedReceiptDelayNotMet => {
            ProgramError::Custom(error::BRIDGED_RECEIPT_DELAY_NOT_MET)
        }
    }
}

pub fn process_init_spend_orchestration_data(
    data: &mut [u8],
    args: InitSpendOrchestrationArgs,
    current_slot: u64,
) -> ProgramResult {
    if !is_zeroed(data) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    if data.len() < SpendOrchestrationState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let state = transition::init_spend_orchestration(
        args.action_hash,
        args.session_commitment,
        args.signers_commitment,
        args.signing_package_hash,
        args.expiry_slot,
        args.threshold,
        args.participant_count,
        args.bump,
        current_slot,
    )
    .map_err(map_transition_error)?;
    state.encode(&mut data[..SpendOrchestrationState::LEN]);
    Ok(())
}

pub fn process_commit_spend_orchestration_data(
    data: &mut [u8],
    args: CommitSpendOrchestrationArgs,
    current_slot: u64,
) -> ProgramResult {
    if data.len() < SpendOrchestrationState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = SpendOrchestrationState::decode(&data[..SpendOrchestrationState::LEN])
        .ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &SPEND_ORCH_DISCRIMINATOR)?;
    transition::commit_spend_orchestration(
        &mut state,
        args.action_hash,
        args.signing_package_hash,
        current_slot,
    )
    .map_err(map_transition_error)?;
    state.encode(&mut data[..SpendOrchestrationState::LEN]);
    Ok(())
}

pub fn process_complete_spend_orchestration_data(
    data: &mut [u8],
    args: CompleteSpendOrchestrationArgs,
    current_slot: u64,
) -> ProgramResult {
    if data.len() < SpendOrchestrationState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = SpendOrchestrationState::decode(&data[..SpendOrchestrationState::LEN])
        .ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &SPEND_ORCH_DISCRIMINATOR)?;
    transition::complete_spend_orchestration(
        &mut state,
        args.action_hash,
        args.tx_binding,
        current_slot,
    )
    .map_err(map_transition_error)?;
    state.encode(&mut data[..SpendOrchestrationState::LEN]);
    Ok(())
}

pub fn process_fail_spend_orchestration_data(
    data: &mut [u8],
    args: FailSpendOrchestrationArgs,
) -> ProgramResult {
    if data.len() < SpendOrchestrationState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = SpendOrchestrationState::decode(&data[..SpendOrchestrationState::LEN])
        .ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &SPEND_ORCH_DISCRIMINATOR)?;
    transition::fail_spend_orchestration(&mut state, args.action_hash)
        .map_err(map_transition_error)?;
    state.encode(&mut data[..SpendOrchestrationState::LEN]);
    Ok(())
}

// ── Recovery bootstrap processors ───────────────────────────────────

pub fn process_init_recovery_data(
    data: &mut [u8],
    args: crate::instruction::InitRecoveryArgs,
    vault_status: u8,
    current_slot: u64,
) -> ProgramResult {
    use crate::state::{RecoveryState, RECOVERY_STATE_DISCRIMINATOR};

    if !is_zeroed(data) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    if data.len() < RecoveryState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    transition::init_recovery(
        vault_status,
        current_slot,
        args.expiry_slot,
        args.new_threshold,
        args.new_participant_count,
    )
    .map_err(map_transition_error)?;

    let state = RecoveryState::new(
        args.vault_pubkey,
        args.recovery_commitment,
        args.expiry_slot,
        args.new_threshold,
        args.new_participant_count,
        args.bump,
    );
    debug_assert_eq!(state.discriminator, RECOVERY_STATE_DISCRIMINATOR);
    state.encode(&mut data[..RecoveryState::LEN]);
    Ok(())
}

pub fn process_complete_recovery_data(
    data: &mut [u8],
    args: crate::instruction::CompleteRecoveryArgs,
    current_slot: u64,
) -> ProgramResult {
    use crate::state::{RecoveryState, RecoveryStatus, RECOVERY_STATE_DISCRIMINATOR};

    if data.len() < RecoveryState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = RecoveryState::decode(&data[..RecoveryState::LEN])
        .ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &RECOVERY_STATE_DISCRIMINATOR)?;

    transition::complete_recovery(&state, current_slot).map_err(map_transition_error)?;

    state.new_group_key = args.new_group_key;
    state.new_authority_hash = args.new_authority_hash;
    state.status = RecoveryStatus::Complete as u8;
    state.encode(&mut data[..RecoveryState::LEN]);
    Ok(())
}

pub fn process_migrate_authority_data(
    data: &mut [u8],
    new_authority_root: [u8; 32],
) -> ProgramResult {
    use crate::state::{QuantumAuthorityState, QUANTUM_STATE_DISCRIMINATOR};

    if data.len() < QuantumAuthorityState::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut authority = QuantumAuthorityState::decode(&data[..QuantumAuthorityState::LEN])
        .ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&authority.discriminator, &QUANTUM_STATE_DISCRIMINATOR)?;

    transition::migrate_authority_tree(&mut authority, new_authority_root)
        .map_err(map_transition_error)?;

    authority.encode(&mut data[..QuantumAuthorityState::LEN]);
    Ok(())
}

pub fn process_advance_policy_version_data(data: &mut [u8], new_version: u64) -> ProgramResult {
    use crate::state::{VaultRegistry, VAULT_REGISTRY_DISCRIMINATOR};

    if data.len() < VaultRegistry::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut vault = VaultRegistry::decode(&data[..VaultRegistry::LEN])
        .ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&vault.discriminator, &VAULT_REGISTRY_DISCRIMINATOR)?;

    transition::advance_policy_version(&mut vault, new_version).map_err(map_transition_error)?;

    vault.encode(&mut data[..VaultRegistry::LEN]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use pinocchio::program_error::ProgramError;
    use solana_nostd_sha256::hashv;
    use solana_winternitz::privkey::WinternitzPrivkey;
    use vaulkyrie_protocol::{
        quantum_close_message, quantum_split_message, ActionDescriptor, ActionKind, PolicyReceipt,
        ThresholdRequirement, WotsAuthProof, WotsSecretKey, AUTHORITY_PROOF_CHUNK_MAX_BYTES,
        WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES, XMSS_LEAF_COUNT,
    };

    use super::{
        ensure_wallet_authority, process_activate_session_data,
        process_advance_policy_version_data, process_close_quantum_vault,
        process_commit_spend_orchestration_data, process_complete_recovery_data,
        process_complete_spend_orchestration_data, process_consume_receipt_data,
        process_consume_session_data, process_fail_spend_orchestration_data,
        process_finalize_session_data, process_init_authority_data,
        process_init_authority_proof_data, process_init_recovery_data,
        process_init_spend_orchestration_data, process_init_vault_data,
        process_migrate_authority_data, process_open_session_data, process_rotate_authority_data,
        process_rotate_authority_staged_data, process_set_vault_status_data,
        process_split_quantum_vault, process_stage_bridged_receipt_data,
        process_stage_receipt_data, process_write_authority_proof_chunk_data,
    };
    use crate::{
        error,
        instruction::{
            CommitSpendOrchestrationArgs, CompleteRecoveryArgs, CompleteSpendOrchestrationArgs,
            FailSpendOrchestrationArgs, InitAuthorityArgs, InitAuthorityProofArgs,
            InitRecoveryArgs, InitSpendOrchestrationArgs, InitVaultArgs,
            WriteAuthorityProofChunkArgs,
        },
        state::{
            ActionSessionState, AuthorityProofState, OrchestrationStatus, PolicyReceiptState,
            QuantumAuthorityState, RecoveryState, RecoveryStatus, SessionStatus,
            SpendOrchestrationState, VaultRegistry, VaultStatus, ACTION_SESSION_DISCRIMINATOR,
            QUANTUM_STATE_DISCRIMINATOR, RECOVERY_STATE_DISCRIMINATOR, SPEND_ORCH_DISCRIMINATOR,
            VAULT_REGISTRY_DISCRIMINATOR,
        },
    };

    fn sample_action_hash() -> [u8; 32] {
        ActionDescriptor {
            vault_id: [1; 32],
            payload_hash: [2; 32],
            policy_version: 3,
            kind: ActionKind::Spend,
        }
        .hash()
    }

    fn sample_receipt() -> PolicyReceipt {
        PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 3,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 9,
            expiry_slot: 100,
        }
    }

    fn sample_rotation_statement(
        vault: &VaultRegistry,
        next_authority_hash: [u8; 32],
        sequence: u64,
        expiry_slot: u64,
    ) -> vaulkyrie_protocol::AuthorityRotationStatement {
        let mut statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash,
            sequence,
            expiry_slot,
        };
        statement.action_hash =
            statement.expected_action_hash(vault.wallet_pubkey, vault.policy_version);
        statement
    }

    fn sample_wots_secret(seed: u8) -> WotsSecretKey {
        let mut elements = [0u8; WOTS_KEY_BYTES];
        for (index, byte) in elements.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        WotsSecretKey { elements }
    }

    fn sample_auth_path(seed: u8) -> [u8; XMSS_AUTH_PATH_BYTES] {
        let mut auth_path = [0u8; XMSS_AUTH_PATH_BYTES];
        for (index, byte) in auth_path.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        auth_path
    }

    fn stage_full_authority_proof(
        statement: &vaulkyrie_protocol::AuthorityRotationStatement,
        proof: &WotsAuthProof,
    ) -> [u8; AuthorityProofState::LEN] {
        let mut bytes = [0; AuthorityProofState::LEN];
        process_init_authority_proof_data(
            &mut bytes,
            InitAuthorityProofArgs {
                statement_digest: statement.digest(),
                proof_commitment: proof.commitment(),
            },
        )
        .expect("authority proof init should succeed");

        let mut encoded = [0u8; WotsAuthProof::ENCODED_LEN];
        assert!(proof.encode(&mut encoded));
        let mut offset = 0usize;
        while offset < encoded.len() {
            let end = core::cmp::min(offset + AUTHORITY_PROOF_CHUNK_MAX_BYTES, encoded.len());
            let chunk_len = end - offset;
            let mut chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
            chunk[..chunk_len].copy_from_slice(&encoded[offset..end]);
            process_write_authority_proof_chunk_data(
                &mut bytes,
                WriteAuthorityProofChunkArgs {
                    offset: offset as u32,
                    chunk_len: chunk_len as u16,
                    chunk,
                },
            )
            .expect("authority proof chunk write should succeed");
            offset = end;
        }

        bytes
    }

    #[test]
    fn wallet_authority_requires_signer() {
        let error = ensure_wallet_authority([1; 32], [1; 32], false)
            .expect_err("missing signer should fail");

        assert_eq!(error, ProgramError::MissingRequiredSignature);
    }

    #[test]
    fn wallet_authority_requires_matching_pubkey() {
        let error = ensure_wallet_authority([1; 32], [2; 32], true)
            .expect_err("wrong signer pubkey should fail");

        assert_eq!(error, ProgramError::IncorrectAuthority);
    }

    #[test]
    fn wallet_authority_accepts_matching_signer() {
        ensure_wallet_authority([1; 32], [1; 32], true)
            .expect("matching signer pubkey should pass");
    }

    #[test]
    fn set_vault_status_updates_state() {
        let mut bytes = [0; VaultRegistry::LEN];
        let vault = VaultRegistry::new([5; 32], [6; 32], 7, VaultStatus::Active, 8, [0; 32]);
        assert!(vault.encode(&mut bytes));

        process_set_vault_status_data(&mut bytes, VaultStatus::Locked as u8)
            .expect("active to locked should pass");

        let updated = VaultRegistry::decode(&bytes).expect("vault should decode");
        assert_eq!(updated.status, VaultStatus::Locked as u8);
    }

    #[test]
    fn set_vault_status_rejects_unknown_value() {
        let mut bytes = [0; VaultRegistry::LEN];
        let vault = VaultRegistry::new([5; 32], [6; 32], 7, VaultStatus::Active, 8, [0; 32]);
        assert!(vault.encode(&mut bytes));

        let error =
            process_set_vault_status_data(&mut bytes, 42).expect_err("unknown status should fail");

        assert_eq!(error, ProgramError::InvalidInstructionData);
    }

    #[test]
    fn set_vault_status_rejects_disallowed_transition() {
        let mut bytes = [0; VaultRegistry::LEN];
        let vault = VaultRegistry::new([5; 32], [6; 32], 7, VaultStatus::Locked, 8, [0; 32]);
        assert!(vault.encode(&mut bytes));

        let error = process_set_vault_status_data(&mut bytes, VaultStatus::Active as u8)
            .expect_err("locked to active should fail");

        assert_eq!(
            error,
            ProgramError::Custom(error::VAULT_STATUS_BAD_TRANSITION)
        );
    }

    #[test]
    fn init_vault_writes_encoded_state() {
        let mut bytes = [0; VaultRegistry::LEN];

        process_init_vault_data(
            &mut bytes,
            InitVaultArgs {
                wallet_pubkey: [5; 32],
                authority_hash: [6; 32],
                policy_version: 7,
                bump: 8,
                policy_mxe_program: [0; 32],
            },
        )
        .expect("vault init should succeed");

        let state = VaultRegistry::decode(&bytes).expect("state should decode");
        assert_eq!(state.wallet_pubkey, [5; 32]);
        assert_eq!(state.current_authority_hash, [6; 32]);
        assert_eq!(state.policy_version, 7);
        assert_eq!(state.bump, 8);
        assert_eq!(state.policy_mxe_program, [0; 32]);
    }

    #[test]
    fn init_vault_rejects_preinitialized_bytes() {
        let mut bytes = [1; VaultRegistry::LEN];

        let error = process_init_vault_data(
            &mut bytes,
            InitVaultArgs {
                wallet_pubkey: [5; 32],
                authority_hash: [6; 32],
                policy_version: 7,
                bump: 8,
                policy_mxe_program: [0; 32],
            },
        )
        .expect_err("preinitialized bytes should fail");

        assert_eq!(error, ProgramError::AccountAlreadyInitialized);
    }

    #[test]
    fn init_authority_writes_encoded_state() {
        let mut bytes = [0; QuantumAuthorityState::LEN];

        process_init_authority_data(
            &mut bytes,
            InitAuthorityArgs {
                current_authority_hash: [7; 32],
                current_authority_root: [8; 32],
                bump: 2,
            },
        )
        .expect("authority init should succeed");

        let state = QuantumAuthorityState::decode(&bytes).expect("state should decode");
        assert_eq!(state.current_authority_hash, [7; 32]);
        assert_eq!(state.current_authority_root, [8; 32]);
        assert_eq!(state.bump, 2);
        assert_eq!(state.next_sequence, 0);
        assert_eq!(state.next_leaf_index, 0);
    }

    #[test]
    fn init_authority_rejects_preinitialized_bytes() {
        let mut bytes = [1; QuantumAuthorityState::LEN];

        let error = process_init_authority_data(
            &mut bytes,
            InitAuthorityArgs {
                current_authority_hash: [7; 32],
                current_authority_root: [8; 32],
                bump: 2,
            },
        )
        .expect_err("preinitialized bytes should fail");

        assert_eq!(error, ProgramError::AccountAlreadyInitialized);
    }

    #[test]
    fn init_authority_proof_writes_encoded_state() {
        let mut bytes = [0; AuthorityProofState::LEN];

        process_init_authority_proof_data(
            &mut bytes,
            InitAuthorityProofArgs {
                statement_digest: [7; 32],
                proof_commitment: [8; 32],
            },
        )
        .expect("authority proof init should succeed");

        let state = AuthorityProofState::decode(&bytes).expect("state should decode");
        assert_eq!(state.statement_digest, [7; 32]);
        assert_eq!(state.proof_commitment, [8; 32]);
        assert_eq!(state.bytes_written, 0);
        assert_eq!(state.consumed, 0);
    }

    #[test]
    fn write_authority_proof_chunk_appends_bytes() {
        let mut bytes = [0; AuthorityProofState::LEN];
        process_init_authority_proof_data(
            &mut bytes,
            InitAuthorityProofArgs {
                statement_digest: [7; 32],
                proof_commitment: [8; 32],
            },
        )
        .expect("authority proof init should succeed");

        let mut chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
        chunk[..3].copy_from_slice(&[1, 2, 3]);
        process_write_authority_proof_chunk_data(
            &mut bytes,
            WriteAuthorityProofChunkArgs {
                offset: 0,
                chunk_len: 3,
                chunk,
            },
        )
        .expect("authority proof chunk write should succeed");

        let state = AuthorityProofState::decode(&bytes).expect("state should decode");
        assert_eq!(state.bytes_written, 3);
        assert_eq!(&state.proof_bytes[..3], &[1, 2, 3]);
    }

    #[test]
    fn write_authority_proof_chunk_rejects_wrong_offset() {
        let mut bytes = [0; AuthorityProofState::LEN];
        process_init_authority_proof_data(
            &mut bytes,
            InitAuthorityProofArgs {
                statement_digest: [7; 32],
                proof_commitment: [8; 32],
            },
        )
        .expect("authority proof init should succeed");

        let mut chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
        chunk[..3].copy_from_slice(&[1, 2, 3]);
        let error = process_write_authority_proof_chunk_data(
            &mut bytes,
            WriteAuthorityProofChunkArgs {
                offset: 1,
                chunk_len: 3,
                chunk,
            },
        )
        .expect_err("authority proof chunk offset must be append-only");

        assert_eq!(
            error,
            ProgramError::Custom(error::PROOF_CHUNK_OFFSET_MISMATCH)
        );
    }

    #[test]
    fn stage_and_consume_receipt_updates_consumed_flag() {
        let receipt = sample_receipt();
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));

        process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect("stage should succeed");
        process_consume_receipt_data(&mut vault_bytes, &mut receipt_bytes, &receipt)
            .expect("consume should succeed");

        let state = PolicyReceiptState::decode(&receipt_bytes).expect("state should decode");
        let vault = VaultRegistry::decode(&vault_bytes).expect("vault should decode");
        assert_eq!(state.consumed, 1);
        assert_eq!(vault.last_consumed_receipt_nonce, receipt.nonce);
    }

    #[test]
    fn consume_receipt_rejects_replayed_nonce() {
        let receipt = sample_receipt();
        let mut vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        vault.last_consumed_receipt_nonce = receipt.nonce;
        let staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        assert!(staged.encode(&mut receipt_bytes));
        let error = process_consume_receipt_data(&mut vault_bytes, &mut receipt_bytes, &receipt)
            .expect_err("replayed nonce should fail");

        assert_eq!(error, ProgramError::Custom(error::RECEIPT_NONCE_REPLAY));
        let state = PolicyReceiptState::decode(&receipt_bytes).expect("state should decode");
        assert_eq!(state.consumed, 0);
    }

    #[test]
    fn stage_receipt_rejects_policy_mismatch() {
        let receipt = sample_receipt();
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            99,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("policy mismatch should fail");

        assert_eq!(error, ProgramError::Custom(error::VAULT_POLICY_MISMATCH));
    }

    #[test]
    fn stage_receipt_rejects_non_active_vault() {
        let receipt = sample_receipt();
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Locked,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("non-active vault should fail");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn stage_receipt_rejects_expired_receipt() {
        let receipt = PolicyReceipt {
            expiry_slot: 9,
            ..sample_receipt()
        };
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("expired receipt should fail");

        assert_eq!(error, ProgramError::Custom(error::RECEIPT_EXPIRED));
    }

    #[test]
    fn stage_receipt_rejects_replayed_nonce() {
        let receipt = sample_receipt();
        let mut vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        vault.last_consumed_receipt_nonce = receipt.nonce;
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("replayed nonce should fail stage");

        assert_eq!(error, ProgramError::Custom(error::RECEIPT_NONCE_REPLAY));
    }

    #[test]
    fn rotate_authority_updates_current_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(31));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut bytes));

        process_rotate_authority_data(&mut vault_bytes, &mut bytes, &statement, &proof, 10)
            .expect("rotation should succeed");

        let vault = VaultRegistry::decode(&vault_bytes).expect("vault should decode");
        let state = QuantumAuthorityState::decode(&bytes).expect("state should decode");
        assert_eq!(vault.current_authority_hash, [8; 32]);
        assert_eq!(state.current_authority_hash, [8; 32]);
        assert_eq!(state.next_sequence, 1);
        assert_eq!(state.next_leaf_index, 1);
    }

    #[test]
    fn rotate_authority_staged_updates_current_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(40));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        let mut proof_bytes = stage_full_authority_proof(&statement, &proof);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        process_rotate_authority_staged_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &mut proof_bytes,
            &statement,
            10,
        )
        .expect("staged rotation should succeed");

        let vault = VaultRegistry::decode(&vault_bytes).expect("vault should decode");
        let state = QuantumAuthorityState::decode(&authority_bytes).expect("state should decode");
        let proof_state = AuthorityProofState::decode(&proof_bytes).expect("proof should decode");
        assert_eq!(vault.current_authority_hash, [8; 32]);
        assert_eq!(state.current_authority_hash, [8; 32]);
        assert_eq!(state.next_leaf_index, 1);
        assert_eq!(proof_state.consumed, 1);
    }

    #[test]
    fn rotate_authority_staged_rejects_incomplete_proof() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let mut proof_bytes = [0; AuthorityProofState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(41));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        process_init_authority_proof_data(
            &mut proof_bytes,
            InitAuthorityProofArgs {
                statement_digest: statement.digest(),
                proof_commitment: proof.commitment(),
            },
        )
        .expect("authority proof init should succeed");

        let error = process_rotate_authority_staged_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &mut proof_bytes,
            &statement,
            10,
        )
        .expect_err("staged rotation should reject incomplete proof data");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn rotate_authority_staged_rejects_commitment_mismatch() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(42));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        let mut proof_bytes = stage_full_authority_proof(&statement, &proof);
        {
            let mut proof_state =
                AuthorityProofState::decode(&proof_bytes).expect("proof should decode");
            proof_state.proof_commitment = [9; 32];
            assert!(proof_state.encode(&mut proof_bytes));
        }
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_staged_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &mut proof_bytes,
            &statement,
            10,
        )
        .expect_err("staged rotation should reject mismatched proof commitment");

        assert_eq!(
            error,
            ProgramError::Custom(error::PROOF_COMMITMENT_MISMATCH)
        );
    }

    #[test]
    fn rotate_authority_rejects_vault_authority_mismatch() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(32));
        let initial = QuantumAuthorityState::new([9; 32], proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("mismatched vault and authority should fail");

        assert_eq!(error, ProgramError::Custom(error::VAULT_AUTHORITY_MISMATCH));
    }

    #[test]
    fn rotate_authority_rejects_no_op_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, secret.authority_hash(), 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(33));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("no-op authority rotation should fail");

        assert_eq!(error, ProgramError::Custom(error::AUTHORITY_NO_OP));
    }

    #[test]
    fn rotate_authority_rejects_expired_statement() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 9);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(34));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("expired authority statement should fail");

        assert_eq!(
            error,
            ProgramError::Custom(error::AUTHORITY_STATEMENT_EXPIRED)
        );
    }

    #[test]
    fn rotate_authority_rejects_active_vault() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(35));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("active vault should fail recovery-mode rotation");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn rotate_authority_rejects_unbound_action_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [8; 32],
            sequence: 0,
            expiry_slot: 200,
        };
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(36));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("rotation should require rekey-bound action hash");

        assert_eq!(
            error,
            ProgramError::Custom(error::AUTHORITY_ACTION_MISMATCH)
        );
    }

    #[test]
    fn rotate_authority_rejects_invalid_wots_proof() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let mut proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(37));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        proof.signature[0] ^= 1;

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("tampered proof should fail");

        assert_eq!(error, ProgramError::Custom(error::AUTHORITY_PROOF_INVALID));
    }

    #[test]
    fn rotate_authority_rejects_leaf_index_mismatch() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);
        let proof = secret.sign_statement_with_auth_path(&statement, 1, sample_auth_path(38));
        let initial = QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("rotation should require the next expected leaf index");

        assert_eq!(
            error,
            ProgramError::Custom(error::AUTHORITY_LEAF_INDEX_MISMATCH)
        );
    }

    #[test]
    fn rotate_authority_rejects_tree_exhaustion() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let secret = sample_wots_secret(41);
        let vault = VaultRegistry::new(
            [5; 32],
            secret.authority_hash(),
            3,
            crate::state::VaultStatus::Recovery,
            8,
            [0; 32],
        );
        let statement = sample_rotation_statement(&vault, [8; 32], XMSS_LEAF_COUNT as u64, 200);
        let proof =
            secret.sign_statement_with_auth_path(&statement, XMSS_LEAF_COUNT, sample_auth_path(39));
        let mut initial =
            QuantumAuthorityState::new(secret.authority_hash(), proof.merkle_root(), 1);
        initial.next_sequence = XMSS_LEAF_COUNT as u64;
        initial.next_leaf_index = XMSS_LEAF_COUNT;
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            &proof,
            10,
        )
        .expect_err("rotation should fail once the authority tree is exhausted");

        assert_eq!(error, ProgramError::Custom(error::AUTHORITY_TREE_EXHAUSTED));
    }

    #[test]
    fn open_session_writes_encoded_state() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");

        let state = ActionSessionState::decode(&session_bytes).expect("state should decode");
        assert_eq!(state.receipt_commitment, receipt.commitment());
        assert_eq!(state.action_hash, receipt.action_hash);
        assert_eq!(state.threshold, ThresholdRequirement::TwoOfThree.as_byte());
        assert_eq!(state.status, SessionStatus::Pending as u8);
    }

    #[test]
    fn activate_session_marks_state_ready() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut bytes, &receipt, 10)
            .expect("open session should succeed");
        process_activate_session_data(&mut bytes, receipt.action_hash, 10, receipt.policy_version)
            .expect("activate session should succeed");

        let state = ActionSessionState::decode(&bytes).expect("state should decode");
        assert_eq!(state.status, SessionStatus::Ready as u8);
    }

    #[test]
    fn activate_session_rejects_wrong_discriminator() {
        let mut bytes = [0; ActionSessionState::LEN];
        bytes[..8].copy_from_slice(b"BADTYPE1");

        let error = process_activate_session_data(&mut bytes, [7; 32], 10, 3)
            .expect_err("wrong discriminator should fail");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn activate_session_rejects_wrong_action_hash() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut bytes, &receipt, 10)
            .expect("open session should succeed");
        let error = process_activate_session_data(&mut bytes, [9; 32], 10, receipt.policy_version)
            .expect_err("wrong action hash should fail");

        assert_eq!(error, ProgramError::Custom(error::SESSION_MISMATCH));
    }

    #[test]
    fn activate_session_rejects_policy_mismatch() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut bytes, &receipt, 10)
            .expect("open session should succeed");
        let error = process_activate_session_data(&mut bytes, receipt.action_hash, 10, 99)
            .expect_err("policy mismatch should fail");

        assert_eq!(error, ProgramError::Custom(error::POLICY_VERSION_MISMATCH));
    }

    #[test]
    fn activate_session_rejects_pqc_only_threshold() {
        let receipt = PolicyReceipt {
            threshold: ThresholdRequirement::RequirePqcAuth,
            ..sample_receipt()
        };
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut bytes, &receipt, 10)
            .expect("open session should succeed");
        let error = process_activate_session_data(
            &mut bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect_err("pqc-only threshold should reject spend activation");

        assert_eq!(error, ProgramError::Custom(error::SESSION_REQUIRES_PQC));
    }

    #[test]
    fn open_session_rejects_expired_receipt() {
        let receipt = PolicyReceipt {
            expiry_slot: 9,
            ..sample_receipt()
        };
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        let error = process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect_err("expired receipt should not open a session");

        assert_eq!(error, ProgramError::Custom(error::RECEIPT_EXPIRED));
    }

    #[test]
    fn consume_session_marks_state_consumed() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        process_activate_session_data(
            &mut session_bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect("activate session should succeed");
        process_consume_session_data(
            &mut session_bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect("consume session should succeed");

        let state = ActionSessionState::decode(&session_bytes).expect("state should decode");
        assert_eq!(state.status, SessionStatus::Consumed as u8);
    }

    #[test]
    fn consume_session_rejects_pending_state() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        let error = process_consume_session_data(
            &mut session_bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect_err("pending session should not be consumable");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn consume_session_rejects_pqc_only_threshold() {
        let receipt = PolicyReceipt {
            threshold: ThresholdRequirement::RequirePqcAuth,
            ..sample_receipt()
        };
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        {
            let mut state =
                ActionSessionState::decode(&session_bytes).expect("session should decode");
            state.status = SessionStatus::Ready as u8;
            assert!(state.encode(&mut session_bytes));
        }

        let error = process_consume_session_data(
            &mut session_bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect_err("pqc-only threshold should reject spend consumption");

        assert_eq!(error, ProgramError::Custom(error::SESSION_REQUIRES_PQC));
    }

    #[test]
    fn finalize_session_consumes_receipt_and_session() {
        let receipt = sample_receipt();
        let staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        assert!(staged.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        process_activate_session_data(
            &mut session_bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect("activate session should succeed");
        process_finalize_session_data(
            &mut vault_bytes,
            &mut receipt_bytes,
            &mut session_bytes,
            &receipt,
            10,
            receipt.policy_version,
        )
        .expect("finalize session should succeed");

        let receipt_state =
            PolicyReceiptState::decode(&receipt_bytes).expect("receipt should decode");
        let session_state =
            ActionSessionState::decode(&session_bytes).expect("session should decode");
        let vault_state = VaultRegistry::decode(&vault_bytes).expect("vault should decode");
        assert_eq!(receipt_state.consumed, 1);
        assert_eq!(session_state.status, SessionStatus::Consumed as u8);
        assert_eq!(vault_state.last_consumed_receipt_nonce, receipt.nonce);
    }

    #[test]
    fn finalize_session_rejects_pending_session() {
        let receipt = sample_receipt();
        let staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        assert!(staged.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        let error = process_finalize_session_data(
            &mut vault_bytes,
            &mut receipt_bytes,
            &mut session_bytes,
            &receipt,
            10,
            receipt.policy_version,
        )
        .expect_err("pending session should not finalize");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn finalize_session_rejects_pqc_only_threshold() {
        let receipt = PolicyReceipt {
            threshold: ThresholdRequirement::RequirePqcAuth,
            ..sample_receipt()
        };
        let staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        assert!(staged.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        {
            let mut state =
                ActionSessionState::decode(&session_bytes).expect("session should decode");
            state.status = SessionStatus::Ready as u8;
            assert!(state.encode(&mut session_bytes));
        }

        let error = process_finalize_session_data(
            &mut vault_bytes,
            &mut receipt_bytes,
            &mut session_bytes,
            &receipt,
            10,
            receipt.policy_version,
        )
        .expect_err("pqc-only threshold should reject spend finalization");

        assert_eq!(error, ProgramError::Custom(error::SESSION_REQUIRES_PQC));
    }

    #[test]
    fn finalize_session_rejects_replayed_nonce() {
        let receipt = sample_receipt();
        let staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut vault = VaultRegistry::new(
            [5; 32],
            [6; 32],
            3,
            crate::state::VaultStatus::Active,
            8,
            [0; 32],
        );
        vault.last_consumed_receipt_nonce = receipt.nonce;
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        assert!(staged.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect("open session should succeed");
        process_activate_session_data(
            &mut session_bytes,
            receipt.action_hash,
            10,
            receipt.policy_version,
        )
        .expect("activate session should succeed");

        let error = process_finalize_session_data(
            &mut vault_bytes,
            &mut receipt_bytes,
            &mut session_bytes,
            &receipt,
            10,
            receipt.policy_version,
        )
        .expect_err("replayed nonce should fail finalize");

        assert_eq!(error, ProgramError::Custom(error::RECEIPT_NONCE_REPLAY));
    }

    #[test]
    fn open_session_writes_expected_discriminator() {
        let receipt = sample_receipt();
        let receipt_state = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut bytes = [0; ActionSessionState::LEN];

        assert!(receipt_state.encode(&mut receipt_bytes));
        process_open_session_data(&receipt_bytes, &mut bytes, &receipt, 10)
            .expect("open session should succeed");

        assert_eq!(&bytes[..8], &ACTION_SESSION_DISCRIMINATOR);
    }

    #[test]
    fn open_session_rejects_mismatched_staged_receipt() {
        let receipt = sample_receipt();
        let staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce + 1,
            receipt.expiry_slot,
        );
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(staged.encode(&mut receipt_bytes));
        let error = process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect_err("mismatched staged receipt should fail");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn open_session_rejects_consumed_receipt() {
        let receipt = sample_receipt();
        let mut staged = PolicyReceiptState::new(
            receipt.commitment(),
            receipt.action_hash,
            receipt.nonce,
            receipt.expiry_slot,
        );
        staged.consumed = 1;
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];
        let mut session_bytes = [0; ActionSessionState::LEN];

        assert!(staged.encode(&mut receipt_bytes));
        let error = process_open_session_data(&receipt_bytes, &mut session_bytes, &receipt, 10)
            .expect_err("consumed staged receipt should fail");

        assert_eq!(error, ProgramError::AccountAlreadyInitialized);
    }

    #[test]
    fn split_quantum_vault_accepts_blueshift_message_binding() {
        let privkey = WinternitzPrivkey::from([51u8; solana_winternitz::HASH_LENGTH * 32]);
        let signature = privkey.sign(&quantum_split_message(55, [7; 32], [8; 32]));
        let hash = privkey.pubkey().merklize();
        let program_id = [3; 32];
        let bump = 4;
        let vault_pubkey = hashv(&[
            hash.as_ref(),
            [bump].as_ref(),
            program_id.as_ref(),
            b"ProgramDerivedAddress",
        ]);

        process_split_quantum_vault(
            55,
            [7; 32],
            [8; 32],
            &signature,
            bump,
            vault_pubkey,
            program_id,
            100,
        )
        .expect("split quantum vault should validate a Blueshift-bound signature");
    }

    #[test]
    fn split_quantum_vault_rejects_overspend() {
        let privkey = WinternitzPrivkey::from([52u8; solana_winternitz::HASH_LENGTH * 32]);
        let signature = privkey.sign(&quantum_split_message(101, [7; 32], [8; 32]));
        let hash = privkey.pubkey().merklize();
        let program_id = [3; 32];
        let bump = 4;
        let vault_pubkey = hashv(&[
            hash.as_ref(),
            [bump].as_ref(),
            program_id.as_ref(),
            b"ProgramDerivedAddress",
        ]);

        let error = process_split_quantum_vault(
            101,
            [7; 32],
            [8; 32],
            &signature,
            bump,
            vault_pubkey,
            program_id,
            100,
        )
        .expect_err("overspend must fail");

        assert_eq!(error, ProgramError::InsufficientFunds);
    }

    #[test]
    fn close_quantum_vault_accepts_blueshift_refund_binding() {
        let privkey = WinternitzPrivkey::from([53u8; solana_winternitz::HASH_LENGTH * 32]);
        let signature = privkey.sign(&quantum_close_message([9; 32]));
        let hash = privkey.pubkey().merklize();
        let program_id = [4; 32];
        let bump = 5;
        let vault_pubkey = hashv(&[
            hash.as_ref(),
            [bump].as_ref(),
            program_id.as_ref(),
            b"ProgramDerivedAddress",
        ]);

        process_close_quantum_vault([9; 32], &signature, bump, vault_pubkey, program_id)
            .expect("close quantum vault should validate a refund-bound signature");
    }

    // ── process_stage_bridged_receipt_data ───────────────────────────────────

    fn make_finalized_eval_bytes_for_receipt(receipt: &PolicyReceipt) -> [u8; 256] {
        let mut bytes = [0u8; 256];
        bytes[0..8].copy_from_slice(b"POLEVAL1");
        bytes[72..104].copy_from_slice(&receipt.action_hash);
        bytes[168..200].copy_from_slice(&receipt.commitment());
        bytes[240] = 2; // Finalized
        bytes
    }

    fn sample_vault_bytes_for_receipt(receipt: &PolicyReceipt) -> Vec<u8> {
        use crate::state::VaultRegistry;
        let state = super::super::transition::initialize_vault(
            [10; 32],
            [11; 32],
            receipt.policy_version,
            1,
            [0; 32],
        );
        let mut buf = vec![0u8; VaultRegistry::LEN];
        state.encode(&mut buf);
        buf
    }

    #[test]
    fn stage_bridged_receipt_succeeds_on_valid_finalized_eval() {
        use super::process_stage_bridged_receipt_data;
        let receipt = PolicyReceipt {
            action_hash: [7; 32],
            policy_version: 5,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 3,
            expiry_slot: 9999,
        };
        let vault_bytes = sample_vault_bytes_for_receipt(&receipt);
        let eval_bytes = make_finalized_eval_bytes_for_receipt(&receipt);
        let mut receipt_buf = vec![0u8; crate::state::PolicyReceiptState::LEN];

        process_stage_bridged_receipt_data(
            &vault_bytes,
            &mut receipt_buf,
            &eval_bytes,
            &receipt,
            100,
        )
        .expect("stage_bridged_receipt_data should succeed with valid finalized eval");
    }

    #[test]
    fn stage_bridged_receipt_rejects_non_finalized_eval() {
        use super::process_stage_bridged_receipt_data;
        use pinocchio::program_error::ProgramError;
        let receipt = PolicyReceipt {
            action_hash: [7; 32],
            policy_version: 5,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 3,
            expiry_slot: 9999,
        };
        let vault_bytes = sample_vault_bytes_for_receipt(&receipt);
        let mut eval_bytes = make_finalized_eval_bytes_for_receipt(&receipt);
        eval_bytes[240] = 1; // Pending — not finalized
        let mut receipt_buf = vec![0u8; crate::state::PolicyReceiptState::LEN];

        let err = process_stage_bridged_receipt_data(
            &vault_bytes,
            &mut receipt_buf,
            &eval_bytes,
            &receipt,
            100,
        )
        .expect_err("should reject non-finalized eval");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn stage_bridged_receipt_rejects_commitment_mismatch() {
        use super::process_stage_bridged_receipt_data;
        use pinocchio::program_error::ProgramError;
        let receipt = PolicyReceipt {
            action_hash: [7; 32],
            policy_version: 5,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 3,
            expiry_slot: 9999,
        };
        let vault_bytes = sample_vault_bytes_for_receipt(&receipt);
        let mut eval_bytes = make_finalized_eval_bytes_for_receipt(&receipt);
        eval_bytes[168..200].copy_from_slice(&[0xAB; 32]); // wrong commitment
        let mut receipt_buf = vec![0u8; crate::state::PolicyReceiptState::LEN];

        let err = process_stage_bridged_receipt_data(
            &vault_bytes,
            &mut receipt_buf,
            &eval_bytes,
            &receipt,
            100,
        )
        .expect_err("should reject mismatched commitment");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    // ── Spend Orchestration Processor Tests ──────────────────────────────────

    fn sample_init_spend_args() -> InitSpendOrchestrationArgs {
        InitSpendOrchestrationArgs {
            action_hash: [1; 32],
            session_commitment: [2; 32],
            signers_commitment: [3; 32],
            signing_package_hash: [4; 32],
            expiry_slot: 1000,
            threshold: 2,
            participant_count: 3,
            bump: 255,
        }
    }

    fn init_spend_orch_buf(current_slot: u64) -> Vec<u8> {
        let args = sample_init_spend_args();
        let mut buf = vec![0u8; SpendOrchestrationState::LEN];
        process_init_spend_orchestration_data(&mut buf, args, current_slot)
            .expect("init should succeed");
        buf
    }

    #[test]
    fn init_spend_orchestration_writes_discriminator_and_pending_status() {
        let buf = init_spend_orch_buf(10);
        let state = SpendOrchestrationState::decode(&buf).expect("decode");
        assert_eq!(state.discriminator, SPEND_ORCH_DISCRIMINATOR);
        assert_eq!(state.status, OrchestrationStatus::Pending as u8);
        assert_eq!(state.action_hash, [1; 32]);
        assert_eq!(state.session_commitment, [2; 32]);
        assert_eq!(state.threshold, 2);
        assert_eq!(state.participant_count, 3);
        assert_eq!(state.bump, 255);
    }

    #[test]
    fn init_spend_orchestration_rejects_already_initialized() {
        let mut buf = init_spend_orch_buf(10);
        let args = sample_init_spend_args();
        let err = process_init_spend_orchestration_data(&mut buf, args, 10)
            .expect_err("double init must fail");
        assert_eq!(err, ProgramError::AccountAlreadyInitialized);
    }

    #[test]
    fn init_spend_orchestration_rejects_undersized_buffer() {
        let mut buf = vec![0u8; SpendOrchestrationState::LEN - 1];
        let args = sample_init_spend_args();
        let err = process_init_spend_orchestration_data(&mut buf, args, 10)
            .expect_err("short buffer must fail");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn init_spend_orchestration_rejects_already_expired() {
        let mut buf = vec![0u8; SpendOrchestrationState::LEN];
        let args = InitSpendOrchestrationArgs {
            expiry_slot: 5,
            ..sample_init_spend_args()
        };
        let err = process_init_spend_orchestration_data(&mut buf, args, 100)
            .expect_err("already expired must fail");
        assert_eq!(err, ProgramError::Custom(error::ORCHESTRATION_EXPIRED));
    }

    #[test]
    fn commit_spend_orchestration_transitions_to_committed() {
        let mut buf = init_spend_orch_buf(10);
        let args = CommitSpendOrchestrationArgs {
            action_hash: [1; 32],
            signing_package_hash: [4; 32],
        };
        process_commit_spend_orchestration_data(&mut buf, args, 20).expect("commit should succeed");
        let state = SpendOrchestrationState::decode(&buf).expect("decode");
        assert_eq!(state.status, OrchestrationStatus::Committed as u8);
    }

    #[test]
    fn commit_spend_orchestration_rejects_wrong_action_hash() {
        let mut buf = init_spend_orch_buf(10);
        let args = CommitSpendOrchestrationArgs {
            action_hash: [99; 32],
            signing_package_hash: [4; 32],
        };
        let err = process_commit_spend_orchestration_data(&mut buf, args, 20)
            .expect_err("wrong action hash must fail");
        assert_eq!(
            err,
            ProgramError::Custom(error::ORCHESTRATION_ACTION_MISMATCH)
        );
    }

    #[test]
    fn commit_spend_orchestration_rejects_expired_session() {
        let mut buf = init_spend_orch_buf(10);
        let args = CommitSpendOrchestrationArgs {
            action_hash: [1; 32],
            signing_package_hash: [4; 32],
        };
        let err = process_commit_spend_orchestration_data(&mut buf, args, 2000)
            .expect_err("expired commit must fail");
        assert_eq!(err, ProgramError::Custom(error::ORCHESTRATION_EXPIRED));
    }

    #[test]
    fn complete_spend_orchestration_transitions_to_complete() {
        let mut buf = init_spend_orch_buf(10);
        // First commit
        process_commit_spend_orchestration_data(
            &mut buf,
            CommitSpendOrchestrationArgs {
                action_hash: [1; 32],
                signing_package_hash: [4; 32],
            },
            20,
        )
        .expect("commit");
        // Then complete
        let args = CompleteSpendOrchestrationArgs {
            action_hash: [1; 32],
            tx_binding: [88; 32],
        };
        process_complete_spend_orchestration_data(&mut buf, args, 30)
            .expect("complete should succeed");
        let state = SpendOrchestrationState::decode(&buf).expect("decode");
        assert_eq!(state.status, OrchestrationStatus::Complete as u8);
        assert_eq!(state.tx_binding, [88; 32]);
    }

    #[test]
    fn complete_spend_orchestration_rejects_if_not_committed() {
        let mut buf = init_spend_orch_buf(10);
        let args = CompleteSpendOrchestrationArgs {
            action_hash: [1; 32],
            tx_binding: [88; 32],
        };
        let err = process_complete_spend_orchestration_data(&mut buf, args, 20)
            .expect_err("complete on pending must fail");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn fail_spend_orchestration_transitions_to_failed() {
        let mut buf = init_spend_orch_buf(10);
        let args = FailSpendOrchestrationArgs {
            action_hash: [1; 32],
            reason_code: 1,
        };
        process_fail_spend_orchestration_data(&mut buf, args).expect("fail should succeed");
        let state = SpendOrchestrationState::decode(&buf).expect("decode");
        assert_eq!(state.status, OrchestrationStatus::Failed as u8);
    }

    #[test]
    fn fail_spend_orchestration_rejects_wrong_action_hash() {
        let mut buf = init_spend_orch_buf(10);
        let args = FailSpendOrchestrationArgs {
            action_hash: [88; 32],
            reason_code: 1,
        };
        let err = process_fail_spend_orchestration_data(&mut buf, args)
            .expect_err("wrong action hash must fail");
        assert_eq!(
            err,
            ProgramError::Custom(error::ORCHESTRATION_ACTION_MISMATCH)
        );
    }

    #[test]
    fn fail_spend_orchestration_rejects_already_complete() {
        let mut buf = init_spend_orch_buf(10);
        // Commit then complete
        process_commit_spend_orchestration_data(
            &mut buf,
            CommitSpendOrchestrationArgs {
                action_hash: [1; 32],
                signing_package_hash: [4; 32],
            },
            20,
        )
        .expect("commit");
        process_complete_spend_orchestration_data(
            &mut buf,
            CompleteSpendOrchestrationArgs {
                action_hash: [1; 32],
                tx_binding: [88; 32],
            },
            25,
        )
        .expect("complete");
        // Try to fail a completed session
        let err = process_fail_spend_orchestration_data(
            &mut buf,
            FailSpendOrchestrationArgs {
                action_hash: [1; 32],
                reason_code: 1,
            },
        )
        .expect_err("fail on complete must error");
        assert_eq!(err, ProgramError::AccountAlreadyInitialized);
    }

    // ── Multi-chunk Authority Proof Assembly ─────────────────────────────────

    #[test]
    fn multi_chunk_proof_assembly_fills_entire_buffer() {
        let mut buf = [0u8; AuthorityProofState::LEN];
        let args = InitAuthorityProofArgs {
            statement_digest: [0xBB; 32],
            proof_commitment: [0xCC; 32],
        };
        process_init_authority_proof_data(&mut buf, args).expect("init proof should succeed");

        let chunk_size = AUTHORITY_PROOF_CHUNK_MAX_BYTES;
        let total = WotsAuthProof::ENCODED_LEN;
        let mut offset = 0u32;

        while (offset as usize) < total {
            let remaining = total - offset as usize;
            let len = remaining.min(chunk_size);
            let mut chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
            for b in chunk[..len].iter_mut() {
                *b = 0xAA;
            }
            let args = WriteAuthorityProofChunkArgs {
                offset,
                chunk_len: len as u16,
                chunk,
            };
            process_write_authority_proof_chunk_data(&mut buf, args)
                .expect("chunk write should succeed");
            offset += len as u32;
        }

        let state = AuthorityProofState::decode(&buf).expect("decode proof state");
        assert_eq!(state.bytes_written as usize, total);
    }

    #[test]
    fn multi_chunk_proof_rejects_gap_in_offset() {
        let mut buf = [0u8; AuthorityProofState::LEN];
        let args = InitAuthorityProofArgs {
            statement_digest: [0xDD; 32],
            proof_commitment: [0xEE; 32],
        };
        process_init_authority_proof_data(&mut buf, args).expect("init");

        // Write first chunk at offset 0
        let mut chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
        chunk.fill(0xAA);
        process_write_authority_proof_chunk_data(
            &mut buf,
            WriteAuthorityProofChunkArgs {
                offset: 0,
                chunk_len: AUTHORITY_PROOF_CHUNK_MAX_BYTES as u16,
                chunk,
            },
        )
        .expect("first chunk");

        // Skip to offset 2048 (gap!)
        let gap_chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
        let err = process_write_authority_proof_chunk_data(
            &mut buf,
            WriteAuthorityProofChunkArgs {
                offset: 2048,
                chunk_len: 128,
                chunk: gap_chunk,
            },
        )
        .expect_err("gap in offset must fail");
        assert_eq!(
            err,
            ProgramError::Custom(error::PROOF_CHUNK_OFFSET_MISMATCH)
        );
    }

    // ── Bridged Receipt Replay Prevention ────────────────────────────────────

    #[test]
    fn stage_bridged_receipt_rejects_double_init() {
        let receipt = PolicyReceipt {
            action_hash: [7; 32],
            policy_version: 5,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 3,
            expiry_slot: 9999,
        };
        let vault_bytes = sample_vault_bytes_for_receipt(&receipt);
        let eval_bytes = make_finalized_eval_bytes_for_receipt(&receipt);
        let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];

        // First staging succeeds
        process_stage_bridged_receipt_data(
            &vault_bytes,
            &mut receipt_buf,
            &eval_bytes,
            &receipt,
            100,
        )
        .expect("first staging should succeed");

        // Second staging must fail because the buffer is no longer zeroed
        let err = process_stage_bridged_receipt_data(
            &vault_bytes,
            &mut receipt_buf,
            &eval_bytes,
            &receipt,
            100,
        )
        .expect_err("double staging must fail");
        assert_eq!(err, ProgramError::AccountAlreadyInitialized);
    }

    // ── Recovery processor tests ────────────────────────────────────

    fn sample_init_recovery_args() -> InitRecoveryArgs {
        InitRecoveryArgs {
            vault_pubkey: [1; 32],
            recovery_commitment: [2; 32],
            expiry_slot: 5000,
            new_threshold: 2,
            new_participant_count: 3,
            bump: 42,
        }
    }

    #[test]
    fn init_recovery_creates_state() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        let args = sample_init_recovery_args();
        let result = process_init_recovery_data(
            &mut buf,
            args,
            VaultStatus::Recovery as u8,
            100, // current_slot
        );
        assert!(result.is_ok());

        let state = RecoveryState::decode(&buf).unwrap();
        assert_eq!(state.discriminator, RECOVERY_STATE_DISCRIMINATOR);
        assert_eq!(state.vault_pubkey, [1; 32]);
        assert_eq!(state.recovery_commitment, [2; 32]);
        assert_eq!(state.expiry_slot, 5000);
        assert_eq!(state.new_threshold, 2);
        assert_eq!(state.new_participant_count, 3);
        assert_eq!(state.status, RecoveryStatus::Pending as u8);
        assert_eq!(state.bump, 42);
    }

    #[test]
    fn init_recovery_rejects_double_init() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        let args = sample_init_recovery_args();
        process_init_recovery_data(&mut buf, args, VaultStatus::Recovery as u8, 100).unwrap();

        let err = process_init_recovery_data(&mut buf, args, VaultStatus::Recovery as u8, 100)
            .expect_err("double init must fail");
        assert_eq!(err, ProgramError::AccountAlreadyInitialized);
    }

    #[test]
    fn init_recovery_rejects_non_recovery_vault() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        let err = process_init_recovery_data(
            &mut buf,
            sample_init_recovery_args(),
            VaultStatus::Active as u8,
            100,
        )
        .expect_err("vault must be in recovery mode");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn init_recovery_rejects_undersized_buffer() {
        let mut buf = vec![0u8; RecoveryState::LEN - 1];
        let err = process_init_recovery_data(
            &mut buf,
            sample_init_recovery_args(),
            VaultStatus::Recovery as u8,
            100,
        )
        .expect_err("buffer must be at least RecoveryState::LEN");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn init_recovery_rejects_already_expired() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        let mut args = sample_init_recovery_args();
        args.expiry_slot = 50;
        let err = process_init_recovery_data(&mut buf, args, VaultStatus::Recovery as u8, 100)
            .expect_err("recovery must not be already expired");
        assert_eq!(err, ProgramError::Custom(error::RECOVERY_EXPIRED));
    }

    #[test]
    fn complete_recovery_succeeds() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        process_init_recovery_data(
            &mut buf,
            sample_init_recovery_args(),
            VaultStatus::Recovery as u8,
            100,
        )
        .unwrap();

        let args = CompleteRecoveryArgs {
            new_group_key: [3; 32],
            new_authority_hash: [4; 32],
        };
        let result = process_complete_recovery_data(&mut buf, args, 200);
        assert!(result.is_ok());

        let state = RecoveryState::decode(&buf).unwrap();
        assert_eq!(state.status, RecoveryStatus::Complete as u8);
        assert_eq!(state.new_group_key, [3; 32]);
        assert_eq!(state.new_authority_hash, [4; 32]);
    }

    #[test]
    fn complete_recovery_rejects_expired() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        process_init_recovery_data(
            &mut buf,
            sample_init_recovery_args(),
            VaultStatus::Recovery as u8,
            100,
        )
        .unwrap();

        let args = CompleteRecoveryArgs {
            new_group_key: [3; 32],
            new_authority_hash: [4; 32],
        };
        let err = process_complete_recovery_data(&mut buf, args, 5000)
            .expect_err("completion must fail when expired");
        assert_eq!(err, ProgramError::Custom(error::RECOVERY_EXPIRED));
    }

    #[test]
    fn complete_recovery_rejects_non_pending() {
        let mut buf = vec![0u8; RecoveryState::LEN];
        process_init_recovery_data(
            &mut buf,
            sample_init_recovery_args(),
            VaultStatus::Recovery as u8,
            100,
        )
        .unwrap();

        // Complete once
        let args = CompleteRecoveryArgs {
            new_group_key: [3; 32],
            new_authority_hash: [4; 32],
        };
        process_complete_recovery_data(&mut buf, args, 200).unwrap();

        // Try to complete again
        let err = process_complete_recovery_data(&mut buf, args, 200)
            .expect_err("double completion must fail");
        assert_eq!(err, ProgramError::AccountAlreadyInitialized);
    }

    // ── Authority migration processor tests ─────────────────────────

    fn make_authority_buffer(leaf_index: u32) -> Vec<u8> {
        let mut authority = crate::transition::initialize_quantum_authority([1; 32], [2; 32], 1);
        authority.next_leaf_index = leaf_index;
        let mut buf = vec![0u8; QuantumAuthorityState::LEN];
        authority.encode(&mut buf);
        buf
    }

    #[test]
    fn migrate_authority_resets_tree() {
        let mut buf = make_authority_buffer(10);
        let result = process_migrate_authority_data(&mut buf, [9; 32]);
        assert!(result.is_ok());

        let state = QuantumAuthorityState::decode(&buf).unwrap();
        assert_eq!(state.next_leaf_index, 0);
        assert_eq!(state.current_authority_root, [9; 32]);
        assert_eq!(state.discriminator, QUANTUM_STATE_DISCRIMINATOR);
    }

    #[test]
    fn migrate_authority_rejects_fresh_tree() {
        let mut buf = make_authority_buffer(0);
        let err = process_migrate_authority_data(&mut buf, [9; 32])
            .expect_err("migration on fresh tree is a no-op");
        assert_eq!(err, ProgramError::Custom(error::AUTHORITY_MIGRATION_NO_OP));
    }

    #[test]
    fn migrate_authority_rejects_undersized_buffer() {
        let mut buf = vec![0u8; QuantumAuthorityState::LEN - 1];
        let err = process_migrate_authority_data(&mut buf, [9; 32])
            .expect_err("buffer must be at least QuantumAuthorityState::LEN");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    // ── Policy version rollover processor tests ─────────────────────

    fn make_active_vault_buffer() -> Vec<u8> {
        let vault = VaultRegistry::new([1; 32], [2; 32], 10, VaultStatus::Active, 1, [0; 32]);
        let mut buf = vec![0u8; VaultRegistry::LEN];
        vault.encode(&mut buf);
        buf
    }

    #[test]
    fn advance_policy_version_happy_path() {
        let mut buf = make_active_vault_buffer();
        let result = process_advance_policy_version_data(&mut buf, 11);
        assert!(result.is_ok());
        let vault = VaultRegistry::decode(&buf).unwrap();
        assert_eq!(vault.policy_version, 11);
    }

    #[test]
    fn advance_policy_version_rejects_skip() {
        let mut buf = make_active_vault_buffer();
        let err = process_advance_policy_version_data(&mut buf, 12)
            .expect_err("skipping versions must fail");
        assert_eq!(
            err,
            ProgramError::Custom(error::POLICY_VERSION_NOT_MONOTONIC)
        );
    }

    #[test]
    fn advance_policy_version_rejects_inactive_vault() {
        let mut buf = vec![0u8; VaultRegistry::LEN];
        // Write discriminator but leave status = 0 (not Active)
        buf[..8].copy_from_slice(&VAULT_REGISTRY_DISCRIMINATOR);
        let err =
            process_advance_policy_version_data(&mut buf, 1).expect_err("inactive vault must fail");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn advance_policy_version_rejects_undersized_buffer() {
        let mut buf = vec![0u8; VaultRegistry::LEN - 1];
        let err = process_advance_policy_version_data(&mut buf, 1)
            .expect_err("buffer must be at least VaultRegistry::LEN");
        assert_eq!(err, ProgramError::InvalidAccountData);
    }
}
