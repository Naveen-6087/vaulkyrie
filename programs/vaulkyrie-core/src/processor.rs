use pinocchio::{
    account_info::AccountInfo,
    get_account_info,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt, WotsAuthProof};

use crate::{
    instruction::{
        CoreInstruction, InitAuthorityArgs, InitAuthorityProofArgs, InitQuantumVaultArgs,
        InitVaultArgs, WriteAuthorityProofChunkArgs,
    },
    state::{
        ActionSessionState, AuthorityProofState, PolicyReceiptState, QuantumAuthorityState,
        QuantumVaultState, VaultRegistry, ACTION_SESSION_DISCRIMINATOR,
        AUTHORITY_PROOF_DISCRIMINATOR, POLICY_RECEIPT_DISCRIMINATOR, QUANTUM_STATE_DISCRIMINATOR,
        QUANTUM_VAULT_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
    },
    transition,
};

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
                return Err(ProgramError::InvalidArgument);
            }

            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_init_authority_data(&mut data, args)
        }
        CoreInstruction::InitQuantumVault(args) => {
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_init_quantum_vault_data(&mut data, args)
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
        CoreInstruction::SplitQuantumVault { proof, amount } => {
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
                return Err(ProgramError::InvalidArgument);
            }

            {
                let mut vault_data = vault_account.try_borrow_mut_data()?;
                process_split_quantum_vault_data(
                    &mut vault_data,
                    amount,
                    *split_account.key(),
                    *refund_account.key(),
                    &proof,
                    vault_account.lamports(),
                )?;
            }

            {
                let mut split_lamports = split_account.try_borrow_mut_lamports()?;
                *split_lamports += amount;
            }
            {
                let refund_amount = vault_account.lamports().saturating_sub(amount);
                let mut refund_lamports = refund_account.try_borrow_mut_lamports()?;
                *refund_lamports += refund_amount;
            }

            vault_account.close()
        }
        CoreInstruction::CloseQuantumVault(proof) => {
            let vault_account = get_account_info!(accounts, 0);
            require_writable(vault_account)?;
            require_program_owner(program_id, vault_account)?;

            let refund_account = get_account_info!(accounts, 1);
            require_writable(refund_account)?;
            if vault_account.key() == refund_account.key() {
                return Err(ProgramError::InvalidArgument);
            }

            {
                let mut vault_data = vault_account.try_borrow_mut_data()?;
                process_close_quantum_vault_data(&mut vault_data, *refund_account.key(), &proof)?;
            }

            {
                let mut refund_lamports = refund_account.try_borrow_mut_lamports()?;
                *refund_lamports += vault_account.lamports();
            }

            vault_account.close()
        }
    }
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

pub fn process_init_quantum_vault_data(
    dst: &mut [u8],
    args: InitQuantumVaultArgs,
) -> ProgramResult {
    if dst.len() != QuantumVaultState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = transition::initialize_quantum_vault(
        args.current_authority_hash,
        args.current_authority_root,
        args.bump,
    );
    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
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

    let offset = usize::try_from(args.offset).map_err(|_| ProgramError::InvalidArgument)?;
    let chunk = args.chunk_bytes();
    if offset != state.bytes_written as usize {
        return Err(ProgramError::InvalidArgument);
    }
    let end = offset
        .checked_add(chunk.len())
        .ok_or(ProgramError::InvalidArgument)?;
    if end > WotsAuthProof::ENCODED_LEN {
        return Err(ProgramError::InvalidArgument);
    }

    state.proof_bytes[offset..end].copy_from_slice(chunk);
    state.bytes_written = end as u32;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_split_quantum_vault_data(
    dst: &mut [u8],
    amount: u64,
    split_pubkey: [u8; 32],
    refund_pubkey: [u8; 32],
    proof: &WotsAuthProof,
    vault_lamports: u64,
) -> ProgramResult {
    if dst.len() != QuantumVaultState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = QuantumVaultState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &QUANTUM_VAULT_DISCRIMINATOR)?;
    transition::validate_quantum_vault_split_amount(vault_lamports, amount)
        .map_err(map_transition_error)?;
    transition::verify_quantum_vault_split(&state, amount, split_pubkey, refund_pubkey, proof)
        .map_err(map_transition_error)?;
    transition::close_quantum_vault(&mut state).map_err(map_transition_error)?;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_close_quantum_vault_data(
    dst: &mut [u8],
    refund_pubkey: [u8; 32],
    proof: &WotsAuthProof,
) -> ProgramResult {
    if dst.len() != QuantumVaultState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = QuantumVaultState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &QUANTUM_VAULT_DISCRIMINATOR)?;
    transition::verify_quantum_vault_close(&state, refund_pubkey, proof)
        .map_err(map_transition_error)?;
    transition::close_quantum_vault(&mut state).map_err(map_transition_error)?;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
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
        return Err(ProgramError::InvalidArgument);
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
        return Err(ProgramError::InvalidArgument);
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
        return Err(ProgramError::InvalidArgument);
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
        return Err(ProgramError::InvalidArgument);
    }

    let mut receipt_state =
        PolicyReceiptState::decode(receipt_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&receipt_state.discriminator, &POLICY_RECEIPT_DISCRIMINATOR)?;

    let mut session_state =
        ActionSessionState::decode(session_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&session_state.discriminator, &ACTION_SESSION_DISCRIMINATOR)?;
    if session_state.policy_version != expected_policy_version {
        return Err(ProgramError::InvalidArgument);
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

    let mut proof_state =
        AuthorityProofState::decode(proof_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&proof_state.discriminator, &AUTHORITY_PROOF_DISCRIMINATOR)?;
    if proof_state.consumed != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    if proof_state.statement_digest != statement.digest() {
        return Err(ProgramError::InvalidArgument);
    }
    if proof_state.bytes_written as usize != WotsAuthProof::ENCODED_LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    let proof =
        WotsAuthProof::decode(&proof_state.proof_bytes).ok_or(ProgramError::InvalidAccountData)?;
    if proof.commitment() != proof_state.proof_commitment {
        return Err(ProgramError::InvalidArgument);
    }

    process_rotate_authority_data(vault_dst, authority_dst, statement, &proof, current_slot)?;
    proof_state.consumed = 1;

    if !proof_state.encode(proof_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

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
        transition::TransitionError::ReceiptExpired => ProgramError::InvalidArgument,
        transition::TransitionError::ReceiptNonceReplay => ProgramError::InvalidArgument,
        transition::TransitionError::SessionExpired => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityStatementExpired => ProgramError::InvalidArgument,
        transition::TransitionError::VaultAuthorityMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::VaultPolicyMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::VaultNotActive => ProgramError::InvalidAccountData,
        transition::TransitionError::VaultNotRecovery => ProgramError::InvalidAccountData,
        transition::TransitionError::VaultStatusInvalid => ProgramError::InvalidInstructionData,
        transition::TransitionError::VaultStatusTransitionNotAllowed => {
            ProgramError::InvalidArgument
        }
        transition::TransitionError::SessionPolicyMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::SessionMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::SessionNotPending => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::SessionNotReady => ProgramError::InvalidAccountData,
        transition::TransitionError::SessionRequiresPqc => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityNoOp => ProgramError::InvalidArgument,
        transition::TransitionError::AuthoritySequenceMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityLeafIndexMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityActionMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityProofInvalid => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityProofMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityMerkleRootMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityTreeExhausted => ProgramError::InvalidArgument,
        transition::TransitionError::QuantumVaultClosed => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::QuantumVaultAmountTooLarge => ProgramError::InsufficientFunds,
    }
}

#[cfg(test)]
mod tests {
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{
        quantum_close_digest, quantum_split_digest, ActionDescriptor, ActionKind, PolicyReceipt,
        ThresholdRequirement, WotsAuthProof, WotsSecretKey, AUTHORITY_PROOF_CHUNK_MAX_BYTES,
        WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES, XMSS_LEAF_COUNT,
    };

    use super::{
        ensure_wallet_authority, process_activate_session_data, process_close_quantum_vault_data,
        process_consume_receipt_data, process_consume_session_data, process_finalize_session_data,
        process_init_authority_data, process_init_authority_proof_data,
        process_init_quantum_vault_data, process_init_vault_data, process_open_session_data,
        process_rotate_authority_data, process_rotate_authority_staged_data,
        process_set_vault_status_data, process_split_quantum_vault_data,
        process_stage_receipt_data, process_write_authority_proof_chunk_data,
    };
    use crate::{
        instruction::{
            InitAuthorityArgs, InitAuthorityProofArgs, InitQuantumVaultArgs, InitVaultArgs,
            WriteAuthorityProofChunkArgs,
        },
        state::{
            ActionSessionState, AuthorityProofState, PolicyReceiptState, QuantumAuthorityState,
            QuantumVaultState, QuantumVaultStatus, SessionStatus, VaultRegistry, VaultStatus,
            ACTION_SESSION_DISCRIMINATOR,
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
        let vault = VaultRegistry::new([5; 32], [6; 32], 7, VaultStatus::Active, 8);
        assert!(vault.encode(&mut bytes));

        process_set_vault_status_data(&mut bytes, VaultStatus::Locked as u8)
            .expect("active to locked should pass");

        let updated = VaultRegistry::decode(&bytes).expect("vault should decode");
        assert_eq!(updated.status, VaultStatus::Locked as u8);
    }

    #[test]
    fn set_vault_status_rejects_unknown_value() {
        let mut bytes = [0; VaultRegistry::LEN];
        let vault = VaultRegistry::new([5; 32], [6; 32], 7, VaultStatus::Active, 8);
        assert!(vault.encode(&mut bytes));

        let error =
            process_set_vault_status_data(&mut bytes, 42).expect_err("unknown status should fail");

        assert_eq!(error, ProgramError::InvalidInstructionData);
    }

    #[test]
    fn set_vault_status_rejects_disallowed_transition() {
        let mut bytes = [0; VaultRegistry::LEN];
        let vault = VaultRegistry::new([5; 32], [6; 32], 7, VaultStatus::Locked, 8);
        assert!(vault.encode(&mut bytes));

        let error = process_set_vault_status_data(&mut bytes, VaultStatus::Active as u8)
            .expect_err("locked to active should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
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
            },
        )
        .expect("vault init should succeed");

        let state = VaultRegistry::decode(&bytes).expect("state should decode");
        assert_eq!(state.wallet_pubkey, [5; 32]);
        assert_eq!(state.current_authority_hash, [6; 32]);
        assert_eq!(state.policy_version, 7);
        assert_eq!(state.bump, 8);
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

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn stage_and_consume_receipt_updates_consumed_flag() {
        let receipt = sample_receipt();
        let vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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
        let mut vault =
            VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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

        assert_eq!(error, ProgramError::InvalidArgument);
        let state = PolicyReceiptState::decode(&receipt_bytes).expect("state should decode");
        assert_eq!(state.consumed, 0);
    }

    #[test]
    fn stage_receipt_rejects_policy_mismatch() {
        let receipt = sample_receipt();
        let vault = VaultRegistry::new([5; 32], [6; 32], 99, crate::state::VaultStatus::Active, 8);
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("policy mismatch should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn stage_receipt_rejects_non_active_vault() {
        let receipt = sample_receipt();
        let vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Locked, 8);
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
        let vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("expired receipt should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn stage_receipt_rejects_replayed_nonce() {
        let receipt = sample_receipt();
        let mut vault =
            VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
        vault.last_consumed_receipt_nonce = receipt.nonce;
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut receipt_bytes = [0; PolicyReceiptState::LEN];

        assert!(vault.encode(&mut vault_bytes));
        let error = process_stage_receipt_data(&vault_bytes, &mut receipt_bytes, &receipt, 10)
            .expect_err("replayed nonce should fail stage");

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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
        let vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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
        let vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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
        let vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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
        let mut vault =
            VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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

        assert_eq!(error, ProgramError::InvalidArgument);
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
    fn init_quantum_vault_writes_encoded_state() {
        let mut bytes = [0; QuantumVaultState::LEN];

        process_init_quantum_vault_data(
            &mut bytes,
            InitQuantumVaultArgs {
                current_authority_hash: [7; 32],
                current_authority_root: [8; 32],
                bump: 4,
            },
        )
        .expect("init quantum vault should succeed");

        let state = QuantumVaultState::decode(&bytes).expect("quantum vault should decode");
        assert_eq!(state.current_authority_hash, [7; 32]);
        assert_eq!(state.current_authority_root, [8; 32]);
        assert_eq!(state.status, QuantumVaultStatus::Open as u8);
    }

    #[test]
    fn split_quantum_vault_marks_state_closed() {
        let secret = sample_wots_secret(51);
        let auth_path = sample_auth_path(41);
        let digest = quantum_split_digest(55, [7; 32], [8; 32]);
        let proof = secret.sign_digest_with_auth_path(digest, 0, auth_path);
        let state = QuantumVaultState::new(secret.authority_hash(), proof.merkle_root(), 3);
        let mut bytes = [0; QuantumVaultState::LEN];
        assert!(state.encode(&mut bytes));

        process_split_quantum_vault_data(&mut bytes, 55, [7; 32], [8; 32], &proof, 100)
            .expect("split quantum vault should succeed");

        let state = QuantumVaultState::decode(&bytes).expect("quantum vault should decode");
        assert_eq!(state.status, QuantumVaultStatus::Closed as u8);
    }

    #[test]
    fn split_quantum_vault_rejects_overspend() {
        let secret = sample_wots_secret(52);
        let auth_path = sample_auth_path(42);
        let digest = quantum_split_digest(101, [7; 32], [8; 32]);
        let proof = secret.sign_digest_with_auth_path(digest, 0, auth_path);
        let state = QuantumVaultState::new(secret.authority_hash(), proof.merkle_root(), 3);
        let mut bytes = [0; QuantumVaultState::LEN];
        assert!(state.encode(&mut bytes));

        let error =
            process_split_quantum_vault_data(&mut bytes, 101, [7; 32], [8; 32], &proof, 100)
                .expect_err("overspend must fail");

        assert_eq!(error, ProgramError::InsufficientFunds);
    }

    #[test]
    fn close_quantum_vault_marks_state_closed() {
        let secret = sample_wots_secret(53);
        let auth_path = sample_auth_path(43);
        let digest = quantum_close_digest([9; 32]);
        let proof = secret.sign_digest_with_auth_path(digest, 0, auth_path);
        let state = QuantumVaultState::new(secret.authority_hash(), proof.merkle_root(), 3);
        let mut bytes = [0; QuantumVaultState::LEN];
        assert!(state.encode(&mut bytes));

        process_close_quantum_vault_data(&mut bytes, [9; 32], &proof)
            .expect("close quantum vault should succeed");

        let state = QuantumVaultState::decode(&bytes).expect("quantum vault should decode");
        assert_eq!(state.status, QuantumVaultStatus::Closed as u8);
    }
}
