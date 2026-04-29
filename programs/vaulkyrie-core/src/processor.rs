#[cfg(all(not(feature = "bpf-entrypoint"), not(target_os = "solana")))]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
use pinocchio::sysvars::clock::Clock;
use pinocchio::{
    account_info::AccountInfo,
    get_account_info,
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program::invoke_signed,
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use solana_winternitz::signature::WinternitzSignature;
use vaulkyrie_protocol::{
    pqc_wallet_advance_message, AuthorityRotationStatement, WotsAuthProof, PQC_WALLET_SEED,
    QUANTUM_AUTHORITY_SEED, QUANTUM_VAULT_SEED, SPEND_ORCH_SEED, VAULT_REGISTRY_SEED,
};

use crate::{
    error,
    instruction::{
        CommitSpendOrchestrationArgs, CompleteSpendOrchestrationArgs, CoreInstruction,
        FailSpendOrchestrationArgs, InitAuthorityArgs, InitAuthorityProofArgs, InitPqcWalletArgs,
        InitQuantumVaultArgs, InitSpendOrchestrationArgs, InitVaultArgs,
        WriteAuthorityProofChunkArgs,
    },
    pda,
    state::{
        AuthorityProofState, PqcWalletState, QuantumAuthorityState, SpendOrchestrationState,
        VaultRegistry, AUTHORITY_PROOF_DISCRIMINATOR, PQC_WALLET_DISCRIMINATOR,
        QUANTUM_STATE_DISCRIMINATOR, SPEND_ORCH_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
    },
    transition,
};

const SYSTEM_PROGRAM_ID: pinocchio::pubkey::Pubkey = [0; 32];
#[cfg(all(not(feature = "bpf-entrypoint"), not(target_os = "solana")))]
static HOST_TEST_SLOT: AtomicU64 = AtomicU64::new(0);

#[cfg(all(not(feature = "bpf-entrypoint"), not(target_os = "solana")))]
pub fn set_host_test_slot(slot: u64) {
    HOST_TEST_SLOT.store(slot, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::AUTHORITY_PROOF_CHUNK_MAX_BYTES;

    use super::{
        ensure_wallet_authority, process_commit_spend_orchestration_data,
        process_complete_recovery_data, process_complete_spend_orchestration_data,
        process_fail_spend_orchestration_data, process_init_authority_data,
        process_init_authority_proof_data, process_init_recovery_data,
        process_init_spend_orchestration_data, process_init_vault_data,
        process_set_vault_status_data, process_write_authority_proof_chunk_data,
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
            AuthorityProofState, OrchestrationStatus, QuantumAuthorityState, RecoveryState,
            RecoveryStatus, SpendOrchestrationState, VaultRegistry, VaultStatus,
        },
    };

    #[test]
    fn wallet_authority_requires_signer() {
        let error = ensure_wallet_authority([1; 32], [1; 32], false).unwrap_err();
        assert_eq!(error, ProgramError::MissingRequiredSignature);
    }

    #[test]
    fn init_vault_writes_encoded_state() {
        let mut bytes = [0; VaultRegistry::LEN];
        process_init_vault_data(
            &mut bytes,
            InitVaultArgs {
                wallet_pubkey: [5; 32],
                authority_hash: [6; 32],
                bump: 8,
            },
        )
        .unwrap();

        let state = VaultRegistry::decode(&bytes).unwrap();
        assert_eq!(state.wallet_pubkey, [5; 32]);
        assert_eq!(state.current_authority_hash, [6; 32]);
        assert_eq!(state.status, VaultStatus::Active as u8);
        assert_eq!(state.bump, 8);
    }

    #[test]
    fn set_vault_status_updates_state() {
        let mut bytes = [0; VaultRegistry::LEN];
        let vault = VaultRegistry::new([5; 32], [6; 32], VaultStatus::Active, 8);
        assert!(vault.encode(&mut bytes));

        process_set_vault_status_data(&mut bytes, VaultStatus::Locked as u8).unwrap();

        let updated = VaultRegistry::decode(&bytes).unwrap();
        assert_eq!(updated.status, VaultStatus::Locked as u8);
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
        .unwrap();

        let state = QuantumAuthorityState::decode(&bytes).unwrap();
        assert_eq!(state.current_authority_hash, [7; 32]);
        assert_eq!(state.current_authority_root, [8; 32]);
        assert_eq!(state.next_sequence, 0);
    }

    #[test]
    fn authority_proof_chunk_appends_bytes() {
        let mut bytes = [0; AuthorityProofState::LEN];
        process_init_authority_proof_data(
            &mut bytes,
            InitAuthorityProofArgs {
                statement_digest: [7; 32],
                proof_commitment: [8; 32],
            },
        )
        .unwrap();

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
        .unwrap();

        let state = AuthorityProofState::decode(&bytes).unwrap();
        assert_eq!(state.bytes_written, 3);
        assert_eq!(&state.proof_bytes[..3], &[1, 2, 3]);
    }

    #[test]
    fn proof_chunk_rejects_wrong_offset() {
        let mut bytes = [0; AuthorityProofState::LEN];
        process_init_authority_proof_data(
            &mut bytes,
            InitAuthorityProofArgs {
                statement_digest: [7; 32],
                proof_commitment: [8; 32],
            },
        )
        .unwrap();

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
        .unwrap_err();

        assert_eq!(
            error,
            ProgramError::Custom(error::PROOF_CHUNK_OFFSET_MISMATCH)
        );
    }

    #[test]
    fn spend_orchestration_roundtrip() {
        let mut bytes = [0; SpendOrchestrationState::LEN];
        process_init_spend_orchestration_data(
            &mut bytes,
            InitSpendOrchestrationArgs {
                action_hash: [1; 32],
                session_commitment: [2; 32],
                signers_commitment: [3; 32],
                signing_package_hash: [4; 32],
                expiry_slot: 100,
                threshold: 2,
                participant_count: 3,
                bump: 9,
            },
            10,
        )
        .unwrap();

        process_commit_spend_orchestration_data(
            &mut bytes,
            CommitSpendOrchestrationArgs {
                action_hash: [1; 32],
                signing_package_hash: [5; 32],
            },
            20,
        )
        .unwrap();
        process_complete_spend_orchestration_data(
            &mut bytes,
            CompleteSpendOrchestrationArgs {
                action_hash: [1; 32],
                tx_binding: [6; 32],
            },
            30,
        )
        .unwrap();

        let state = SpendOrchestrationState::decode(&bytes).unwrap();
        assert_eq!(state.status, OrchestrationStatus::Complete as u8);
        assert_eq!(state.tx_binding, [6; 32]);
    }

    #[test]
    fn spend_orchestration_can_fail_before_completion() {
        let mut bytes = [0; SpendOrchestrationState::LEN];
        process_init_spend_orchestration_data(
            &mut bytes,
            InitSpendOrchestrationArgs {
                action_hash: [1; 32],
                session_commitment: [2; 32],
                signers_commitment: [3; 32],
                signing_package_hash: [4; 32],
                expiry_slot: 100,
                threshold: 2,
                participant_count: 3,
                bump: 9,
            },
            10,
        )
        .unwrap();

        process_fail_spend_orchestration_data(
            &mut bytes,
            FailSpendOrchestrationArgs {
                action_hash: [1; 32],
                reason_code: 42,
            },
        )
        .unwrap();

        let state = SpendOrchestrationState::decode(&bytes).unwrap();
        assert_eq!(state.status, OrchestrationStatus::Failed as u8);
    }

    #[test]
    fn recovery_roundtrip() {
        let mut bytes = [0; RecoveryState::LEN];
        process_init_recovery_data(
            &mut bytes,
            InitRecoveryArgs {
                vault_pubkey: [1; 32],
                recovery_commitment: [2; 32],
                expiry_slot: 100,
                new_threshold: 2,
                new_participant_count: 3,
                bump: 4,
            },
            VaultStatus::Recovery as u8,
            10,
        )
        .unwrap();

        process_complete_recovery_data(
            &mut bytes,
            CompleteRecoveryArgs {
                new_group_key: [8; 32],
                new_authority_hash: [9; 32],
            },
            20,
        )
        .unwrap();

        let state = RecoveryState::decode(&bytes).unwrap();
        assert_eq!(state.status, RecoveryStatus::Complete as u8);
        assert_eq!(state.new_group_key, [8; 32]);
        assert_eq!(state.new_authority_hash, [9; 32]);
    }
}

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
            if let Some(system_program) = accounts.get(2) {
                process_open_vault_registry(
                    program_id,
                    wallet_signer,
                    account,
                    system_program,
                    args,
                )?;
            } else {
                require_program_owner(program_id, account)?;
            }
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
            if let Some(system_program) = accounts.get(3) {
                process_open_quantum_authority(
                    program_id,
                    wallet_signer,
                    account,
                    vault_account,
                    system_program,
                    args,
                )?;
            } else {
                require_program_owner(program_id, account)?;
            }
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
        CoreInstruction::InitPqcWallet(args) => process_open_pqc_wallet(program_id, accounts, args),
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
        CoreInstruction::AdvanceWinterAuthority(args) => {
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

            process_advance_winter_authority_data(
                &mut vault_data,
                &mut authority_data,
                &args.statement,
                &args.signature,
                current_slot,
            )
        }
        CoreInstruction::AdvancePqcWallet(args) => {
            let wallet_account = get_account_info!(accounts, 0);
            require_writable(wallet_account)?;
            require_program_owner(program_id, wallet_account)?;

            let destination_account = get_account_info!(accounts, 1);
            require_writable(destination_account)?;
            if wallet_account.key() == destination_account.key() {
                return Err(ProgramError::Custom(error::DUPLICATE_ACCOUNT_KEYS));
            }

            {
                let mut wallet_data = wallet_account.try_borrow_mut_data()?;
                process_advance_pqc_wallet_data(
                    &mut wallet_data,
                    args.amount,
                    *destination_account.key(),
                    &args.signature(),
                    args.next_root,
                    wallet_account.lamports(),
                )?;
            }

            {
                let mut wallet_lamports = wallet_account.try_borrow_mut_lamports()?;
                *wallet_lamports = (*wallet_lamports).saturating_sub(args.amount);
            }
            {
                let mut destination_lamports = destination_account.try_borrow_mut_lamports()?;
                *destination_lamports += args.amount;
            }

            Ok(())
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

            if let Some(system_program) = accounts.get(3) {
                process_open_spend_orchestration(
                    program_id,
                    wallet_signer,
                    orch_account,
                    vault_account,
                    system_program,
                    args,
                )?;
            } else {
                require_program_owner(program_id, orch_account)?;
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

    let state = transition::initialize_vault(args.wallet_pubkey, args.authority_hash, args.bump);

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

    let lamports = Rent::get()?.minimum_balance(0);
    let bump_seed = [args.bump];
    pda::verify_quantum_vault(vault.key(), &args.hash, args.bump, program_id)?;
    let signer_seed_bytes = quantum_vault_signer_seed_slices(&args.hash, &bump_seed);
    let seeds = [
        Seed::from(signer_seed_bytes[0]),
        Seed::from(signer_seed_bytes[1]),
        Seed::from(signer_seed_bytes[2]),
    ];
    let signers = [Signer::from(&seeds)];
    create_program_owned_account(
        program_id,
        payer,
        vault,
        system_program,
        &signers,
        lamports,
        0,
    )
}

pub fn process_open_pqc_wallet(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    args: InitPqcWalletArgs,
) -> ProgramResult {
    let [payer, wallet, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    pda::verify_pqc_wallet(wallet.key(), &args.wallet_id, args.bump, program_id)?;
    let bump_seed = [args.bump];
    let signer_seed_bytes = pqc_wallet_signer_seed_slices(&args.wallet_id, &bump_seed);
    let seeds = [
        Seed::from(signer_seed_bytes[0]),
        Seed::from(signer_seed_bytes[1]),
        Seed::from(signer_seed_bytes[2]),
    ];
    let signers = [Signer::from(&seeds)];
    let lamports = Rent::get()?.minimum_balance(PqcWalletState::LEN);
    create_program_owned_account(
        program_id,
        payer,
        wallet,
        system_program,
        &signers,
        lamports,
        PqcWalletState::LEN as u64,
    )?;

    let mut data = wallet.try_borrow_mut_data()?;
    let state = PqcWalletState::new(args.wallet_id, args.current_root, args.bump);
    if !state.encode(&mut data) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn quantum_vault_signer_seed_slices<'a>(
    hash: &'a [u8; 32],
    bump_seed: &'a [u8; 1],
) -> [&'a [u8]; 3] {
    [QUANTUM_VAULT_SEED, hash, bump_seed]
}

fn pqc_wallet_signer_seed_slices<'a>(
    wallet_id: &'a [u8; 32],
    bump_seed: &'a [u8; 1],
) -> [&'a [u8]; 3] {
    [PQC_WALLET_SEED, wallet_id, bump_seed]
}

fn rent_minimum_balance(data_len: usize) -> Result<u64, ProgramError> {
    #[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
    {
        Rent::get().map(|rent| rent.minimum_balance(data_len))
    }

    #[cfg(all(not(feature = "bpf-entrypoint"), not(target_os = "solana")))]
    {
        let _ = data_len;
        Ok(0)
    }
}

fn create_program_owned_account(
    program_id: &pinocchio::pubkey::Pubkey,
    payer: &AccountInfo,
    new_account: &AccountInfo,
    system_program: &AccountInfo,
    signers: &[Signer],
    lamports: u64,
    space: u64,
) -> ProgramResult {
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    require_writable(payer)?;
    require_writable(new_account)?;
    if system_program.key() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let account_metas = [
        AccountMeta::writable_signer(payer.key()),
        AccountMeta::writable_signer(new_account.key()),
    ];
    let mut instruction_data = [0u8; 52];
    instruction_data[4..12].copy_from_slice(&lamports.to_le_bytes());
    instruction_data[12..20].copy_from_slice(&space.to_le_bytes());
    instruction_data[20..52].copy_from_slice(program_id);
    let instruction = Instruction {
        program_id: &SYSTEM_PROGRAM_ID,
        accounts: &account_metas,
        data: &instruction_data,
    };

    invoke_signed(&instruction, &[payer, new_account], signers)
}

fn process_open_vault_registry(
    program_id: &pinocchio::pubkey::Pubkey,
    payer: &AccountInfo,
    vault_registry: &AccountInfo,
    system_program: &AccountInfo,
    args: InitVaultArgs,
) -> ProgramResult {
    let bump_seed = [args.bump];
    let seeds = [
        Seed::from(VAULT_REGISTRY_SEED),
        Seed::from(&args.wallet_pubkey),
        Seed::from(&bump_seed),
    ];
    let signers = [Signer::from(&seeds)];
    let lamports = Rent::get()?.minimum_balance(VaultRegistry::LEN);
    create_program_owned_account(
        program_id,
        payer,
        vault_registry,
        system_program,
        &signers,
        lamports,
        VaultRegistry::LEN as u64,
    )
}

fn process_open_quantum_authority(
    program_id: &pinocchio::pubkey::Pubkey,
    payer: &AccountInfo,
    authority_account: &AccountInfo,
    vault_account: &AccountInfo,
    system_program: &AccountInfo,
    args: InitAuthorityArgs,
) -> ProgramResult {
    let bump_seed = [args.bump];
    let seeds = [
        Seed::from(QUANTUM_AUTHORITY_SEED),
        Seed::from(vault_account.key().as_ref()),
        Seed::from(&bump_seed),
    ];
    let signers = [Signer::from(&seeds)];
    let lamports = Rent::get()?.minimum_balance(QuantumAuthorityState::LEN);
    create_program_owned_account(
        program_id,
        payer,
        authority_account,
        system_program,
        &signers,
        lamports,
        QuantumAuthorityState::LEN as u64,
    )
}

fn process_open_spend_orchestration(
    program_id: &pinocchio::pubkey::Pubkey,
    payer: &AccountInfo,
    orch_account: &AccountInfo,
    vault_account: &AccountInfo,
    system_program: &AccountInfo,
    args: InitSpendOrchestrationArgs,
) -> ProgramResult {
    let bump_seed = [args.bump];
    let seeds = [
        Seed::from(SPEND_ORCH_SEED),
        Seed::from(vault_account.key().as_ref()),
        Seed::from(&args.action_hash),
        Seed::from(&bump_seed),
    ];
    let signers = [Signer::from(&seeds)];
    let lamports = Rent::get()?.minimum_balance(SpendOrchestrationState::LEN);
    create_program_owned_account(
        program_id,
        payer,
        orch_account,
        system_program,
        &signers,
        lamports,
        SpendOrchestrationState::LEN as u64,
    )
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

pub fn process_advance_pqc_wallet_data(
    wallet_dst: &mut [u8],
    amount: u64,
    destination: [u8; 32],
    signature: &WinternitzSignature,
    next_root: [u8; 32],
    wallet_lamports: u64,
) -> ProgramResult {
    if wallet_dst.len() != PqcWalletState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let mut state = PqcWalletState::decode(wallet_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &PQC_WALLET_DISCRIMINATOR)?;

    let rent_reserve = rent_minimum_balance(PqcWalletState::LEN)?;
    let spendable = wallet_lamports.saturating_sub(rent_reserve);
    if amount > spendable {
        return Err(ProgramError::InsufficientFunds);
    }

    let message = pqc_wallet_advance_message(
        state.wallet_id,
        state.current_root,
        next_root,
        destination,
        amount,
        state.sequence,
    );
    let recovered_root = signature.recover_pubkey(&message).merklize();
    if recovered_root != state.current_root {
        return Err(ProgramError::MissingRequiredSignature);
    }

    state.current_root = next_root;
    state.sequence = state
        .sequence
        .checked_add(1)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if !state.encode(wallet_dst) {
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
    validate_and_rotate_with_proof(
        vault_dst,
        authority_dst,
        proof_dst,
        &pc,
        statement,
        current_slot,
    )
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

pub fn process_advance_winter_authority_data(
    vault_dst: &mut [u8],
    authority_dst: &mut [u8],
    statement: &vaulkyrie_protocol::WinterAuthorityAdvanceStatement,
    signature: &vaulkyrie_protocol::WinterAuthoritySignature,
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

    transition::advance_winter_authority(
        &mut vault,
        &mut authority,
        statement,
        signature,
        current_slot,
    )
    .map_err(map_transition_error)?;

    if !vault.encode(vault_dst) || !authority.encode(authority_dst) {
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
    #[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
    {
        Ok(Clock::get()?.slot)
    }

    #[cfg(all(not(feature = "bpf-entrypoint"), not(target_os = "solana")))]
    {
        Ok(HOST_TEST_SLOT.load(Ordering::Relaxed))
    }
}

fn map_transition_error(error: transition::TransitionError) -> ProgramError {
    match error {
        transition::TransitionError::AuthorityStatementExpired => {
            ProgramError::Custom(error::AUTHORITY_STATEMENT_EXPIRED)
        }
        transition::TransitionError::VaultAuthorityMismatch => {
            ProgramError::Custom(error::VAULT_AUTHORITY_MISMATCH)
        }
        transition::TransitionError::VaultNotActive => ProgramError::InvalidAccountData,
        transition::TransitionError::VaultNotRecovery => ProgramError::InvalidAccountData,
        transition::TransitionError::VaultStatusInvalid => ProgramError::InvalidInstructionData,
        transition::TransitionError::VaultStatusTransitionNotAllowed => {
            ProgramError::Custom(error::VAULT_STATUS_BAD_TRANSITION)
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
        transition::TransitionError::TxBindingMissing => ProgramError::InvalidInstructionData,
        transition::TransitionError::AuthorityStatementReplay => {
            ProgramError::Custom(error::AUTHORITY_STATEMENT_REPLAY)
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
