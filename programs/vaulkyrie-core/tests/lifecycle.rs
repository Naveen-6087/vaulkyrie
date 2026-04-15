// Vaulkyrie lifecycle integration tests
//
// These tests chain multiple processor-level data functions to verify
// that complete instruction flows work end-to-end.  Each test operates
// on byte buffers (the same representation the on-chain program uses)
// so the entire state-machine path is exercised without needing a BPF
// runtime.

use vaulkyrie_core::{
    error,
    instruction::{
        CommitSpendOrchestrationArgs, CompleteRecoveryArgs, CompleteSpendOrchestrationArgs,
        FailSpendOrchestrationArgs, InitAuthorityArgs, InitAuthorityProofArgs, InitRecoveryArgs,
        InitSpendOrchestrationArgs, InitVaultArgs, WriteAuthorityProofChunkArgs,
    },
    processor::{
        process_activate_session_data, process_advance_policy_version_data,
        process_commit_spend_orchestration_data, process_complete_recovery_data,
        process_complete_spend_orchestration_data, process_consume_receipt_data,
        process_consume_session_data, process_fail_spend_orchestration_data,
        process_finalize_session_data, process_init_authority_data,
        process_init_authority_proof_data, process_init_recovery_data,
        process_init_spend_orchestration_data, process_init_vault_data,
        process_migrate_authority_data, process_open_session_data,
        process_set_vault_status_data, process_stage_bridged_receipt_data,
        process_stage_receipt_data, process_write_authority_proof_chunk_data,
    },
    state::{
        ActionSessionState, AuthorityProofState, PolicyReceiptState, QuantumAuthorityState,
        RecoveryState, SpendOrchestrationState, VaultRegistry, VaultStatus,
    },
};
use vaulkyrie_protocol::{
    PolicyReceipt, ThresholdRequirement, WotsAuthProof, AUTHORITY_PROOF_CHUNK_MAX_BYTES,
};

// ── Helpers ────────────────────────────────────────────────────────────────

const WALLET: [u8; 32] = [0xAA; 32];
const AUTH_HASH: [u8; 32] = [0xBB; 32];
const AUTH_ROOT: [u8; 32] = [0xCC; 32];
const MXE_PROGRAM: [u8; 32] = [0xDD; 32];
const ACTION_HASH: [u8; 32] = [0x11; 32];
const POLICY_VERSION: u64 = 1;
const CURRENT_SLOT: u64 = 100;
const FUTURE_SLOT: u64 = 10_000;

fn make_receipt(nonce: u64) -> PolicyReceipt {
    PolicyReceipt {
        action_hash: ACTION_HASH,
        policy_version: POLICY_VERSION,
        threshold: ThresholdRequirement::TwoOfThree,
        nonce,
        expiry_slot: FUTURE_SLOT,
    }
}

fn init_vault_buf() -> Vec<u8> {
    let mut buf = vec![0u8; VaultRegistry::LEN];
    let args = InitVaultArgs {
        wallet_pubkey: WALLET,
        authority_hash: AUTH_HASH,
        policy_version: POLICY_VERSION,
        bump: 255,
        policy_mxe_program: MXE_PROGRAM,
    };
    process_init_vault_data(&mut buf, args).expect("init vault");
    buf
}

fn init_vault_and_stage_receipt(nonce: u64) -> (Vec<u8>, Vec<u8>) {
    let vault_buf = init_vault_buf();
    let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];
    let receipt = make_receipt(nonce);
    process_stage_receipt_data(&vault_buf, &mut receipt_buf, &receipt, CURRENT_SLOT)
        .expect("stage receipt");
    (vault_buf, receipt_buf)
}

fn is_program_error_custom(err: pinocchio::program_error::ProgramError, code: u32) -> bool {
    matches!(err, pinocchio::program_error::ProgramError::Custom(c) if c == code)
}

// ── 1. Vault lifecycle ─────────────────────────────────────────────────────

#[test]
fn vault_lifecycle_init_status_advance() {
    let mut vault_buf = init_vault_buf();

    let vault = VaultRegistry::decode(&vault_buf).unwrap();
    assert_eq!(vault.wallet_pubkey, WALLET);
    assert_eq!(vault.current_authority_hash, AUTH_HASH);
    assert_eq!(vault.policy_version, POLICY_VERSION);
    assert_eq!(vault.status, VaultStatus::Active as u8);
    assert_eq!(vault.policy_mxe_program, MXE_PROGRAM);
    assert_eq!(vault.last_consumed_receipt_nonce, 0);

    // Active → Recovery
    process_set_vault_status_data(&mut vault_buf, VaultStatus::Recovery as u8).unwrap();
    let vault = VaultRegistry::decode(&vault_buf).unwrap();
    assert_eq!(vault.status, VaultStatus::Recovery as u8);

    // Recovery → Active
    process_set_vault_status_data(&mut vault_buf, VaultStatus::Active as u8).unwrap();
    let vault = VaultRegistry::decode(&vault_buf).unwrap();
    assert_eq!(vault.status, VaultStatus::Active as u8);

    // Advance policy version 1 → 2
    process_advance_policy_version_data(&mut vault_buf, 2).unwrap();
    let vault = VaultRegistry::decode(&vault_buf).unwrap();
    assert_eq!(vault.policy_version, 2);
}

#[test]
fn vault_init_rejects_already_initialized() {
    let mut buf = init_vault_buf();
    let args = InitVaultArgs {
        wallet_pubkey: WALLET,
        authority_hash: AUTH_HASH,
        policy_version: POLICY_VERSION,
        bump: 255,
        policy_mxe_program: MXE_PROGRAM,
    };
    let err = process_init_vault_data(&mut buf, args).unwrap_err();
    assert_eq!(
        err,
        pinocchio::program_error::ProgramError::AccountAlreadyInitialized
    );
}

#[test]
fn vault_policy_version_must_advance_monotonically() {
    let mut vault_buf = init_vault_buf();
    let err = process_advance_policy_version_data(&mut vault_buf, 1).unwrap_err();
    assert!(is_program_error_custom(err, error::POLICY_VERSION_NOT_MONOTONIC));

    let err = process_advance_policy_version_data(&mut vault_buf, 3).unwrap_err();
    assert!(is_program_error_custom(err, error::POLICY_VERSION_NOT_MONOTONIC));
}

#[test]
fn vault_status_invalid_transition_rejected() {
    let mut vault_buf = init_vault_buf();
    process_set_vault_status_data(&mut vault_buf, VaultStatus::Locked as u8).unwrap();
    let err =
        process_set_vault_status_data(&mut vault_buf, VaultStatus::Active as u8).unwrap_err();
    assert!(is_program_error_custom(err, error::VAULT_STATUS_BAD_TRANSITION));
}

// ── 2. Receipt + Session lifecycle ─────────────────────────────────────────

#[test]
fn receipt_session_full_lifecycle() {
    let (_vault_buf, receipt_buf) = init_vault_and_stage_receipt(1);

    let receipt_state = PolicyReceiptState::decode(&receipt_buf).unwrap();
    assert_eq!(receipt_state.action_hash, ACTION_HASH);
    assert_eq!(receipt_state.nonce, 1);
    assert_eq!(receipt_state.consumed, 0);

    // OpenSession from receipt
    let mut session_buf = vec![0u8; ActionSessionState::LEN];
    let receipt = make_receipt(1);
    process_open_session_data(&receipt_buf, &mut session_buf, &receipt, CURRENT_SLOT)
        .expect("open session");

    let session = ActionSessionState::decode(&session_buf).unwrap();
    assert_eq!(session.action_hash, ACTION_HASH);
    assert_eq!(session.policy_version, POLICY_VERSION);
    assert_eq!(session.status, 1); // Pending

    // ActivateSession
    process_activate_session_data(&mut session_buf, ACTION_HASH, CURRENT_SLOT, POLICY_VERSION)
        .expect("activate session");
    let session = ActionSessionState::decode(&session_buf).unwrap();
    assert_eq!(session.status, 2); // Ready

    // ConsumeSession
    process_consume_session_data(&mut session_buf, ACTION_HASH, CURRENT_SLOT, POLICY_VERSION)
        .expect("consume session");
    let session = ActionSessionState::decode(&session_buf).unwrap();
    assert_eq!(session.status, 3); // Consumed
}

#[test]
fn receipt_consume_updates_vault_nonce() {
    let (mut vault_buf, mut receipt_buf) = init_vault_and_stage_receipt(1);
    let receipt = make_receipt(1);

    process_consume_receipt_data(&mut vault_buf, &mut receipt_buf, &receipt)
        .expect("consume receipt");

    let vault = VaultRegistry::decode(&vault_buf).unwrap();
    assert_eq!(vault.last_consumed_receipt_nonce, 1);

    let receipt_state = PolicyReceiptState::decode(&receipt_buf).unwrap();
    assert_eq!(receipt_state.consumed, 1);
}

#[test]
fn receipt_consume_rejects_replay() {
    let (mut vault_buf, mut receipt_buf) = init_vault_and_stage_receipt(1);
    let receipt = make_receipt(1);

    process_consume_receipt_data(&mut vault_buf, &mut receipt_buf, &receipt).unwrap();

    let err =
        process_consume_receipt_data(&mut vault_buf, &mut receipt_buf, &receipt).unwrap_err();
    assert!(is_program_error_custom(err, error::RECEIPT_NONCE_REPLAY));
}

#[test]
fn receipt_stage_rejects_expired() {
    let vault_buf = init_vault_buf();
    let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];
    let receipt = PolicyReceipt {
        action_hash: ACTION_HASH,
        policy_version: POLICY_VERSION,
        threshold: ThresholdRequirement::TwoOfThree,
        nonce: 1,
        expiry_slot: 50, // Already expired at slot 100
    };
    let err = process_stage_receipt_data(&vault_buf, &mut receipt_buf, &receipt, CURRENT_SLOT)
        .unwrap_err();
    assert!(is_program_error_custom(err, error::RECEIPT_EXPIRED));
}

#[test]
fn receipt_nonce_replay_rejected() {
    let (mut vault_buf, mut receipt_buf) = init_vault_and_stage_receipt(1);
    let receipt = make_receipt(1);
    process_consume_receipt_data(&mut vault_buf, &mut receipt_buf, &receipt).unwrap();

    let mut receipt_buf_2 = vec![0u8; PolicyReceiptState::LEN];
    let stale_receipt = PolicyReceipt {
        action_hash: [0x22; 32],
        policy_version: POLICY_VERSION,
        threshold: ThresholdRequirement::TwoOfThree,
        nonce: 0,
        expiry_slot: FUTURE_SLOT,
    };
    let err =
        process_stage_receipt_data(&vault_buf, &mut receipt_buf_2, &stale_receipt, CURRENT_SLOT)
            .unwrap_err();
    assert!(is_program_error_custom(err, error::RECEIPT_NONCE_REPLAY));
}

#[test]
fn finalize_session_full_chain() {
    let mut vault_buf = init_vault_buf();

    let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];
    let receipt = make_receipt(1);
    process_stage_receipt_data(&vault_buf, &mut receipt_buf, &receipt, CURRENT_SLOT).unwrap();

    let mut session_buf = vec![0u8; ActionSessionState::LEN];
    process_open_session_data(&receipt_buf, &mut session_buf, &receipt, CURRENT_SLOT).unwrap();
    process_activate_session_data(&mut session_buf, ACTION_HASH, CURRENT_SLOT, POLICY_VERSION)
        .unwrap();

    process_finalize_session_data(
        &mut vault_buf,
        &mut receipt_buf,
        &mut session_buf,
        &receipt,
        CURRENT_SLOT,
        POLICY_VERSION,
    )
    .unwrap();

    let vault = VaultRegistry::decode(&vault_buf).unwrap();
    assert_eq!(vault.last_consumed_receipt_nonce, 1);

    let receipt_state = PolicyReceiptState::decode(&receipt_buf).unwrap();
    assert_eq!(receipt_state.consumed, 1);

    let session = ActionSessionState::decode(&session_buf).unwrap();
    assert_eq!(session.status, 3); // Consumed
}

// ── 3. Spend orchestration lifecycle ───────────────────────────────────────

#[test]
fn spend_orchestration_full_lifecycle() {
    let mut orch_buf = vec![0u8; SpendOrchestrationState::LEN];
    let args = InitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        session_commitment: [0x22; 32],
        signers_commitment: [0x33; 32],
        signing_package_hash: [0x44; 32],
        expiry_slot: FUTURE_SLOT,
        threshold: 2,
        participant_count: 3,
        bump: 254,
    };
    process_init_spend_orchestration_data(&mut orch_buf, args, CURRENT_SLOT).unwrap();

    let orch = SpendOrchestrationState::decode(&orch_buf).unwrap();
    assert_eq!(orch.action_hash, ACTION_HASH);
    assert_eq!(orch.status, 1); // Pending

    let commit_args = CommitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        signing_package_hash: [0x55; 32],
    };
    process_commit_spend_orchestration_data(&mut orch_buf, commit_args, CURRENT_SLOT).unwrap();
    let orch = SpendOrchestrationState::decode(&orch_buf).unwrap();
    assert_eq!(orch.status, 2); // Committed
    assert_eq!(orch.signing_package_hash, [0x55; 32]);

    let complete_args = CompleteSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        tx_binding: [0x66; 32],
    };
    process_complete_spend_orchestration_data(&mut orch_buf, complete_args, CURRENT_SLOT).unwrap();
    let orch = SpendOrchestrationState::decode(&orch_buf).unwrap();
    assert_eq!(orch.status, 3); // Complete
    assert_eq!(orch.tx_binding, [0x66; 32]);
}

#[test]
fn spend_orchestration_fail_path() {
    let mut orch_buf = vec![0u8; SpendOrchestrationState::LEN];
    let args = InitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        session_commitment: [0x22; 32],
        signers_commitment: [0x33; 32],
        signing_package_hash: [0x44; 32],
        expiry_slot: FUTURE_SLOT,
        threshold: 2,
        participant_count: 3,
        bump: 254,
    };
    process_init_spend_orchestration_data(&mut orch_buf, args, CURRENT_SLOT).unwrap();

    let fail_args = FailSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        reason_code: 1,
    };
    process_fail_spend_orchestration_data(&mut orch_buf, fail_args).unwrap();
    let orch = SpendOrchestrationState::decode(&orch_buf).unwrap();
    assert_eq!(orch.status, 4); // Failed
}

#[test]
fn spend_orchestration_rejects_wrong_action_hash() {
    let mut orch_buf = vec![0u8; SpendOrchestrationState::LEN];
    let args = InitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        session_commitment: [0x22; 32],
        signers_commitment: [0x33; 32],
        signing_package_hash: [0x44; 32],
        expiry_slot: FUTURE_SLOT,
        threshold: 2,
        participant_count: 3,
        bump: 254,
    };
    process_init_spend_orchestration_data(&mut orch_buf, args, CURRENT_SLOT).unwrap();

    let commit_args = CommitSpendOrchestrationArgs {
        action_hash: [0xFF; 32],
        signing_package_hash: [0x55; 32],
    };
    let err =
        process_commit_spend_orchestration_data(&mut orch_buf, commit_args, CURRENT_SLOT)
            .unwrap_err();
    assert!(is_program_error_custom(err, error::ORCHESTRATION_ACTION_MISMATCH));
}

#[test]
fn spend_orchestration_rejects_expired() {
    let mut orch_buf = vec![0u8; SpendOrchestrationState::LEN];
    let args = InitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        session_commitment: [0x22; 32],
        signers_commitment: [0x33; 32],
        signing_package_hash: [0x44; 32],
        expiry_slot: 200,
        threshold: 2,
        participant_count: 3,
        bump: 254,
    };
    process_init_spend_orchestration_data(&mut orch_buf, args, CURRENT_SLOT).unwrap();

    let commit_args = CommitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        signing_package_hash: [0x55; 32],
    };
    let err =
        process_commit_spend_orchestration_data(&mut orch_buf, commit_args, 300).unwrap_err();
    assert!(is_program_error_custom(err, error::ORCHESTRATION_EXPIRED));
}

#[test]
fn spend_orchestration_complete_rejects_zero_tx_binding() {
    let mut orch_buf = vec![0u8; SpendOrchestrationState::LEN];
    let args = InitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        session_commitment: [0x22; 32],
        signers_commitment: [0x33; 32],
        signing_package_hash: [0x44; 32],
        expiry_slot: FUTURE_SLOT,
        threshold: 2,
        participant_count: 3,
        bump: 254,
    };
    process_init_spend_orchestration_data(&mut orch_buf, args, CURRENT_SLOT).unwrap();
    let commit_args = CommitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        signing_package_hash: [0x55; 32],
    };
    process_commit_spend_orchestration_data(&mut orch_buf, commit_args, CURRENT_SLOT).unwrap();

    let complete_args = CompleteSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        tx_binding: [0; 32],
    };
    let err =
        process_complete_spend_orchestration_data(&mut orch_buf, complete_args, CURRENT_SLOT)
            .unwrap_err();
    assert_eq!(
        err,
        pinocchio::program_error::ProgramError::InvalidInstructionData
    );
}

#[test]
fn spend_orchestration_double_complete_rejected() {
    let mut orch_buf = vec![0u8; SpendOrchestrationState::LEN];
    let args = InitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        session_commitment: [0x22; 32],
        signers_commitment: [0x33; 32],
        signing_package_hash: [0x44; 32],
        expiry_slot: FUTURE_SLOT,
        threshold: 2,
        participant_count: 3,
        bump: 254,
    };
    process_init_spend_orchestration_data(&mut orch_buf, args, CURRENT_SLOT).unwrap();

    let commit_args = CommitSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        signing_package_hash: [0x55; 32],
    };
    process_commit_spend_orchestration_data(&mut orch_buf, commit_args, CURRENT_SLOT).unwrap();

    let complete_args = CompleteSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        tx_binding: [0x66; 32],
    };
    process_complete_spend_orchestration_data(&mut orch_buf, complete_args, CURRENT_SLOT).unwrap();

    let complete_args2 = CompleteSpendOrchestrationArgs {
        action_hash: ACTION_HASH,
        tx_binding: [0x77; 32],
    };
    let err =
        process_complete_spend_orchestration_data(&mut orch_buf, complete_args2, CURRENT_SLOT)
            .unwrap_err();
    assert_eq!(
        err,
        pinocchio::program_error::ProgramError::InvalidAccountData
    );
}

// ── 4. Recovery lifecycle ──────────────────────────────────────────────────

#[test]
fn recovery_full_lifecycle() {
    let mut recovery_buf = vec![0u8; RecoveryState::LEN];
    let args = InitRecoveryArgs {
        vault_pubkey: WALLET,
        recovery_commitment: [0x55; 32],
        expiry_slot: FUTURE_SLOT,
        new_threshold: 2,
        new_participant_count: 3,
        bump: 253,
    };
    process_init_recovery_data(
        &mut recovery_buf,
        args,
        VaultStatus::Recovery as u8,
        CURRENT_SLOT,
    )
    .unwrap();

    let state = RecoveryState::decode(&recovery_buf).unwrap();
    assert_eq!(state.vault_pubkey, WALLET);
    assert_eq!(state.status, 1); // Pending

    let complete_args = CompleteRecoveryArgs {
        new_group_key: [0x77; 32],
        new_authority_hash: [0x88; 32],
    };
    process_complete_recovery_data(&mut recovery_buf, complete_args, CURRENT_SLOT).unwrap();

    let state = RecoveryState::decode(&recovery_buf).unwrap();
    assert_eq!(state.status, 2); // Complete
    assert_eq!(state.new_group_key, [0x77; 32]);
    assert_eq!(state.new_authority_hash, [0x88; 32]);
}

#[test]
fn recovery_rejects_non_recovery_vault() {
    let mut recovery_buf = vec![0u8; RecoveryState::LEN];
    let args = InitRecoveryArgs {
        vault_pubkey: WALLET,
        recovery_commitment: [0x55; 32],
        expiry_slot: FUTURE_SLOT,
        new_threshold: 2,
        new_participant_count: 3,
        bump: 253,
    };
    let err = process_init_recovery_data(
        &mut recovery_buf,
        args,
        VaultStatus::Active as u8,
        CURRENT_SLOT,
    )
    .unwrap_err();
    assert_eq!(
        err,
        pinocchio::program_error::ProgramError::InvalidAccountData
    );
}

#[test]
fn recovery_rejects_expired() {
    let mut recovery_buf = vec![0u8; RecoveryState::LEN];
    let args = InitRecoveryArgs {
        vault_pubkey: WALLET,
        recovery_commitment: [0x55; 32],
        expiry_slot: FUTURE_SLOT,
        new_threshold: 2,
        new_participant_count: 3,
        bump: 253,
    };
    process_init_recovery_data(
        &mut recovery_buf,
        args,
        VaultStatus::Recovery as u8,
        CURRENT_SLOT,
    )
    .unwrap();

    let complete_args = CompleteRecoveryArgs {
        new_group_key: [0x77; 32],
        new_authority_hash: [0x88; 32],
    };
    let err = process_complete_recovery_data(&mut recovery_buf, complete_args, FUTURE_SLOT + 1)
        .unwrap_err();
    assert!(is_program_error_custom(err, error::RECOVERY_EXPIRED));
}

#[test]
fn recovery_rejects_invalid_threshold() {
    let mut recovery_buf = vec![0u8; RecoveryState::LEN];
    let args = InitRecoveryArgs {
        vault_pubkey: WALLET,
        recovery_commitment: [0x55; 32],
        expiry_slot: FUTURE_SLOT,
        new_threshold: 5, // > participant_count
        new_participant_count: 3,
        bump: 253,
    };
    let err = process_init_recovery_data(
        &mut recovery_buf,
        args,
        VaultStatus::Recovery as u8,
        CURRENT_SLOT,
    )
    .unwrap_err();
    assert_eq!(
        err,
        pinocchio::program_error::ProgramError::InvalidInstructionData
    );
}

// ── 5. Authority + migrate lifecycle ───────────────────────────────────────

#[test]
fn authority_init_and_migrate() {
    let mut authority_buf = vec![0u8; QuantumAuthorityState::LEN];
    let args = InitAuthorityArgs {
        current_authority_hash: AUTH_HASH,
        current_authority_root: AUTH_ROOT,
        bump: 252,
    };
    process_init_authority_data(&mut authority_buf, args).unwrap();

    let auth = QuantumAuthorityState::decode(&authority_buf).unwrap();
    assert_eq!(auth.current_authority_hash, AUTH_HASH);
    assert_eq!(auth.current_authority_root, AUTH_ROOT);
    assert_eq!(auth.next_sequence, 0);
    assert_eq!(auth.next_leaf_index, 0);

    // Simulate leaf usage so migration is not a no-op
    let mut auth = QuantumAuthorityState::decode(&authority_buf).unwrap();
    auth.next_leaf_index = 1;
    auth.next_sequence = 1;
    auth.encode(&mut authority_buf);

    let new_root = [0xEE; 32];
    process_migrate_authority_data(&mut authority_buf, new_root).unwrap();

    let auth = QuantumAuthorityState::decode(&authority_buf).unwrap();
    assert_eq!(auth.current_authority_root, new_root);
    assert_eq!(auth.next_leaf_index, 0);
}

#[test]
fn authority_migrate_rejects_no_op() {
    let mut authority_buf = vec![0u8; QuantumAuthorityState::LEN];
    let args = InitAuthorityArgs {
        current_authority_hash: AUTH_HASH,
        current_authority_root: AUTH_ROOT,
        bump: 252,
    };
    process_init_authority_data(&mut authority_buf, args).unwrap();

    let err = process_migrate_authority_data(&mut authority_buf, [0xEE; 32]).unwrap_err();
    assert!(is_program_error_custom(err, error::AUTHORITY_MIGRATION_NO_OP));
}

// ── 6. Authority proof lifecycle ───────────────────────────────────────────

#[test]
fn authority_proof_init_and_write_chunks() {
    let statement_digest = [0xA1; 32];
    let proof_commitment = [0xA2; 32];

    let mut proof_buf = vec![0u8; AuthorityProofState::LEN];
    let init_args = InitAuthorityProofArgs {
        statement_digest,
        proof_commitment,
    };
    process_init_authority_proof_data(&mut proof_buf, init_args).unwrap();

    let state = AuthorityProofState::decode(&proof_buf).unwrap();
    assert_eq!(state.statement_digest, statement_digest);
    assert_eq!(state.proof_commitment, proof_commitment);
    assert_eq!(state.bytes_written, 0);
    assert_eq!(state.consumed, 0);

    // Write proof in chunks
    let proof_len = WotsAuthProof::ENCODED_LEN;
    let chunk_size = AUTHORITY_PROOF_CHUNK_MAX_BYTES;
    let mut offset = 0u32;

    while (offset as usize) < proof_len {
        let remaining = proof_len - offset as usize;
        let this_chunk_len = remaining.min(chunk_size);
        let mut chunk = [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
        for i in 0..this_chunk_len {
            chunk[i] = ((offset as usize + i) % 256) as u8;
        }

        let write_args = WriteAuthorityProofChunkArgs {
            offset,
            chunk_len: this_chunk_len as u16,
            chunk,
        };
        process_write_authority_proof_chunk_data(&mut proof_buf, write_args).unwrap();
        offset += this_chunk_len as u32;
    }

    let state = AuthorityProofState::decode(&proof_buf).unwrap();
    assert_eq!(state.bytes_written as usize, proof_len);
}

#[test]
fn authority_proof_rejects_offset_mismatch() {
    let mut proof_buf = vec![0u8; AuthorityProofState::LEN];
    let init_args = InitAuthorityProofArgs {
        statement_digest: [0xA1; 32],
        proof_commitment: [0xA2; 32],
    };
    process_init_authority_proof_data(&mut proof_buf, init_args).unwrap();

    let write_args = WriteAuthorityProofChunkArgs {
        offset: 100, // Mismatch: bytes_written is 0
        chunk_len: 64,
        chunk: [0u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES],
    };
    let err = process_write_authority_proof_chunk_data(&mut proof_buf, write_args).unwrap_err();
    assert!(is_program_error_custom(err, error::PROOF_CHUNK_OFFSET_MISMATCH));
}

// ── 7. Bridged receipt lifecycle ───────────────────────────────────────────

#[test]
fn bridged_receipt_stages_from_finalized_eval() {
    let vault_buf = init_vault_buf();
    let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];
    let receipt = make_receipt(1);

    // Mock PolicyEvaluationState from policy-mxe (must match the layout
    // that validate_bridged_receipt_claim reads):
    //   [0..8]     = discriminator "POLEVAL1"
    //   [72..104]  = action_hash
    //   [168..200] = receipt_commitment
    //   [240]      = status (2 = Finalized)
    let receipt_commitment = receipt.commitment();
    let mut eval_buf = vec![0u8; 256];
    eval_buf[0..8].copy_from_slice(b"POLEVAL1");
    eval_buf[72..104].copy_from_slice(&receipt.action_hash);
    eval_buf[168..200].copy_from_slice(&receipt_commitment);
    eval_buf[240] = 2; // Finalized

    process_stage_bridged_receipt_data(
        &vault_buf,
        &mut receipt_buf,
        &eval_buf,
        &receipt,
        CURRENT_SLOT,
    )
    .unwrap();

    let receipt_state = PolicyReceiptState::decode(&receipt_buf).unwrap();
    assert_eq!(receipt_state.action_hash, ACTION_HASH);
    assert_eq!(receipt_state.consumed, 0);
}

// ── 8. Cross-flow: policy version mismatch ─────────────────────────────────

#[test]
fn receipt_rejects_policy_version_mismatch() {
    let vault_buf = init_vault_buf();
    let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];
    let receipt = PolicyReceipt {
        action_hash: ACTION_HASH,
        policy_version: 99,
        threshold: ThresholdRequirement::TwoOfThree,
        nonce: 1,
        expiry_slot: FUTURE_SLOT,
    };
    let err = process_stage_receipt_data(&vault_buf, &mut receipt_buf, &receipt, CURRENT_SLOT)
        .unwrap_err();
    assert!(is_program_error_custom(err, error::VAULT_POLICY_MISMATCH));
}

// ── 9. Session rejects wrong action hash ───────────────────────────────────

#[test]
fn session_activate_rejects_wrong_action_hash() {
    let (_, receipt_buf) = init_vault_and_stage_receipt(1);
    let receipt = make_receipt(1);

    let mut session_buf = vec![0u8; ActionSessionState::LEN];
    process_open_session_data(&receipt_buf, &mut session_buf, &receipt, CURRENT_SLOT).unwrap();

    let wrong_hash = [0xFF; 32];
    let err =
        process_activate_session_data(&mut session_buf, wrong_hash, CURRENT_SLOT, POLICY_VERSION)
            .unwrap_err();
    assert!(is_program_error_custom(err, error::SESSION_MISMATCH));
}

// ── 10. Multiple receipts sequential processing ────────────────────────────

#[test]
fn multiple_receipts_sequential_nonces() {
    let mut vault_buf = init_vault_buf();

    for nonce in 1..=5u64 {
        let mut receipt_buf = vec![0u8; PolicyReceiptState::LEN];
        let receipt = PolicyReceipt {
            action_hash: [nonce as u8; 32],
            policy_version: POLICY_VERSION,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce,
            expiry_slot: FUTURE_SLOT,
        };
        process_stage_receipt_data(&vault_buf, &mut receipt_buf, &receipt, CURRENT_SLOT).unwrap();
        process_consume_receipt_data(&mut vault_buf, &mut receipt_buf, &receipt).unwrap();

        let vault = VaultRegistry::decode(&vault_buf).unwrap();
        assert_eq!(vault.last_consumed_receipt_nonce, nonce);
    }
}
