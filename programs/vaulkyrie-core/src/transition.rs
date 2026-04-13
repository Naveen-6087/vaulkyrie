use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt};

use crate::state::{
    ActionSessionState, PolicyReceiptState, QuantumAuthorityState, SessionStatus, VaultRegistry,
    VaultStatus,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    ReceiptAlreadyConsumed,
    ReceiptMismatch,
    VaultAuthorityMismatch,
    VaultPolicyMismatch,
    VaultNotActive,
    SessionMismatch,
    SessionNotPending,
    SessionNotReady,
    AuthorityNoOp,
    AuthoritySequenceMismatch,
}

pub fn initialize_vault(
    wallet_pubkey: [u8; 32],
    authority_hash: [u8; 32],
    policy_version: u64,
    bump: u8,
) -> VaultRegistry {
    VaultRegistry::new(
        wallet_pubkey,
        authority_hash,
        policy_version,
        VaultStatus::Active,
        bump,
    )
}

pub fn initialize_quantum_authority(
    current_authority_hash: [u8; 32],
    bump: u8,
) -> QuantumAuthorityState {
    QuantumAuthorityState::new(current_authority_hash, bump)
}

pub fn validate_vault_for_receipt(
    vault: &VaultRegistry,
    receipt: &PolicyReceipt,
) -> Result<(), TransitionError> {
    if vault.policy_version != receipt.policy_version {
        return Err(TransitionError::VaultPolicyMismatch);
    }

    if vault.status != VaultStatus::Active as u8 {
        return Err(TransitionError::VaultNotActive);
    }

    Ok(())
}

pub fn validate_vault_authority_alignment(
    vault: &VaultRegistry,
    authority: &QuantumAuthorityState,
) -> Result<(), TransitionError> {
    if vault.current_authority_hash != authority.current_authority_hash {
        return Err(TransitionError::VaultAuthorityMismatch);
    }

    Ok(())
}

pub fn stage_policy_receipt(receipt: &PolicyReceipt) -> PolicyReceiptState {
    PolicyReceiptState::new(
        receipt.commitment(),
        receipt.action_hash,
        receipt.nonce,
        receipt.expiry_slot,
    )
}

pub fn open_action_session(receipt: &PolicyReceipt) -> ActionSessionState {
    ActionSessionState::new(
        receipt.commitment(),
        receipt.action_hash,
        receipt.expiry_slot,
        receipt.threshold.as_byte(),
    )
}

pub fn open_action_session_from_receipt(
    state: &PolicyReceiptState,
    receipt: &PolicyReceipt,
) -> Result<ActionSessionState, TransitionError> {
    if state.consumed != 0 {
        return Err(TransitionError::ReceiptAlreadyConsumed);
    }

    if state.receipt_commitment != receipt.commitment()
        || state.action_hash != receipt.action_hash
        || state.nonce != receipt.nonce
        || state.expiry_slot != receipt.expiry_slot
    {
        return Err(TransitionError::ReceiptMismatch);
    }

    Ok(open_action_session(receipt))
}

pub fn consume_policy_receipt(
    state: &mut PolicyReceiptState,
    receipt: &PolicyReceipt,
) -> Result<(), TransitionError> {
    if state.consumed != 0 {
        return Err(TransitionError::ReceiptAlreadyConsumed);
    }

    if state.receipt_commitment != receipt.commitment() || state.action_hash != receipt.action_hash {
        return Err(TransitionError::ReceiptMismatch);
    }

    state.consumed = 1;
    Ok(())
}

pub fn mark_action_session_ready(
    state: &mut ActionSessionState,
    action_hash: [u8; 32],
) -> Result<(), TransitionError> {
    if state.action_hash != action_hash {
        return Err(TransitionError::SessionMismatch);
    }

    if state.status != SessionStatus::Pending as u8 {
        return Err(TransitionError::SessionNotPending);
    }

    state.status = SessionStatus::Ready as u8;
    Ok(())
}

pub fn consume_action_session(
    state: &mut ActionSessionState,
    action_hash: [u8; 32],
) -> Result<(), TransitionError> {
    if state.action_hash != action_hash {
        return Err(TransitionError::SessionMismatch);
    }

    if state.status != SessionStatus::Ready as u8 {
        return Err(TransitionError::SessionNotReady);
    }

    state.status = SessionStatus::Consumed as u8;
    Ok(())
}

pub fn finalize_action_session(
    session: &mut ActionSessionState,
    receipt_state: &mut PolicyReceiptState,
    receipt: &PolicyReceipt,
) -> Result<(), TransitionError> {
    if session.action_hash != receipt.action_hash
        || session.receipt_commitment != receipt.commitment()
    {
        return Err(TransitionError::SessionMismatch);
    }

    if session.status != SessionStatus::Ready as u8 {
        return Err(TransitionError::SessionNotReady);
    }

    consume_policy_receipt(receipt_state, receipt)?;
    session.status = SessionStatus::Consumed as u8;

    Ok(())
}

pub fn apply_authority_rotation(
    state: &mut QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
) -> Result<(), TransitionError> {
    if state.current_authority_hash == statement.next_authority_hash {
        return Err(TransitionError::AuthorityNoOp);
    }

    if state.next_sequence != statement.sequence {
        return Err(TransitionError::AuthoritySequenceMismatch);
    }

    state.last_consumed_digest = statement.digest();
    state.current_authority_hash = statement.next_authority_hash;
    state.next_sequence += 1;

    Ok(())
}

pub fn rotate_vault_authority(
    vault: &mut VaultRegistry,
    authority: &mut QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
) -> Result<(), TransitionError> {
    validate_vault_authority_alignment(vault, authority)?;
    apply_authority_rotation(authority, statement)?;
    vault.current_authority_hash = authority.current_authority_hash;

    Ok(())
}

#[cfg(test)]
mod tests {
    use vaulkyrie_protocol::{ActionDescriptor, ActionKind, ThresholdRequirement};

    use super::{
        apply_authority_rotation, consume_action_session, consume_policy_receipt,
        finalize_action_session, initialize_quantum_authority, initialize_vault,
        mark_action_session_ready, rotate_vault_authority, validate_vault_authority_alignment,
        validate_vault_for_receipt,
        open_action_session, open_action_session_from_receipt, stage_policy_receipt,
        TransitionError,
    };
    use crate::state::{QuantumAuthorityState, SessionStatus, VaultStatus};

    fn sample_action_hash() -> [u8; 32] {
        ActionDescriptor {
            vault_id: [7; 32],
            payload_hash: [8; 32],
            policy_version: 9,
            kind: ActionKind::Spend,
        }
        .hash()
    }

    #[test]
    fn initialize_vault_sets_active_status() {
        let vault = initialize_vault([1; 32], [2; 32], 3, 4);

        assert_eq!(vault.wallet_pubkey, [1; 32]);
        assert_eq!(vault.current_authority_hash, [2; 32]);
        assert_eq!(vault.policy_version, 3);
        assert_eq!(vault.status, 1);
    }

    #[test]
    fn initialize_quantum_authority_sets_sequence_zero() {
        let state = initialize_quantum_authority([8; 32], 6);

        assert_eq!(state.current_authority_hash, [8; 32]);
        assert_eq!(state.bump, 6);
        assert_eq!(state.next_sequence, 0);
    }

    #[test]
    fn validate_vault_for_receipt_accepts_matching_active_policy() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };

        validate_vault_for_receipt(&vault, &receipt)
            .expect("active vault with matching policy should pass");
    }

    #[test]
    fn validate_vault_for_receipt_rejects_policy_mismatch() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 10,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };

        let error = validate_vault_for_receipt(&vault, &receipt)
            .expect_err("mismatched policy version should fail");

        assert_eq!(error, TransitionError::VaultPolicyMismatch);
    }

    #[test]
    fn validate_vault_for_receipt_rejects_non_active_vault() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.status = VaultStatus::Locked as u8;
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };

        let error = validate_vault_for_receipt(&vault, &receipt)
            .expect_err("locked vault should not stage receipts");

        assert_eq!(error, TransitionError::VaultNotActive);
    }

    #[test]
    fn validate_vault_authority_alignment_accepts_matching_hashes() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let authority = initialize_quantum_authority([2; 32], 1);

        validate_vault_authority_alignment(&vault, &authority)
            .expect("matching authority hashes should pass");
    }

    #[test]
    fn validate_vault_authority_alignment_rejects_mismatch() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let authority = initialize_quantum_authority([3; 32], 1);

        let error = validate_vault_authority_alignment(&vault, &authority)
            .expect_err("mismatched authority hashes should fail");

        assert_eq!(error, TransitionError::VaultAuthorityMismatch);
    }

    #[test]
    fn consuming_matching_receipt_marks_state_consumed() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut state = stage_policy_receipt(&receipt);

        consume_policy_receipt(&mut state, &receipt).expect("receipt should match");

        assert_eq!(state.consumed, 1);
    }

    #[test]
    fn consuming_receipt_twice_fails() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut state = stage_policy_receipt(&receipt);

        consume_policy_receipt(&mut state, &receipt).expect("first consume should succeed");
        let error =
            consume_policy_receipt(&mut state, &receipt).expect_err("second consume should fail");

        assert_eq!(error, TransitionError::ReceiptAlreadyConsumed);
    }

    #[test]
    fn opening_action_session_copies_receipt_constraints() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };

        let session = open_action_session(&receipt);

        assert_eq!(session.receipt_commitment, receipt.commitment());
        assert_eq!(session.action_hash, receipt.action_hash);
        assert_eq!(session.expiry_slot, receipt.expiry_slot);
        assert_eq!(
            session.threshold,
            ThresholdRequirement::TwoOfThree.as_byte()
        );
        assert_eq!(session.status, SessionStatus::Pending as u8);
    }

    #[test]
    fn opening_action_session_from_staged_receipt_validates_commitment() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let staged = stage_policy_receipt(&receipt);

        let session = open_action_session_from_receipt(&staged, &receipt)
            .expect("matching receipt should open a session");

        assert_eq!(session.receipt_commitment, receipt.commitment());
        assert_eq!(session.action_hash, receipt.action_hash);
    }

    #[test]
    fn opening_action_session_from_consumed_receipt_fails() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut staged = stage_policy_receipt(&receipt);
        staged.consumed = 1;

        let error = open_action_session_from_receipt(&staged, &receipt)
            .expect_err("consumed receipts should not open new sessions");

        assert_eq!(error, TransitionError::ReceiptAlreadyConsumed);
    }

    #[test]
    fn opening_action_session_from_mismatched_receipt_fails() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let staged = stage_policy_receipt(&receipt);
        let mismatched = vaulkyrie_protocol::PolicyReceipt {
            nonce: 99,
            ..receipt
        };

        let error = open_action_session_from_receipt(&staged, &mismatched)
            .expect_err("mismatched receipt should be rejected");

        assert_eq!(error, TransitionError::ReceiptMismatch);
    }

    #[test]
    fn marking_action_session_ready_updates_status() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);

        mark_action_session_ready(&mut session, receipt.action_hash)
            .expect("matching action hash should mark session ready");

        assert_eq!(session.status, SessionStatus::Ready as u8);
    }

    #[test]
    fn marking_action_session_ready_rejects_action_mismatch() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);

        let error = mark_action_session_ready(&mut session, [99; 32])
            .expect_err("wrong action hash should be rejected");

        assert_eq!(error, TransitionError::SessionMismatch);
    }

    #[test]
    fn marking_action_session_ready_rejects_non_pending_session() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);
        session.status = SessionStatus::Ready as u8;

        let error = mark_action_session_ready(&mut session, receipt.action_hash)
            .expect_err("ready session should not transition twice");

        assert_eq!(error, TransitionError::SessionNotPending);
    }

    #[test]
    fn consuming_ready_action_session_updates_status() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);
        mark_action_session_ready(&mut session, receipt.action_hash)
            .expect("matching action hash should mark session ready");

        consume_action_session(&mut session, receipt.action_hash)
            .expect("ready session should be consumable");

        assert_eq!(session.status, SessionStatus::Consumed as u8);
    }

    #[test]
    fn consuming_pending_action_session_rejects_transition() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);

        let error = consume_action_session(&mut session, receipt.action_hash)
            .expect_err("pending session should not be consumable");

        assert_eq!(error, TransitionError::SessionNotReady);
    }

    #[test]
    fn finalizing_action_session_consumes_session_and_receipt() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        mark_action_session_ready(&mut session, receipt.action_hash)
            .expect("matching action hash should mark session ready");

        finalize_action_session(&mut session, &mut staged, &receipt)
            .expect("ready session should finalize against staged receipt");

        assert_eq!(session.status, SessionStatus::Consumed as u8);
        assert_eq!(staged.consumed, 1);
    }

    #[test]
    fn finalizing_action_session_rejects_mismatched_receipt() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        let mismatched = vaulkyrie_protocol::PolicyReceipt {
            nonce: 77,
            ..receipt
        };
        mark_action_session_ready(&mut session, receipt.action_hash)
            .expect("matching action hash should mark session ready");

        let error = finalize_action_session(&mut session, &mut staged, &mismatched)
            .expect_err("mismatched receipt should be rejected");

        assert_eq!(error, TransitionError::SessionMismatch);
    }

    #[test]
    fn authority_rotation_advances_sequence() {
        let mut state = QuantumAuthorityState::new([3; 32], 1);
        let statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [4; 32],
            sequence: 0,
            expiry_slot: 100,
        };

        apply_authority_rotation(&mut state, &statement).expect("sequence should match");

        assert_eq!(state.current_authority_hash, [4; 32]);
        assert_eq!(state.next_sequence, 1);
        assert_eq!(state.last_consumed_digest, statement.digest());
    }

    #[test]
    fn authority_rotation_rejects_stale_sequence() {
        let mut state = QuantumAuthorityState::new([3; 32], 1);
        state.next_sequence = 2;
        let statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [4; 32],
            sequence: 1,
            expiry_slot: 100,
        };

        let error = apply_authority_rotation(&mut state, &statement)
            .expect_err("stale sequence should be rejected");

        assert_eq!(error, TransitionError::AuthoritySequenceMismatch);
    }

    #[test]
    fn authority_rotation_rejects_no_op_hash() {
        let mut state = QuantumAuthorityState::new([3; 32], 1);
        let statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [3; 32],
            sequence: 0,
            expiry_slot: 100,
        };

        let error = apply_authority_rotation(&mut state, &statement)
            .expect_err("reusing the same authority hash should fail");

        assert_eq!(error, TransitionError::AuthorityNoOp);
    }

    #[test]
    fn rotate_vault_authority_updates_both_states() {
        let mut vault = initialize_vault([1; 32], [3; 32], 9, 4);
        let mut authority = initialize_quantum_authority([3; 32], 1);
        let statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [4; 32],
            sequence: 0,
            expiry_slot: 100,
        };

        rotate_vault_authority(&mut vault, &mut authority, &statement)
            .expect("aligned authority should rotate");

        assert_eq!(vault.current_authority_hash, [4; 32]);
        assert_eq!(authority.current_authority_hash, [4; 32]);
        assert_eq!(authority.next_sequence, 1);
    }
}
