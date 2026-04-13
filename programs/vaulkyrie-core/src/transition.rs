use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt};

use crate::state::{
    ActionSessionState, PolicyReceiptState, QuantumAuthorityState, SessionStatus, VaultRegistry,
    VaultStatus,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    ReceiptAlreadyConsumed,
    ReceiptMismatch,
    SessionMismatch,
    SessionNotPending,
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

pub fn apply_authority_rotation(
    state: &mut QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
) -> Result<(), TransitionError> {
    if state.next_sequence != statement.sequence {
        return Err(TransitionError::AuthoritySequenceMismatch);
    }

    state.last_consumed_digest = statement.digest();
    state.current_authority_hash = statement.next_authority_hash;
    state.next_sequence += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use vaulkyrie_protocol::{ActionDescriptor, ActionKind, ThresholdRequirement};

    use super::{
        apply_authority_rotation, consume_policy_receipt, initialize_vault,
        mark_action_session_ready, open_action_session, stage_policy_receipt, TransitionError,
    };
    use crate::state::{QuantumAuthorityState, SessionStatus};

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
}
