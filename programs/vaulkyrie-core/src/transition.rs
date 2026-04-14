use solana_nostd_sha256::hashv;
use solana_winternitz::signature::WinternitzSignature;
use vaulkyrie_protocol::{
    quantum_close_message, quantum_split_message, AuthorityRotationStatement, PolicyReceipt,
    ThresholdRequirement, WotsAuthProof, XMSS_LEAF_COUNT,
};

use crate::state::{
    ActionSessionState, OrchestrationStatus, PolicyReceiptState, QuantumAuthorityState,
    SessionStatus, SpendOrchestrationState, VaultRegistry, VaultStatus,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    ReceiptAlreadyConsumed,
    ReceiptMismatch,
    ReceiptExpired,
    ReceiptNonceReplay,
    SessionExpired,
    AuthorityStatementExpired,
    VaultAuthorityMismatch,
    VaultPolicyMismatch,
    VaultNotActive,
    VaultNotRecovery,
    VaultStatusInvalid,
    VaultStatusTransitionNotAllowed,
    SessionPolicyMismatch,
    SessionMismatch,
    SessionNotPending,
    SessionNotReady,
    SessionRequiresPqc,
    AuthorityNoOp,
    AuthoritySequenceMismatch,
    AuthorityLeafIndexMismatch,
    AuthorityActionMismatch,
    AuthorityProofInvalid,
    AuthorityProofMismatch,
    AuthorityMerkleRootMismatch,
    AuthorityTreeExhausted,
    QuantumVaultAmountTooLarge,
    QuantumVaultSignatureInvalid,
    QuantumVaultPdaMismatch,
    OrchestrationExpired,
    OrchestrationInvalidParams,
    OrchestrationActionMismatch,
    OrchestrationNotPending,
    OrchestrationNotCommitted,
    OrchestrationAlreadyComplete,
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
    current_authority_root: [u8; 32],
    bump: u8,
) -> QuantumAuthorityState {
    QuantumAuthorityState::new(current_authority_hash, current_authority_root, bump)
}

pub fn parse_vault_status(status: u8) -> Result<VaultStatus, TransitionError> {
    match status {
        value if value == VaultStatus::Active as u8 => Ok(VaultStatus::Active),
        value if value == VaultStatus::Recovery as u8 => Ok(VaultStatus::Recovery),
        value if value == VaultStatus::Locked as u8 => Ok(VaultStatus::Locked),
        _ => Err(TransitionError::VaultStatusInvalid),
    }
}

pub fn update_vault_status(
    vault: &mut VaultRegistry,
    next_status: VaultStatus,
) -> Result<(), TransitionError> {
    let current = parse_vault_status(vault.status)?;

    let is_allowed = matches!(
        (current, next_status),
        (VaultStatus::Active, VaultStatus::Recovery)
            | (VaultStatus::Active, VaultStatus::Locked)
            | (VaultStatus::Recovery, VaultStatus::Active)
            | (VaultStatus::Recovery, VaultStatus::Locked)
            | (VaultStatus::Locked, VaultStatus::Recovery)
    ) || current == next_status;

    if !is_allowed {
        return Err(TransitionError::VaultStatusTransitionNotAllowed);
    }

    vault.status = next_status as u8;
    Ok(())
}

pub fn validate_vault_for_receipt(
    vault: &VaultRegistry,
    receipt: &PolicyReceipt,
    current_slot: u64,
) -> Result<(), TransitionError> {
    validate_vault_active(vault)?;

    if vault.policy_version != receipt.policy_version {
        return Err(TransitionError::VaultPolicyMismatch);
    }

    if receipt.expiry_slot < current_slot {
        return Err(TransitionError::ReceiptExpired);
    }
    if receipt.nonce <= vault.last_consumed_receipt_nonce {
        return Err(TransitionError::ReceiptNonceReplay);
    }

    Ok(())
}

pub fn validate_vault_active(vault: &VaultRegistry) -> Result<(), TransitionError> {
    if vault.status != VaultStatus::Active as u8 {
        return Err(TransitionError::VaultNotActive);
    }

    Ok(())
}

pub fn validate_vault_recovery_mode(vault: &VaultRegistry) -> Result<(), TransitionError> {
    if vault.status == VaultStatus::Recovery as u8 || vault.status == VaultStatus::Locked as u8 {
        Ok(())
    } else {
        Err(TransitionError::VaultNotRecovery)
    }
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
        receipt.policy_version,
        receipt.expiry_slot,
        receipt.threshold.as_byte(),
    )
}

pub fn open_action_session_from_receipt(
    state: &PolicyReceiptState,
    receipt: &PolicyReceipt,
    current_slot: u64,
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

    if state.expiry_slot < current_slot {
        return Err(TransitionError::ReceiptExpired);
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

    if state.receipt_commitment != receipt.commitment() || state.action_hash != receipt.action_hash
    {
        return Err(TransitionError::ReceiptMismatch);
    }

    state.consumed = 1;
    Ok(())
}

pub fn validate_and_advance_receipt_nonce(
    vault: &mut VaultRegistry,
    receipt: &PolicyReceipt,
) -> Result<(), TransitionError> {
    if receipt.nonce <= vault.last_consumed_receipt_nonce {
        return Err(TransitionError::ReceiptNonceReplay);
    }

    vault.last_consumed_receipt_nonce = receipt.nonce;
    Ok(())
}

pub fn consume_policy_receipt_for_vault(
    vault: &mut VaultRegistry,
    state: &mut PolicyReceiptState,
    receipt: &PolicyReceipt,
) -> Result<(), TransitionError> {
    validate_and_advance_receipt_nonce(vault, receipt)?;
    consume_policy_receipt(state, receipt)
}

pub fn mark_action_session_ready(
    state: &mut ActionSessionState,
    action_hash: [u8; 32],
    current_slot: u64,
) -> Result<(), TransitionError> {
    validate_spend_threshold(state.threshold)?;

    if state.action_hash != action_hash {
        return Err(TransitionError::SessionMismatch);
    }

    if state.expiry_slot < current_slot {
        return Err(TransitionError::SessionExpired);
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
    current_slot: u64,
) -> Result<(), TransitionError> {
    validate_spend_threshold(state.threshold)?;

    if state.action_hash != action_hash {
        return Err(TransitionError::SessionMismatch);
    }

    if state.expiry_slot < current_slot {
        return Err(TransitionError::SessionExpired);
    }

    if state.status != SessionStatus::Ready as u8 {
        return Err(TransitionError::SessionNotReady);
    }

    state.status = SessionStatus::Consumed as u8;
    Ok(())
}

pub fn finalize_action_session(
    vault: &mut VaultRegistry,
    session: &mut ActionSessionState,
    receipt_state: &mut PolicyReceiptState,
    receipt: &PolicyReceipt,
    current_slot: u64,
) -> Result<(), TransitionError> {
    validate_spend_threshold(session.threshold)?;

    if session.action_hash != receipt.action_hash
        || session.receipt_commitment != receipt.commitment()
    {
        return Err(TransitionError::SessionMismatch);
    }

    if session.expiry_slot < current_slot || receipt_state.expiry_slot < current_slot {
        return Err(TransitionError::SessionExpired);
    }

    if session.policy_version != receipt.policy_version {
        return Err(TransitionError::SessionPolicyMismatch);
    }

    if session.status != SessionStatus::Ready as u8 {
        return Err(TransitionError::SessionNotReady);
    }

    consume_policy_receipt_for_vault(vault, receipt_state, receipt)?;
    session.status = SessionStatus::Consumed as u8;

    Ok(())
}

pub fn apply_authority_rotation(
    state: &mut QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
    current_slot: u64,
) -> Result<(), TransitionError> {
    if state.current_authority_hash == statement.next_authority_hash {
        return Err(TransitionError::AuthorityNoOp);
    }

    if statement.expiry_slot < current_slot {
        return Err(TransitionError::AuthorityStatementExpired);
    }

    if state.next_sequence != statement.sequence {
        return Err(TransitionError::AuthoritySequenceMismatch);
    }
    if state.next_leaf_index >= XMSS_LEAF_COUNT {
        return Err(TransitionError::AuthorityTreeExhausted);
    }

    state.last_consumed_digest = statement.digest();
    state.current_authority_hash = statement.next_authority_hash;
    state.next_sequence += 1;
    state.next_leaf_index += 1;

    Ok(())
}

pub fn rotate_vault_authority(
    vault: &mut VaultRegistry,
    authority: &mut QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
    proof: &WotsAuthProof,
    current_slot: u64,
) -> Result<(), TransitionError> {
    validate_vault_recovery_mode(vault)?;
    validate_authority_action_binding(vault, statement)?;
    validate_vault_authority_alignment(vault, authority)?;
    verify_authority_proof(authority, statement, proof)?;
    apply_authority_rotation(authority, statement, current_slot)?;
    vault.current_authority_hash = authority.current_authority_hash;

    Ok(())
}

pub fn validate_authority_action_binding(
    vault: &VaultRegistry,
    statement: &AuthorityRotationStatement,
) -> Result<(), TransitionError> {
    if statement.is_action_bound(vault.wallet_pubkey, vault.policy_version) {
        Ok(())
    } else {
        Err(TransitionError::AuthorityActionMismatch)
    }
}

pub fn verify_authority_proof(
    authority: &QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
    proof: &WotsAuthProof,
) -> Result<(), TransitionError> {
    if authority.next_leaf_index >= XMSS_LEAF_COUNT {
        return Err(TransitionError::AuthorityTreeExhausted);
    }
    if proof.authority_hash() != authority.current_authority_hash {
        return Err(TransitionError::AuthorityProofMismatch);
    }
    if proof.leaf_index != authority.next_leaf_index {
        return Err(TransitionError::AuthorityLeafIndexMismatch);
    }
    if !proof.verify_merkle_root(authority.current_authority_root) {
        return Err(TransitionError::AuthorityMerkleRootMismatch);
    }
    if !proof.verify_statement(statement) {
        return Err(TransitionError::AuthorityProofInvalid);
    }

    Ok(())
}

pub fn validate_quantum_vault_split(
    signature: &WinternitzSignature,
    amount: u64,
    split_pubkey: [u8; 32],
    refund_pubkey: [u8; 32],
    bump: u8,
    vault_pubkey: [u8; 32],
    program_id: [u8; 32],
) -> Result<(), TransitionError> {
    let hash = signature
        .recover_pubkey(&quantum_split_message(amount, split_pubkey, refund_pubkey))
        .merklize();
    validate_quantum_vault_pda(hash, bump, vault_pubkey, program_id)
}

pub fn validate_quantum_vault_close(
    signature: &WinternitzSignature,
    refund_pubkey: [u8; 32],
    bump: u8,
    vault_pubkey: [u8; 32],
    program_id: [u8; 32],
) -> Result<(), TransitionError> {
    let hash = signature
        .recover_pubkey(&quantum_close_message(refund_pubkey))
        .merklize();
    validate_quantum_vault_pda(hash, bump, vault_pubkey, program_id)
}

pub fn validate_quantum_vault_split_amount(
    vault_lamports: u64,
    split_amount: u64,
) -> Result<(), TransitionError> {
    if split_amount > vault_lamports {
        return Err(TransitionError::QuantumVaultAmountTooLarge);
    }

    Ok(())
}

fn validate_quantum_vault_pda(
    hash: [u8; 32],
    bump: u8,
    vault_pubkey: [u8; 32],
    program_id: [u8; 32],
) -> Result<(), TransitionError> {
    let bump_seed = [bump];
    let derived = hashv(&[
        hash.as_ref(),
        bump_seed.as_ref(),
        program_id.as_ref(),
        b"ProgramDerivedAddress",
    ]);

    if derived == vault_pubkey {
        Ok(())
    } else {
        Err(TransitionError::QuantumVaultPdaMismatch)
    }
}

pub fn validate_vault_for_session(
    vault: &VaultRegistry,
    session: &ActionSessionState,
) -> Result<(), TransitionError> {
    validate_vault_active(vault)?;

    if vault.policy_version != session.policy_version {
        return Err(TransitionError::SessionPolicyMismatch);
    }

    Ok(())
}

fn validate_spend_threshold(threshold: u8) -> Result<(), TransitionError> {
    if threshold == ThresholdRequirement::RequirePqcAuth.as_byte() {
        return Err(TransitionError::SessionRequiresPqc);
    }

    Ok(())
}

/// Initialize a new spend orchestration account in `Pending` status.
pub fn init_spend_orchestration(
    action_hash: [u8; 32],
    session_commitment: [u8; 32],
    signers_commitment: [u8; 32],
    signing_package_hash: [u8; 32],
    expiry_slot: u64,
    threshold: u8,
    participant_count: u8,
    bump: u8,
    current_slot: u64,
) -> Result<SpendOrchestrationState, TransitionError> {
    if expiry_slot <= current_slot {
        return Err(TransitionError::OrchestrationExpired);
    }
    if threshold == 0 || participant_count == 0 || threshold > participant_count {
        return Err(TransitionError::OrchestrationInvalidParams);
    }

    let mut state = SpendOrchestrationState::new(
        action_hash,
        session_commitment,
        signers_commitment,
        expiry_slot,
        threshold,
        participant_count,
        bump,
    );
    state.signing_package_hash = signing_package_hash;
    Ok(state)
}

/// Record the signing package hash and advance status to `Committed`.
pub fn commit_spend_orchestration(
    state: &mut SpendOrchestrationState,
    action_hash: [u8; 32],
    signing_package_hash: [u8; 32],
    current_slot: u64,
) -> Result<(), TransitionError> {
    if state.expiry_slot <= current_slot {
        return Err(TransitionError::OrchestrationExpired);
    }
    if state.status != OrchestrationStatus::Pending as u8 {
        return Err(TransitionError::OrchestrationNotPending);
    }
    if state.action_hash != action_hash {
        return Err(TransitionError::OrchestrationActionMismatch);
    }

    state.signing_package_hash = signing_package_hash;
    state.status = OrchestrationStatus::Committed as u8;
    Ok(())
}

/// Mark the orchestration as `Complete` once the signature has been broadcast on-chain.
pub fn complete_spend_orchestration(
    state: &mut SpendOrchestrationState,
    action_hash: [u8; 32],
    current_slot: u64,
) -> Result<(), TransitionError> {
    if state.expiry_slot <= current_slot {
        return Err(TransitionError::OrchestrationExpired);
    }
    if state.status != OrchestrationStatus::Committed as u8 {
        return Err(TransitionError::OrchestrationNotCommitted);
    }
    if state.action_hash != action_hash {
        return Err(TransitionError::OrchestrationActionMismatch);
    }

    state.status = OrchestrationStatus::Complete as u8;
    Ok(())
}

/// Mark the orchestration as `Failed` with an optional reason code.
pub fn fail_spend_orchestration(
    state: &mut SpendOrchestrationState,
    action_hash: [u8; 32],
) -> Result<(), TransitionError> {
    if state.status == OrchestrationStatus::Complete as u8 {
        return Err(TransitionError::OrchestrationAlreadyComplete);
    }
    if state.action_hash != action_hash {
        return Err(TransitionError::OrchestrationActionMismatch);
    }

    state.status = OrchestrationStatus::Failed as u8;
    Ok(())
}

#[cfg(test)]
mod tests {
    use solana_nostd_sha256::hashv;
    use solana_winternitz::privkey::WinternitzPrivkey;
    use vaulkyrie_protocol::{
        ActionDescriptor, ActionKind, AuthorityRotationStatement, ThresholdRequirement,
        WotsSecretKey, WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES, XMSS_LEAF_COUNT,
    };

    use super::{
        apply_authority_rotation, consume_action_session, consume_policy_receipt,
        finalize_action_session, initialize_quantum_authority, initialize_vault,
        mark_action_session_ready, open_action_session, open_action_session_from_receipt,
        parse_vault_status, rotate_vault_authority, stage_policy_receipt, update_vault_status,
        validate_and_advance_receipt_nonce, validate_authority_action_binding,
        validate_quantum_vault_close, validate_quantum_vault_split,
        validate_quantum_vault_split_amount, validate_vault_active,
        validate_vault_authority_alignment, validate_vault_for_receipt, validate_vault_for_session,
        validate_vault_recovery_mode, verify_authority_proof, TransitionError,
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

    fn sample_rotation_statement(
        vault_wallet: [u8; 32],
        policy_version: u64,
        next_authority_hash: [u8; 32],
        sequence: u64,
        expiry_slot: u64,
    ) -> AuthorityRotationStatement {
        let mut statement = AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash,
            sequence,
            expiry_slot,
        };
        statement.action_hash = statement.expected_action_hash(vault_wallet, policy_version);
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
        let state = initialize_quantum_authority([8; 32], [9; 32], 6);

        assert_eq!(state.current_authority_hash, [8; 32]);
        assert_eq!(state.current_authority_root, [9; 32]);
        assert_eq!(state.bump, 6);
        assert_eq!(state.next_sequence, 0);
        assert_eq!(state.next_leaf_index, 0);
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

        validate_vault_for_receipt(&vault, &receipt, 10)
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

        let error = validate_vault_for_receipt(&vault, &receipt, 10)
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

        let error = validate_vault_for_receipt(&vault, &receipt, 10)
            .expect_err("locked vault should not stage receipts");

        assert_eq!(error, TransitionError::VaultNotActive);
    }

    #[test]
    fn validate_vault_active_rejects_locked_vault() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.status = VaultStatus::Locked as u8;

        let error = validate_vault_active(&vault).expect_err("locked vault should fail");

        assert_eq!(error, TransitionError::VaultNotActive);
    }

    #[test]
    fn validate_vault_recovery_mode_accepts_recovery() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.status = VaultStatus::Recovery as u8;

        validate_vault_recovery_mode(&vault).expect("recovery vault should pass");
    }

    #[test]
    fn validate_vault_recovery_mode_accepts_locked() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.status = VaultStatus::Locked as u8;

        validate_vault_recovery_mode(&vault).expect("locked vault should pass");
    }

    #[test]
    fn validate_vault_recovery_mode_rejects_active() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);

        let error = validate_vault_recovery_mode(&vault)
            .expect_err("active vault should fail recovery-mode check");

        assert_eq!(error, TransitionError::VaultNotRecovery);
    }

    #[test]
    fn validate_vault_for_receipt_rejects_expired_receipt() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 9,
        };

        let error = validate_vault_for_receipt(&vault, &receipt, 10)
            .expect_err("expired receipt should not stage");

        assert_eq!(error, TransitionError::ReceiptExpired);
    }

    #[test]
    fn validate_vault_for_receipt_rejects_replayed_nonce() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.last_consumed_receipt_nonce = 5;
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };

        let error = validate_vault_for_receipt(&vault, &receipt, 10)
            .expect_err("replayed nonce should fail fast");

        assert_eq!(error, TransitionError::ReceiptNonceReplay);
    }

    #[test]
    fn parse_vault_status_rejects_unknown_value() {
        let error = parse_vault_status(42).expect_err("unknown status should fail");

        assert_eq!(error, TransitionError::VaultStatusInvalid);
    }

    #[test]
    fn update_vault_status_allows_lock_then_recovery() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);

        update_vault_status(&mut vault, VaultStatus::Locked)
            .expect("active to locked should be allowed");
        update_vault_status(&mut vault, VaultStatus::Recovery)
            .expect("locked to recovery should be allowed");

        assert_eq!(vault.status, VaultStatus::Recovery as u8);
    }

    #[test]
    fn update_vault_status_rejects_locked_to_active() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.status = VaultStatus::Locked as u8;

        let error = update_vault_status(&mut vault, VaultStatus::Active)
            .expect_err("locked to active should be rejected");

        assert_eq!(error, TransitionError::VaultStatusTransitionNotAllowed);
    }

    #[test]
    fn validate_vault_authority_alignment_accepts_matching_hashes() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let authority = initialize_quantum_authority([2; 32], [3; 32], 1);

        validate_vault_authority_alignment(&vault, &authority)
            .expect("matching authority hashes should pass");
    }

    #[test]
    fn validate_vault_authority_alignment_rejects_mismatch() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let authority = initialize_quantum_authority([3; 32], [4; 32], 1);

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
    fn validate_and_advance_receipt_nonce_rejects_replay() {
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };

        validate_and_advance_receipt_nonce(&mut vault, &receipt)
            .expect("first nonce should advance");
        let error = validate_and_advance_receipt_nonce(&mut vault, &receipt)
            .expect_err("reusing nonce should fail");

        assert_eq!(error, TransitionError::ReceiptNonceReplay);
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
        assert_eq!(session.policy_version, receipt.policy_version);
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

        let session = open_action_session_from_receipt(&staged, &receipt, 10)
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

        let error = open_action_session_from_receipt(&staged, &receipt, 10)
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

        let error = open_action_session_from_receipt(&staged, &mismatched, 10)
            .expect_err("mismatched receipt should be rejected");

        assert_eq!(error, TransitionError::ReceiptMismatch);
    }

    #[test]
    fn opening_action_session_from_expired_receipt_fails() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 9,
        };
        let staged = stage_policy_receipt(&receipt);

        let error = open_action_session_from_receipt(&staged, &receipt, 10)
            .expect_err("expired staged receipt should be rejected");

        assert_eq!(error, TransitionError::ReceiptExpired);
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

        mark_action_session_ready(&mut session, receipt.action_hash, 10)
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

        let error = mark_action_session_ready(&mut session, [99; 32], 10)
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

        let error = mark_action_session_ready(&mut session, receipt.action_hash, 10)
            .expect_err("ready session should not transition twice");

        assert_eq!(error, TransitionError::SessionNotPending);
    }

    #[test]
    fn marking_action_session_ready_rejects_expired_session() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 9,
        };
        let mut session = open_action_session(&receipt);

        let error = mark_action_session_ready(&mut session, receipt.action_hash, 10)
            .expect_err("expired session should not become ready");

        assert_eq!(error, TransitionError::SessionExpired);
    }

    #[test]
    fn marking_action_session_ready_rejects_pqc_only_threshold() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::RequirePqcAuth,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);

        let error = mark_action_session_ready(&mut session, receipt.action_hash, 10)
            .expect_err("pqc-only threshold should not pass spend path");

        assert_eq!(error, TransitionError::SessionRequiresPqc);
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
        mark_action_session_ready(&mut session, receipt.action_hash, 10)
            .expect("matching action hash should mark session ready");

        consume_action_session(&mut session, receipt.action_hash, 10)
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

        let error = consume_action_session(&mut session, receipt.action_hash, 10)
            .expect_err("pending session should not be consumable");

        assert_eq!(error, TransitionError::SessionNotReady);
    }

    #[test]
    fn consuming_expired_action_session_rejects_transition() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 9,
        };
        let mut session = open_action_session(&receipt);
        session.status = SessionStatus::Ready as u8;

        let error = consume_action_session(&mut session, receipt.action_hash, 10)
            .expect_err("expired ready session should not be consumable");

        assert_eq!(error, TransitionError::SessionExpired);
    }

    #[test]
    fn consuming_action_session_rejects_pqc_only_threshold() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::RequirePqcAuth,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);
        session.status = SessionStatus::Ready as u8;

        let error = consume_action_session(&mut session, receipt.action_hash, 10)
            .expect_err("pqc-only threshold should not be consumable by spend path");

        assert_eq!(error, TransitionError::SessionRequiresPqc);
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
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        mark_action_session_ready(&mut session, receipt.action_hash, 10)
            .expect("matching action hash should mark session ready");

        finalize_action_session(&mut vault, &mut session, &mut staged, &receipt, 10)
            .expect("ready session should finalize against staged receipt");

        assert_eq!(session.status, SessionStatus::Consumed as u8);
        assert_eq!(staged.consumed, 1);
        assert_eq!(vault.last_consumed_receipt_nonce, receipt.nonce);
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
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let mismatched = vaulkyrie_protocol::PolicyReceipt {
            nonce: 77,
            ..receipt
        };
        mark_action_session_ready(&mut session, receipt.action_hash, 10)
            .expect("matching action hash should mark session ready");

        let error = finalize_action_session(&mut vault, &mut session, &mut staged, &mismatched, 10)
            .expect_err("mismatched receipt should be rejected");

        assert_eq!(error, TransitionError::SessionMismatch);
    }

    #[test]
    fn finalizing_action_session_rejects_policy_mismatch() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        session.status = SessionStatus::Ready as u8;
        session.policy_version = 10;

        let error = finalize_action_session(&mut vault, &mut session, &mut staged, &receipt, 10)
            .expect_err("mismatched policy version should fail");

        assert_eq!(error, TransitionError::SessionPolicyMismatch);
    }

    #[test]
    fn finalizing_expired_action_session_rejects_transition() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 9,
        };
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        session.status = SessionStatus::Ready as u8;

        let error = finalize_action_session(&mut vault, &mut session, &mut staged, &receipt, 10)
            .expect_err("expired session should not finalize");

        assert_eq!(error, TransitionError::SessionExpired);
    }

    #[test]
    fn finalizing_action_session_rejects_pqc_only_threshold() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::RequirePqcAuth,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        session.status = SessionStatus::Ready as u8;

        let error = finalize_action_session(&mut vault, &mut session, &mut staged, &receipt, 10)
            .expect_err("pqc-only threshold should not finalize through spend path");

        assert_eq!(error, TransitionError::SessionRequiresPqc);
    }

    #[test]
    fn finalizing_action_session_rejects_replayed_nonce() {
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 9,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let mut vault = initialize_vault([1; 32], [2; 32], 9, 4);
        vault.last_consumed_receipt_nonce = 5;
        let mut session = open_action_session(&receipt);
        let mut staged = stage_policy_receipt(&receipt);
        session.status = SessionStatus::Ready as u8;

        let error = finalize_action_session(&mut vault, &mut session, &mut staged, &receipt, 10)
            .expect_err("replayed nonce should fail finalize");

        assert_eq!(error, TransitionError::ReceiptNonceReplay);
    }

    #[test]
    fn authority_rotation_advances_sequence() {
        let secret = sample_wots_secret(33);
        let auth_path = sample_auth_path(17);
        let proof_root = secret
            .sign_statement_with_auth_path(
                &vaulkyrie_protocol::AuthorityRotationStatement {
                    action_hash: [0; 32],
                    next_authority_hash: [4; 32],
                    sequence: 0,
                    expiry_slot: 100,
                },
                0,
                auth_path,
            )
            .merkle_root();
        let mut state = QuantumAuthorityState::new(secret.authority_hash(), proof_root, 1);
        let mut statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: [4; 32],
            sequence: 0,
            expiry_slot: 100,
        };
        statement.action_hash = statement.expected_action_hash([1; 32], 9);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, auth_path);
        verify_authority_proof(&state, &statement, &proof).expect("proof should verify");

        apply_authority_rotation(&mut state, &statement, 10).expect("sequence should match");

        assert_eq!(state.current_authority_hash, [4; 32]);
        assert_eq!(state.next_sequence, 1);
        assert_eq!(state.next_leaf_index, 1);
        assert_eq!(state.last_consumed_digest, statement.digest());
    }

    #[test]
    fn authority_rotation_rejects_stale_sequence() {
        let secret = sample_wots_secret(33);
        let mut state = QuantumAuthorityState::new(secret.authority_hash(), [8; 32], 1);
        state.next_sequence = 2;
        let mut statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: [4; 32],
            sequence: 1,
            expiry_slot: 100,
        };
        statement.action_hash = statement.expected_action_hash([1; 32], 9);

        let error = apply_authority_rotation(&mut state, &statement, 10)
            .expect_err("stale sequence should be rejected");

        assert_eq!(error, TransitionError::AuthoritySequenceMismatch);
    }

    #[test]
    fn authority_rotation_rejects_no_op_hash() {
        let secret = sample_wots_secret(33);
        let mut state = QuantumAuthorityState::new(secret.authority_hash(), [8; 32], 1);
        let mut statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: secret.authority_hash(),
            sequence: 0,
            expiry_slot: 100,
        };
        statement.action_hash = statement.expected_action_hash([1; 32], 9);

        let error = apply_authority_rotation(&mut state, &statement, 10)
            .expect_err("reusing the same authority hash should fail");

        assert_eq!(error, TransitionError::AuthorityNoOp);
    }

    #[test]
    fn authority_rotation_rejects_expired_statement() {
        let secret = sample_wots_secret(33);
        let mut state = QuantumAuthorityState::new(secret.authority_hash(), [8; 32], 1);
        let mut statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: [4; 32],
            sequence: 0,
            expiry_slot: 9,
        };
        statement.action_hash = statement.expected_action_hash([1; 32], 9);

        let error = apply_authority_rotation(&mut state, &statement, 10)
            .expect_err("expired authority statement should fail");

        assert_eq!(error, TransitionError::AuthorityStatementExpired);
    }

    #[test]
    fn rotate_vault_authority_updates_both_states() {
        let secret = sample_wots_secret(33);
        let auth_path = sample_auth_path(21);
        let mut vault = initialize_vault([1; 32], secret.authority_hash(), 9, 4);
        vault.status = VaultStatus::Recovery as u8;
        let statement =
            sample_rotation_statement(vault.wallet_pubkey, vault.policy_version, [4; 32], 0, 100);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, auth_path);
        let mut authority =
            initialize_quantum_authority(secret.authority_hash(), proof.merkle_root(), 1);

        rotate_vault_authority(&mut vault, &mut authority, &statement, &proof, 10)
            .expect("aligned authority should rotate");

        assert_eq!(vault.current_authority_hash, [4; 32]);
        assert_eq!(authority.current_authority_hash, [4; 32]);
        assert_eq!(authority.next_sequence, 1);
        assert_eq!(authority.next_leaf_index, 1);
    }

    #[test]
    fn rotate_vault_authority_rejects_active_vault() {
        let secret = sample_wots_secret(33);
        let mut vault = initialize_vault([1; 32], secret.authority_hash(), 9, 4);
        let statement =
            sample_rotation_statement(vault.wallet_pubkey, vault.policy_version, [4; 32], 0, 100);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(22));
        let mut authority =
            initialize_quantum_authority(secret.authority_hash(), proof.merkle_root(), 1);

        let error = rotate_vault_authority(&mut vault, &mut authority, &statement, &proof, 10)
            .expect_err("active vault should not allow authority rotation");

        assert_eq!(error, TransitionError::VaultNotRecovery);
    }

    #[test]
    fn rotate_vault_authority_rejects_unbound_action_hash() {
        let secret = sample_wots_secret(33);
        let mut vault = initialize_vault([1; 32], secret.authority_hash(), 9, 4);
        vault.status = VaultStatus::Recovery as u8;
        let mut authority = initialize_quantum_authority(secret.authority_hash(), [8; 32], 1);
        let statement = AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [4; 32],
            sequence: 0,
            expiry_slot: 100,
        };
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(23));

        let error = rotate_vault_authority(&mut vault, &mut authority, &statement, &proof, 10)
            .expect_err("rotation must require rekey-bound action hash");

        assert_eq!(error, TransitionError::AuthorityActionMismatch);
    }

    #[test]
    fn validate_authority_action_binding_accepts_rekey_bound_hash() {
        let vault = initialize_vault([1; 32], [3; 32], 9, 4);
        let statement =
            sample_rotation_statement(vault.wallet_pubkey, vault.policy_version, [4; 32], 0, 100);

        validate_authority_action_binding(&vault, &statement)
            .expect("rekey-bound action hash should pass");
    }

    #[test]
    fn verify_authority_proof_rejects_hash_mismatch() {
        let secret = sample_wots_secret(33);
        let statement = sample_rotation_statement([1; 32], 9, [4; 32], 0, 100);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(24));
        let authority = initialize_quantum_authority([9; 32], proof.merkle_root(), 1);

        let error = verify_authority_proof(&authority, &statement, &proof)
            .expect_err("proof hash must match current authority hash");

        assert_eq!(error, TransitionError::AuthorityProofMismatch);
    }

    #[test]
    fn verify_authority_proof_rejects_invalid_signature() {
        let secret = sample_wots_secret(33);
        let statement = sample_rotation_statement([1; 32], 9, [4; 32], 0, 100);
        let mut proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(25));
        proof.signature[0] ^= 1;
        let authority =
            initialize_quantum_authority(secret.authority_hash(), proof.merkle_root(), 1);

        let error = verify_authority_proof(&authority, &statement, &proof)
            .expect_err("tampered proof should fail verification");

        assert_eq!(error, TransitionError::AuthorityProofInvalid);
    }

    #[test]
    fn verify_authority_proof_rejects_leaf_index_mismatch() {
        let secret = sample_wots_secret(33);
        let statement = sample_rotation_statement([1; 32], 9, [4; 32], 0, 100);
        let proof = secret.sign_statement_with_auth_path(&statement, 1, sample_auth_path(26));
        let authority =
            initialize_quantum_authority(secret.authority_hash(), proof.merkle_root(), 1);

        let error = verify_authority_proof(&authority, &statement, &proof)
            .expect_err("proof must consume the next expected leaf index");

        assert_eq!(error, TransitionError::AuthorityLeafIndexMismatch);
    }

    #[test]
    fn verify_authority_proof_rejects_merkle_root_mismatch() {
        let secret = sample_wots_secret(33);
        let statement = sample_rotation_statement([1; 32], 9, [4; 32], 0, 100);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(27));
        let authority = initialize_quantum_authority(secret.authority_hash(), [8; 32], 1);

        let error = verify_authority_proof(&authority, &statement, &proof)
            .expect_err("proof root must match the current authority root");

        assert_eq!(error, TransitionError::AuthorityMerkleRootMismatch);
    }

    #[test]
    fn verify_authority_proof_rejects_tree_exhaustion() {
        let secret = sample_wots_secret(33);
        let statement = sample_rotation_statement([1; 32], 9, [4; 32], 0, 100);
        let proof =
            secret.sign_statement_with_auth_path(&statement, XMSS_LEAF_COUNT, sample_auth_path(28));
        let mut authority =
            initialize_quantum_authority(secret.authority_hash(), proof.merkle_root(), 1);
        authority.next_leaf_index = XMSS_LEAF_COUNT;

        let error = verify_authority_proof(&authority, &statement, &proof)
            .expect_err("no proof should pass once the authority tree is exhausted");

        assert_eq!(error, TransitionError::AuthorityTreeExhausted);
    }

    #[test]
    fn validate_quantum_vault_split_accepts_bound_message() {
        let privkey = WinternitzPrivkey::from([44u8; solana_winternitz::HASH_LENGTH * 32]);
        let signature = privkey.sign(&vaulkyrie_protocol::quantum_split_message(
            55, [7; 32], [8; 32],
        ));
        let hash = privkey.pubkey().merklize();
        let program_id = [1; 32];
        let bump = 2;
        let vault_pubkey = hashv(&[
            hash.as_ref(),
            [bump].as_ref(),
            program_id.as_ref(),
            b"ProgramDerivedAddress",
        ]);

        validate_quantum_vault_split(
            &signature,
            55,
            [7; 32],
            [8; 32],
            bump,
            vault_pubkey,
            program_id,
        )
        .expect("split signature should validate");
    }

    #[test]
    fn validate_quantum_vault_split_rejects_wrong_amount() {
        let privkey = WinternitzPrivkey::from([45u8; solana_winternitz::HASH_LENGTH * 32]);
        let signature = privkey.sign(&vaulkyrie_protocol::quantum_split_message(
            55, [7; 32], [8; 32],
        ));
        let hash = privkey.pubkey().merklize();
        let program_id = [1; 32];
        let bump = 2;
        let vault_pubkey = hashv(&[
            hash.as_ref(),
            [bump].as_ref(),
            program_id.as_ref(),
            b"ProgramDerivedAddress",
        ]);

        let error = validate_quantum_vault_split(
            &signature,
            56,
            [7; 32],
            [8; 32],
            bump,
            vault_pubkey,
            program_id,
        )
        .expect_err("split signature must be amount-bound");

        assert_eq!(error, TransitionError::QuantumVaultPdaMismatch);
    }

    #[test]
    fn validate_quantum_vault_close_accepts_refund_binding() {
        let privkey = WinternitzPrivkey::from([46u8; solana_winternitz::HASH_LENGTH * 32]);
        let signature = privkey.sign(&vaulkyrie_protocol::quantum_close_message([9; 32]));
        let hash = privkey.pubkey().merklize();
        let program_id = [2; 32];
        let bump = 3;
        let vault_pubkey = hashv(&[
            hash.as_ref(),
            [bump].as_ref(),
            program_id.as_ref(),
            b"ProgramDerivedAddress",
        ]);

        validate_quantum_vault_close(&signature, [9; 32], bump, vault_pubkey, program_id)
            .expect("close signature should validate");
    }

    #[test]
    fn validate_quantum_vault_split_amount_rejects_overspend() {
        let error = validate_quantum_vault_split_amount(10, 11)
            .expect_err("split amount above vault balance should fail");

        assert_eq!(error, TransitionError::QuantumVaultAmountTooLarge);
    }

    #[test]
    fn validate_vault_for_session_rejects_policy_mismatch() {
        let vault = initialize_vault([1; 32], [2; 32], 9, 4);
        let receipt = vaulkyrie_protocol::PolicyReceipt {
            action_hash: sample_action_hash(),
            policy_version: 10,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 5,
            expiry_slot: 10,
        };
        let session = open_action_session(&receipt);

        let error = validate_vault_for_session(&vault, &session)
            .expect_err("vault/session policy mismatch should fail");

        assert_eq!(error, TransitionError::SessionPolicyMismatch);
    }

    #[test]
    fn init_spend_orchestration_creates_pending_state() {
        use super::{init_spend_orchestration, OrchestrationStatus};
        let state = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [4; 32], 1000, 2, 3, 7, 500,
        )
        .expect("valid params should succeed");

        assert_eq!(state.action_hash, [1; 32]);
        assert_eq!(state.status, OrchestrationStatus::Pending as u8);
        assert_eq!(state.threshold, 2);
        assert_eq!(state.participant_count, 3);
        assert_eq!(state.signing_package_hash, [4; 32]);
    }

    #[test]
    fn init_spend_orchestration_rejects_expired_slot() {
        use super::init_spend_orchestration;
        let error = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [4; 32], 500, 2, 3, 7, 500,
        )
        .expect_err("expiry <= current_slot should fail");

        assert_eq!(error, TransitionError::OrchestrationExpired);
    }

    #[test]
    fn init_spend_orchestration_rejects_invalid_threshold() {
        use super::init_spend_orchestration;
        let error = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [4; 32], 1000, 5, 3, 7, 500,
        )
        .expect_err("threshold > participant_count should fail");

        assert_eq!(error, TransitionError::OrchestrationInvalidParams);
    }

    #[test]
    fn commit_spend_orchestration_advances_to_committed() {
        use super::{commit_spend_orchestration, init_spend_orchestration, OrchestrationStatus};
        let mut state = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [0; 32], 1000, 2, 3, 7, 500,
        )
        .unwrap();

        commit_spend_orchestration(&mut state, [1; 32], [5; 32], 600).expect("should commit");

        assert_eq!(state.status, OrchestrationStatus::Committed as u8);
        assert_eq!(state.signing_package_hash, [5; 32]);
    }

    #[test]
    fn commit_spend_orchestration_rejects_wrong_action_hash() {
        use super::{commit_spend_orchestration, init_spend_orchestration};
        let mut state = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [0; 32], 1000, 2, 3, 7, 500,
        )
        .unwrap();

        let error = commit_spend_orchestration(&mut state, [9; 32], [5; 32], 600)
            .expect_err("wrong action hash should fail");

        assert_eq!(error, TransitionError::OrchestrationActionMismatch);
    }

    #[test]
    fn complete_spend_orchestration_marks_complete() {
        use super::{
            commit_spend_orchestration, complete_spend_orchestration, init_spend_orchestration,
            OrchestrationStatus,
        };
        let mut state = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [0; 32], 1000, 2, 3, 7, 500,
        )
        .unwrap();
        commit_spend_orchestration(&mut state, [1; 32], [5; 32], 600).unwrap();

        complete_spend_orchestration(&mut state, [1; 32], 700).expect("should complete");

        assert_eq!(state.status, OrchestrationStatus::Complete as u8);
    }

    #[test]
    fn fail_spend_orchestration_marks_failed() {
        use super::{fail_spend_orchestration, init_spend_orchestration, OrchestrationStatus};
        let mut state = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [0; 32], 1000, 2, 3, 7, 500,
        )
        .unwrap();

        fail_spend_orchestration(&mut state, [1; 32]).expect("should fail orchestration");

        assert_eq!(state.status, OrchestrationStatus::Failed as u8);
    }

    #[test]
    fn fail_spend_orchestration_rejects_already_complete() {
        use super::{
            commit_spend_orchestration, complete_spend_orchestration, fail_spend_orchestration,
            init_spend_orchestration,
        };
        let mut state = init_spend_orchestration(
            [1; 32], [2; 32], [3; 32], [0; 32], 1000, 2, 3, 7, 500,
        )
        .unwrap();
        commit_spend_orchestration(&mut state, [1; 32], [5; 32], 600).unwrap();
        complete_spend_orchestration(&mut state, [1; 32], 700).unwrap();

        let error = fail_spend_orchestration(&mut state, [1; 32])
            .expect_err("complete orchestration cannot be failed");

        assert_eq!(error, TransitionError::OrchestrationAlreadyComplete);
    }
}
