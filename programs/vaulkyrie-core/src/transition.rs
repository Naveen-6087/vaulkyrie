use solana_nostd_sha256::hashv;
use solana_winternitz::signature::WinternitzSignature;
use vaulkyrie_protocol::{
    quantum_close_message, quantum_split_message, AuthorityRotationStatement,
    WinterAuthorityAdvanceStatement, WinterAuthoritySignature, WotsAuthProof, XMSS_LEAF_COUNT,
};

use crate::state::{
    OrchestrationStatus, QuantumAuthorityState, RecoveryState, RecoveryStatus,
    SpendOrchestrationState, VaultRegistry, VaultStatus,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    AuthorityStatementExpired,
    VaultAuthorityMismatch,
    VaultNotActive,
    VaultNotRecovery,
    VaultStatusInvalid,
    VaultStatusTransitionNotAllowed,
    AuthorityNoOp,
    AuthoritySequenceMismatch,
    AuthorityLeafIndexMismatch,
    AuthorityActionMismatch,
    AuthorityProofInvalid,
    AuthorityProofMismatch,
    AuthorityMerkleRootMismatch,
    AuthorityTreeExhausted,
    QuantumVaultAmountTooLarge,
    QuantumVaultPdaMismatch,
    OrchestrationExpired,
    OrchestrationInvalidParams,
    OrchestrationActionMismatch,
    OrchestrationNotPending,
    OrchestrationNotCommitted,
    OrchestrationAlreadyComplete,
    RecoveryVaultNotInRecoveryMode,
    RecoveryExpired,
    RecoveryNotPending,
    RecoveryInvalidParams,
    AuthorityMigrationNoOp,
    TxBindingMissing,
    AuthorityStatementReplay,
}

pub fn initialize_vault(
    wallet_pubkey: [u8; 32],
    authority_hash: [u8; 32],
    bump: u8,
) -> VaultRegistry {
    VaultRegistry::new(wallet_pubkey, authority_hash, VaultStatus::Active, bump)
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

pub fn validate_vault_active(vault: &VaultRegistry) -> Result<(), TransitionError> {
    if vault.status == VaultStatus::Active as u8 {
        Ok(())
    } else {
        Err(TransitionError::VaultNotActive)
    }
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
    if vault.current_authority_hash == authority.current_authority_hash {
        Ok(())
    } else {
        Err(TransitionError::VaultAuthorityMismatch)
    }
}

pub fn validate_authority_action_binding(
    vault: &VaultRegistry,
    statement: &AuthorityRotationStatement,
) -> Result<(), TransitionError> {
    if statement.is_action_bound(vault.wallet_pubkey) {
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

pub fn apply_authority_rotation(
    authority: &mut QuantumAuthorityState,
    statement: &AuthorityRotationStatement,
    current_slot: u64,
) -> Result<(), TransitionError> {
    if authority.current_authority_hash == statement.next_authority_hash {
        return Err(TransitionError::AuthorityNoOp);
    }
    if statement.expiry_slot < current_slot {
        return Err(TransitionError::AuthorityStatementExpired);
    }
    if authority.next_sequence != statement.sequence {
        return Err(TransitionError::AuthoritySequenceMismatch);
    }
    if authority.next_leaf_index >= XMSS_LEAF_COUNT {
        return Err(TransitionError::AuthorityTreeExhausted);
    }

    let digest = statement.digest();
    if authority.last_consumed_digest != [0; 32] && authority.last_consumed_digest == digest {
        return Err(TransitionError::AuthorityStatementReplay);
    }

    authority.last_consumed_digest = digest;
    authority.current_authority_hash = statement.next_authority_hash;
    authority.next_sequence += 1;
    authority.next_leaf_index += 1;
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

pub fn verify_winter_authority_advance(
    authority: &QuantumAuthorityState,
    statement: &WinterAuthorityAdvanceStatement,
    signature: &WinterAuthoritySignature,
) -> Result<(), TransitionError> {
    if statement.current_root != authority.current_authority_root {
        return Err(TransitionError::AuthorityMerkleRootMismatch);
    }
    if authority.current_authority_hash != statement.current_root {
        return Err(TransitionError::AuthorityProofMismatch);
    }
    if !signature.verify_statement(statement) {
        return Err(TransitionError::AuthorityProofInvalid);
    }

    Ok(())
}

pub fn apply_winter_authority_advance(
    authority: &mut QuantumAuthorityState,
    statement: &WinterAuthorityAdvanceStatement,
    current_slot: u64,
) -> Result<(), TransitionError> {
    if statement.current_root == statement.next_root {
        return Err(TransitionError::AuthorityNoOp);
    }
    if statement.expiry_slot < current_slot {
        return Err(TransitionError::AuthorityStatementExpired);
    }
    if authority.next_sequence != statement.sequence {
        return Err(TransitionError::AuthoritySequenceMismatch);
    }

    let digest = statement.replay_digest();
    if authority.last_consumed_digest != [0; 32] && authority.last_consumed_digest == digest {
        return Err(TransitionError::AuthorityStatementReplay);
    }

    authority.last_consumed_digest = digest;
    authority.current_authority_hash = statement.next_root;
    authority.current_authority_root = statement.next_root;
    authority.next_sequence += 1;
    authority.next_leaf_index = 0;
    Ok(())
}

pub fn advance_winter_authority(
    vault: &mut VaultRegistry,
    authority: &mut QuantumAuthorityState,
    statement: &WinterAuthorityAdvanceStatement,
    signature: &WinterAuthoritySignature,
    current_slot: u64,
) -> Result<(), TransitionError> {
    validate_vault_recovery_mode(vault)?;
    if !statement.is_action_bound(vault.wallet_pubkey) {
        return Err(TransitionError::AuthorityActionMismatch);
    }
    validate_vault_authority_alignment(vault, authority)?;
    verify_winter_authority_advance(authority, statement, signature)?;
    apply_winter_authority_advance(authority, statement, current_slot)?;
    vault.current_authority_hash = authority.current_authority_hash;
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
        Err(TransitionError::QuantumVaultAmountTooLarge)
    } else {
        Ok(())
    }
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

pub fn complete_spend_orchestration(
    state: &mut SpendOrchestrationState,
    action_hash: [u8; 32],
    tx_binding: [u8; 32],
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
    if tx_binding == [0; 32] {
        return Err(TransitionError::TxBindingMissing);
    }

    state.tx_binding = tx_binding;
    state.status = OrchestrationStatus::Complete as u8;
    Ok(())
}

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

pub fn init_recovery(
    vault_status: u8,
    current_slot: u64,
    expiry_slot: u64,
    new_threshold: u8,
    new_participant_count: u8,
) -> Result<(), TransitionError> {
    if parse_vault_status(vault_status) != Ok(VaultStatus::Recovery) {
        return Err(TransitionError::RecoveryVaultNotInRecoveryMode);
    }
    if current_slot >= expiry_slot {
        return Err(TransitionError::RecoveryExpired);
    }
    if new_threshold == 0 || new_participant_count == 0 || new_threshold > new_participant_count {
        return Err(TransitionError::RecoveryInvalidParams);
    }
    Ok(())
}

pub fn complete_recovery(
    recovery: &RecoveryState,
    current_slot: u64,
) -> Result<(), TransitionError> {
    if recovery.status != RecoveryStatus::Pending as u8 {
        return Err(TransitionError::RecoveryNotPending);
    }
    if current_slot >= recovery.expiry_slot {
        return Err(TransitionError::RecoveryExpired);
    }
    Ok(())
}

pub fn migrate_authority_tree(
    authority: &mut QuantumAuthorityState,
    new_authority_root: [u8; 32],
) -> Result<(), TransitionError> {
    if authority.next_leaf_index == 0 {
        return Err(TransitionError::AuthorityMigrationNoOp);
    }
    authority.current_authority_root = new_authority_root;
    authority.next_leaf_index = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaulkyrie_protocol::{
        WinterAuthoritySecretKey, WotsSecretKey, WINTER_AUTHORITY_SIGNATURE_BYTES, WOTS_KEY_BYTES,
        XMSS_AUTH_PATH_BYTES,
    };

    fn sample_rotation_statement(next_authority_hash: [u8; 32]) -> AuthorityRotationStatement {
        let mut statement = AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash,
            sequence: 0,
            expiry_slot: 100,
        };
        statement.action_hash = statement.expected_action_hash([1; 32]);
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

    fn sample_winter_secret(seed: u8) -> WinterAuthoritySecretKey {
        let mut scalars = [0u8; WINTER_AUTHORITY_SIGNATURE_BYTES];
        for (index, byte) in scalars.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        WinterAuthoritySecretKey { scalars }
    }

    #[test]
    fn initialize_vault_sets_active_status() {
        let vault = initialize_vault([1; 32], [2; 32], 4);
        assert_eq!(vault.wallet_pubkey, [1; 32]);
        assert_eq!(vault.current_authority_hash, [2; 32]);
        assert_eq!(vault.status, VaultStatus::Active as u8);
        assert_eq!(vault.bump, 4);
    }

    #[test]
    fn update_vault_status_rejects_locked_to_active() {
        let mut vault = initialize_vault([1; 32], [2; 32], 4);
        vault.status = VaultStatus::Locked as u8;
        let error = update_vault_status(&mut vault, VaultStatus::Active).unwrap_err();
        assert_eq!(error, TransitionError::VaultStatusTransitionNotAllowed);
    }

    #[test]
    fn rotate_vault_authority_updates_current_hash() {
        let secret = sample_wots_secret(7);
        let statement = sample_rotation_statement([9; 32]);
        let proof = secret.sign_statement_with_auth_path(&statement, 0, sample_auth_path(4));
        let current_root = proof.merkle_root();

        let mut vault = initialize_vault([1; 32], proof.authority_hash(), 2);
        vault.status = VaultStatus::Recovery as u8;
        let mut authority = initialize_quantum_authority(proof.authority_hash(), current_root, 2);

        rotate_vault_authority(&mut vault, &mut authority, &statement, &proof, 10).unwrap();

        assert_eq!(vault.current_authority_hash, [9; 32]);
        assert_eq!(authority.next_sequence, 1);
    }

    #[test]
    fn init_spend_orchestration_requires_live_expiry() {
        let error = init_spend_orchestration([1; 32], [2; 32], [3; 32], [4; 32], 10, 2, 3, 1, 10)
            .unwrap_err();
        assert_eq!(error, TransitionError::OrchestrationExpired);
    }

    #[test]
    fn spend_orchestration_flow_roundtrips_status() {
        let mut state =
            init_spend_orchestration([1; 32], [2; 32], [3; 32], [4; 32], 20, 2, 3, 1, 10).unwrap();
        commit_spend_orchestration(&mut state, [1; 32], [5; 32], 11).unwrap();
        complete_spend_orchestration(&mut state, [1; 32], [6; 32], 12).unwrap();
        assert_eq!(state.status, OrchestrationStatus::Complete as u8);
    }

    #[test]
    fn recovery_requires_recovery_mode() {
        let error = init_recovery(VaultStatus::Active as u8, 10, 20, 2, 3).unwrap_err();
        assert_eq!(error, TransitionError::RecoveryVaultNotInRecoveryMode);
    }

    #[test]
    fn winter_authority_advance_updates_hash() {
        let secret = sample_winter_secret(9);
        let current_root = secret.root();
        let next_root = sample_winter_secret(10).root();
        let mut authority = initialize_quantum_authority(current_root, current_root, 1);
        let mut vault = initialize_vault([1; 32], current_root, 2);
        vault.status = VaultStatus::Recovery as u8;

        let mut statement = WinterAuthorityAdvanceStatement {
            action_hash: [0; 32],
            current_root,
            next_root,
            sequence: 0,
            expiry_slot: 100,
        };
        statement.action_hash = statement.expected_action_hash(vault.wallet_pubkey);
        let signature = secret.sign_statement(&statement);

        advance_winter_authority(&mut vault, &mut authority, &statement, &signature, 10).unwrap();
        assert_eq!(vault.current_authority_hash, next_root);
    }
}
