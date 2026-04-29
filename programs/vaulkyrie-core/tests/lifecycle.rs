use vaulkyrie_core::{
    instruction::{
        CommitSpendOrchestrationArgs, CompleteRecoveryArgs, CompleteSpendOrchestrationArgs,
        InitRecoveryArgs, InitSpendOrchestrationArgs, InitVaultArgs,
    },
    processor::{
        process_commit_spend_orchestration_data, process_complete_recovery_data,
        process_complete_spend_orchestration_data, process_init_recovery_data,
        process_init_spend_orchestration_data, process_init_vault_data,
        process_set_vault_status_data,
    },
    state::{
        OrchestrationStatus, RecoveryState, RecoveryStatus, SpendOrchestrationState, VaultRegistry,
        VaultStatus,
    },
};

#[test]
fn vault_status_lifecycle_uses_trimmed_registry() {
    let mut bytes = [0u8; VaultRegistry::LEN];
    process_init_vault_data(
        &mut bytes,
        InitVaultArgs {
            wallet_pubkey: [1; 32],
            authority_hash: [2; 32],
            bump: 3,
        },
    )
    .unwrap();

    process_set_vault_status_data(&mut bytes, VaultStatus::Recovery as u8).unwrap();
    process_set_vault_status_data(&mut bytes, VaultStatus::Locked as u8).unwrap();

    let vault = VaultRegistry::decode(&bytes).unwrap();
    assert_eq!(vault.wallet_pubkey, [1; 32]);
    assert_eq!(vault.current_authority_hash, [2; 32]);
    assert_eq!(vault.status, VaultStatus::Locked as u8);
}

#[test]
fn spend_orchestration_lifecycle_completes() {
    let mut bytes = [0u8; SpendOrchestrationState::LEN];
    process_init_spend_orchestration_data(
        &mut bytes,
        InitSpendOrchestrationArgs {
            action_hash: [4; 32],
            session_commitment: [5; 32],
            signers_commitment: [6; 32],
            signing_package_hash: [7; 32],
            expiry_slot: 100,
            threshold: 2,
            participant_count: 3,
            bump: 8,
        },
        10,
    )
    .unwrap();

    process_commit_spend_orchestration_data(
        &mut bytes,
        CommitSpendOrchestrationArgs {
            action_hash: [4; 32],
            signing_package_hash: [9; 32],
        },
        20,
    )
    .unwrap();
    process_complete_spend_orchestration_data(
        &mut bytes,
        CompleteSpendOrchestrationArgs {
            action_hash: [4; 32],
            tx_binding: [10; 32],
        },
        30,
    )
    .unwrap();

    let state = SpendOrchestrationState::decode(&bytes).unwrap();
    assert_eq!(state.status, OrchestrationStatus::Complete as u8);
    assert_eq!(state.tx_binding, [10; 32]);
}

#[test]
fn recovery_lifecycle_completes() {
    let mut bytes = [0u8; RecoveryState::LEN];
    process_init_recovery_data(
        &mut bytes,
        InitRecoveryArgs {
            vault_pubkey: [11; 32],
            recovery_commitment: [12; 32],
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
            new_group_key: [13; 32],
            new_authority_hash: [14; 32],
        },
        20,
    )
    .unwrap();

    let state = RecoveryState::decode(&bytes).unwrap();
    assert_eq!(state.status, RecoveryStatus::Complete as u8);
    assert_eq!(state.new_group_key, [13; 32]);
    assert_eq!(state.new_authority_hash, [14; 32]);
}
