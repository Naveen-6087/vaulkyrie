use pinocchio::{
    account_info::AccountInfo,
    get_account_info,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt};

use crate::{
    instruction::{CoreInstruction, InitAuthorityArgs, InitVaultArgs},
    state::{
        ActionSessionState, PolicyReceiptState, QuantumAuthorityState, VaultRegistry,
        ACTION_SESSION_DISCRIMINATOR, POLICY_RECEIPT_DISCRIMINATOR,
        QUANTUM_STATE_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
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
            ensure_wallet_authority(args.wallet_pubkey, *wallet_signer.key(), wallet_signer.is_signer())?;

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
        CoreInstruction::RotateAuthority(statement) => {
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
                &statement,
                current_slot,
            )
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

    let state = transition::initialize_quantum_authority(args.current_authority_hash, args.bump);
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

    let mut state = PolicyReceiptState::decode(receipt_dst).ok_or(ProgramError::InvalidAccountData)?;
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

    let mut vault_state = VaultRegistry::decode(vault_dst).ok_or(ProgramError::InvalidAccountData)?;
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

    transition::rotate_vault_authority(&mut vault, &mut authority, statement, current_slot)
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
    Ok(Clock::get()?.slot)
}

fn map_transition_error(error: transition::TransitionError) -> ProgramError {
    match error {
        transition::TransitionError::ReceiptAlreadyConsumed => ProgramError::AccountAlreadyInitialized,
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
        transition::TransitionError::VaultStatusTransitionNotAllowed => ProgramError::InvalidArgument,
        transition::TransitionError::SessionPolicyMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::SessionMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::SessionNotPending => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::SessionNotReady => ProgramError::InvalidAccountData,
        transition::TransitionError::SessionRequiresPqc => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityNoOp => ProgramError::InvalidArgument,
        transition::TransitionError::AuthoritySequenceMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::AuthorityActionMismatch => ProgramError::InvalidArgument,
    }
}

#[cfg(test)]
mod tests {
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{ActionDescriptor, ActionKind, PolicyReceipt, ThresholdRequirement};

    use super::{
        process_activate_session_data, process_consume_receipt_data, process_consume_session_data,
        process_finalize_session_data, process_init_authority_data, process_init_vault_data,
        process_open_session_data, process_rotate_authority_data, process_set_vault_status_data,
        process_stage_receipt_data, ensure_wallet_authority,
    };
    use crate::{
        instruction::{InitAuthorityArgs, InitVaultArgs},
        state::{
            ActionSessionState, PolicyReceiptState, QuantumAuthorityState, SessionStatus,
            VaultRegistry, VaultStatus, ACTION_SESSION_DISCRIMINATOR,
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
        statement.action_hash = statement.expected_action_hash(vault.wallet_pubkey, vault.policy_version);
        statement
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

        let error = process_set_vault_status_data(&mut bytes, 42)
            .expect_err("unknown status should fail");

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
                bump: 2,
            },
        )
        .expect("authority init should succeed");

        let state = QuantumAuthorityState::decode(&bytes).expect("state should decode");
        assert_eq!(state.current_authority_hash, [7; 32]);
        assert_eq!(state.bump, 2);
        assert_eq!(state.next_sequence, 0);
    }

    #[test]
    fn init_authority_rejects_preinitialized_bytes() {
        let mut bytes = [1; QuantumAuthorityState::LEN];

        let error = process_init_authority_data(
            &mut bytes,
            InitAuthorityArgs {
                current_authority_hash: [7; 32],
                bump: 2,
            },
        )
        .expect_err("preinitialized bytes should fail");

        assert_eq!(error, ProgramError::AccountAlreadyInitialized);
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
        let mut vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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
    fn rotate_authority_updates_current_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut bytes = [0; QuantumAuthorityState::LEN];
        let vault = VaultRegistry::new([5; 32], [7; 32], 3, crate::state::VaultStatus::Recovery, 8);
        let initial = QuantumAuthorityState::new([7; 32], 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut bytes));
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);

        process_rotate_authority_data(
            &mut vault_bytes,
            &mut bytes,
            &statement,
            10,
        )
        .expect("rotation should succeed");

        let vault = VaultRegistry::decode(&vault_bytes).expect("vault should decode");
        let state = QuantumAuthorityState::decode(&bytes).expect("state should decode");
        assert_eq!(vault.current_authority_hash, [8; 32]);
        assert_eq!(state.current_authority_hash, [8; 32]);
        assert_eq!(state.next_sequence, 1);
    }

    #[test]
    fn rotate_authority_rejects_vault_authority_mismatch() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let vault = VaultRegistry::new([5; 32], [7; 32], 3, crate::state::VaultStatus::Recovery, 8);
        let initial = QuantumAuthorityState::new([9; 32], 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            10,
        )
        .expect_err("mismatched vault and authority should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn rotate_authority_rejects_no_op_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let vault = VaultRegistry::new([5; 32], [7; 32], 3, crate::state::VaultStatus::Recovery, 8);
        let initial = QuantumAuthorityState::new([7; 32], 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        let statement = sample_rotation_statement(&vault, [7; 32], 0, 200);

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            10,
        )
        .expect_err("no-op authority rotation should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn rotate_authority_rejects_expired_statement() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let vault = VaultRegistry::new([5; 32], [7; 32], 3, crate::state::VaultStatus::Recovery, 8);
        let initial = QuantumAuthorityState::new([7; 32], 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 9);

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            10,
        )
        .expect_err("expired authority statement should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn rotate_authority_rejects_active_vault() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let vault = VaultRegistry::new([5; 32], [7; 32], 3, crate::state::VaultStatus::Active, 8);
        let initial = QuantumAuthorityState::new([7; 32], 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        let statement = sample_rotation_statement(&vault, [8; 32], 0, 200);

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            10,
        )
        .expect_err("active vault should fail recovery-mode rotation");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn rotate_authority_rejects_unbound_action_hash() {
        let mut vault_bytes = [0; VaultRegistry::LEN];
        let mut authority_bytes = [0; QuantumAuthorityState::LEN];
        let vault = VaultRegistry::new([5; 32], [7; 32], 3, crate::state::VaultStatus::Recovery, 8);
        let initial = QuantumAuthorityState::new([7; 32], 1);
        assert!(vault.encode(&mut vault_bytes));
        assert!(initial.encode(&mut authority_bytes));
        let statement = vaulkyrie_protocol::AuthorityRotationStatement {
            action_hash: sample_action_hash(),
            next_authority_hash: [8; 32],
            sequence: 0,
            expiry_slot: 200,
        };

        let error = process_rotate_authority_data(
            &mut vault_bytes,
            &mut authority_bytes,
            &statement,
            10,
        )
        .expect_err("rotation should require rekey-bound action hash");

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
        assert_eq!(
            state.threshold,
            ThresholdRequirement::TwoOfThree.as_byte()
        );
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
        let error =
            process_activate_session_data(&mut bytes, receipt.action_hash, 10, receipt.policy_version)
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

        let receipt_state = PolicyReceiptState::decode(&receipt_bytes).expect("receipt should decode");
        let session_state = ActionSessionState::decode(&session_bytes).expect("session should decode");
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
        let mut vault = VaultRegistry::new([5; 32], [6; 32], 3, crate::state::VaultStatus::Active, 8);
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
}
