use pinocchio::{account_info::AccountInfo, get_account_info, program_error::ProgramError, ProgramResult};
use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt};

use crate::{
    instruction::{CoreInstruction, InitVaultArgs},
    state::{
        ActionSessionState, PolicyReceiptState, QuantumAuthorityState, VaultRegistry,
        ACTION_SESSION_DISCRIMINATOR, POLICY_RECEIPT_DISCRIMINATOR,
        QUANTUM_STATE_DISCRIMINATOR,
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
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_init_vault_data(&mut data, args)
        }
        CoreInstruction::StageReceipt(receipt) => {
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_stage_receipt_data(&mut data, &receipt)
        }
        CoreInstruction::ConsumeReceipt(receipt) => {
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_consume_receipt_data(&mut data, &receipt)
        }
        CoreInstruction::OpenSession(receipt) => {
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_open_session_data(&mut data, &receipt)
        }
        CoreInstruction::ActivateSession(action_hash) => {
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_activate_session_data(&mut data, action_hash)
        }
        CoreInstruction::RotateAuthority(statement) => {
            let account = get_account_info!(accounts, 0);
            require_writable(account)?;
            require_program_owner(program_id, account)?;
            let mut data = account.try_borrow_mut_data()?;
            process_rotate_authority_data(&mut data, &statement)
        }
    }
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

pub fn process_stage_receipt_data(dst: &mut [u8], receipt: &PolicyReceipt) -> ProgramResult {
    if dst.len() != PolicyReceiptState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = transition::stage_policy_receipt(receipt);
    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_consume_receipt_data(dst: &mut [u8], receipt: &PolicyReceipt) -> ProgramResult {
    if dst.len() != PolicyReceiptState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = PolicyReceiptState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &POLICY_RECEIPT_DISCRIMINATOR)?;
    transition::consume_policy_receipt(&mut state, receipt)
        .map_err(map_transition_error)?;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_open_session_data(dst: &mut [u8], receipt: &PolicyReceipt) -> ProgramResult {
    if dst.len() != ActionSessionState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = transition::open_action_session(receipt);
    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_activate_session_data(dst: &mut [u8], action_hash: [u8; 32]) -> ProgramResult {
    if dst.len() != ActionSessionState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = ActionSessionState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &ACTION_SESSION_DISCRIMINATOR)?;
    transition::mark_action_session_ready(&mut state, action_hash)
        .map_err(map_transition_error)?;

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_rotate_authority_data(
    dst: &mut [u8],
    statement: &AuthorityRotationStatement,
) -> ProgramResult {
    if dst.len() != QuantumAuthorityState::LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let mut state = QuantumAuthorityState::decode(dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &QUANTUM_STATE_DISCRIMINATOR)?;
    transition::apply_authority_rotation(&mut state, statement)
        .map_err(map_transition_error)?;

    if !state.encode(dst) {
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

fn map_transition_error(error: transition::TransitionError) -> ProgramError {
    match error {
        transition::TransitionError::ReceiptAlreadyConsumed => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::ReceiptMismatch => ProgramError::InvalidAccountData,
        transition::TransitionError::SessionMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::SessionNotPending => ProgramError::AccountAlreadyInitialized,
        transition::TransitionError::AuthoritySequenceMismatch => ProgramError::InvalidArgument,
    }
}

#[cfg(test)]
mod tests {
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{ActionDescriptor, ActionKind, PolicyReceipt, ThresholdRequirement};

    use super::{
        process_activate_session_data, process_consume_receipt_data, process_init_vault_data,
        process_open_session_data, process_rotate_authority_data, process_stage_receipt_data,
    };
    use crate::{
        instruction::InitVaultArgs,
        state::{
            ActionSessionState, PolicyReceiptState, QuantumAuthorityState, SessionStatus,
            VaultRegistry, ACTION_SESSION_DISCRIMINATOR,
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
    fn stage_and_consume_receipt_updates_consumed_flag() {
        let receipt = sample_receipt();
        let mut bytes = [0; PolicyReceiptState::LEN];

        process_stage_receipt_data(&mut bytes, &receipt).expect("stage should succeed");
        process_consume_receipt_data(&mut bytes, &receipt).expect("consume should succeed");

        let state = PolicyReceiptState::decode(&bytes).expect("state should decode");
        assert_eq!(state.consumed, 1);
    }

    #[test]
    fn rotate_authority_updates_current_hash() {
        let mut bytes = [0; QuantumAuthorityState::LEN];
        let initial = QuantumAuthorityState::new([7; 32], 1);
        assert!(initial.encode(&mut bytes));

        process_rotate_authority_data(
            &mut bytes,
            &vaulkyrie_protocol::AuthorityRotationStatement {
                action_hash: sample_action_hash(),
                next_authority_hash: [8; 32],
                sequence: 0,
                expiry_slot: 200,
            },
        )
        .expect("rotation should succeed");

        let state = QuantumAuthorityState::decode(&bytes).expect("state should decode");
        assert_eq!(state.current_authority_hash, [8; 32]);
        assert_eq!(state.next_sequence, 1);
    }

    #[test]
    fn open_session_writes_encoded_state() {
        let receipt = sample_receipt();
        let mut bytes = [0; ActionSessionState::LEN];

        process_open_session_data(&mut bytes, &receipt).expect("open session should succeed");

        let state = ActionSessionState::decode(&bytes).expect("state should decode");
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
        let mut bytes = [0; ActionSessionState::LEN];

        process_open_session_data(&mut bytes, &receipt).expect("open session should succeed");
        process_activate_session_data(&mut bytes, receipt.action_hash)
            .expect("activate session should succeed");

        let state = ActionSessionState::decode(&bytes).expect("state should decode");
        assert_eq!(state.status, SessionStatus::Ready as u8);
    }

    #[test]
    fn activate_session_rejects_wrong_discriminator() {
        let mut bytes = [0; ActionSessionState::LEN];
        bytes[..8].copy_from_slice(b"BADTYPE1");

        let error = process_activate_session_data(&mut bytes, [7; 32])
            .expect_err("wrong discriminator should fail");

        assert_eq!(error, ProgramError::InvalidAccountData);
    }

    #[test]
    fn activate_session_rejects_wrong_action_hash() {
        let receipt = sample_receipt();
        let mut bytes = [0; ActionSessionState::LEN];

        process_open_session_data(&mut bytes, &receipt).expect("open session should succeed");
        let error = process_activate_session_data(&mut bytes, [9; 32])
            .expect_err("wrong action hash should fail");

        assert_eq!(error, ProgramError::InvalidArgument);
    }

    #[test]
    fn open_session_writes_expected_discriminator() {
        let receipt = sample_receipt();
        let mut bytes = [0; ActionSessionState::LEN];

        process_open_session_data(&mut bytes, &receipt).expect("open session should succeed");

        assert_eq!(&bytes[..8], &ACTION_SESSION_DISCRIMINATOR);
    }
}
