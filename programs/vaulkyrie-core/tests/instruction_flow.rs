use core::mem::size_of;

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use vaulkyrie_core::{
    pda, process_instruction,
    processor::set_host_test_slot,
    state::{
        ActionSessionState, OrchestrationStatus, PolicyReceiptState, RecoveryState, RecoveryStatus,
        SpendOrchestrationState, VaultRegistry, VaultStatus,
    },
};
use vaulkyrie_protocol::{PolicyReceipt, ThresholdRequirement};

const PROGRAM_ID: Pubkey = [9; 32];
const WALLET: Pubkey = [0xAA; 32];
const AUTH_HASH: [u8; 32] = [0xBB; 32];
const MXE_PROGRAM: [u8; 32] = [0xCC; 32];
const ACTION_HASH: [u8; 32] = [0x11; 32];
const CURRENT_SLOT: u64 = 100;
const FUTURE_SLOT: u64 = 10_000;

#[repr(C)]
struct TestAccountHeader {
    borrow_state: u8,
    is_signer: u8,
    is_writable: u8,
    executable: u8,
    original_data_len: u32,
    key: Pubkey,
    owner: Pubkey,
    lamports: u64,
    data_len: u64,
}

struct TestAccount {
    _storage: Box<[u8]>,
    info: AccountInfo,
}

impl TestAccount {
    fn new(
        key: Pubkey,
        owner: Pubkey,
        lamports: u64,
        data_len: usize,
        is_signer: bool,
        is_writable: bool,
    ) -> Self {
        let mut storage = vec![0u8; size_of::<TestAccountHeader>() + data_len].into_boxed_slice();
        let header = storage.as_mut_ptr() as *mut TestAccountHeader;

        unsafe {
            *header = TestAccountHeader {
                borrow_state: 0,
                is_signer: u8::from(is_signer),
                is_writable: u8::from(is_writable),
                executable: 0,
                original_data_len: data_len as u32,
                key,
                owner,
                lamports,
                data_len: data_len as u64,
            };
        }

        let info = unsafe { core::mem::transmute::<*mut TestAccountHeader, AccountInfo>(header) };
        Self {
            _storage: storage,
            info,
        }
    }

    fn info(&self) -> AccountInfo {
        self.info.clone()
    }
}

fn process(ix_data: &[u8], accounts: &[AccountInfo]) {
    process_instruction(&PROGRAM_ID, accounts, ix_data).expect("instruction should succeed");
}

fn encode_receipt_instruction(tag: u8, receipt: &PolicyReceipt) -> Vec<u8> {
    let mut data = Vec::with_capacity(58);
    data.push(tag);
    data.extend_from_slice(&receipt.action_hash);
    data.extend_from_slice(&receipt.policy_version.to_le_bytes());
    data.push(receipt.threshold as u8);
    data.extend_from_slice(&receipt.nonce.to_le_bytes());
    data.extend_from_slice(&receipt.expiry_slot.to_le_bytes());
    data
}

fn encode_action_hash_instruction(tag: u8, action_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(33);
    data.push(tag);
    data.extend_from_slice(action_hash);
    data
}

fn encode_init_vault() -> Vec<u8> {
    let mut data = Vec::with_capacity(106);
    data.push(1);
    data.extend_from_slice(&WALLET);
    data.extend_from_slice(&AUTH_HASH);
    data.extend_from_slice(&1u64.to_le_bytes());
    data.push(255);
    data.extend_from_slice(&MXE_PROGRAM);
    data
}

fn encode_set_vault_status(status: u8) -> Vec<u8> {
    vec![10, status]
}

fn encode_init_spend_orchestration(bump: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(140);
    data.push(17);
    data.extend_from_slice(&ACTION_HASH);
    data.extend_from_slice(&[2; 32]);
    data.extend_from_slice(&[3; 32]);
    data.extend_from_slice(&[4; 32]);
    data.extend_from_slice(&FUTURE_SLOT.to_le_bytes());
    data.push(2);
    data.push(3);
    data.push(bump);
    data
}

fn encode_commit_spend_orchestration() -> Vec<u8> {
    let mut data = Vec::with_capacity(65);
    data.push(18);
    data.extend_from_slice(&ACTION_HASH);
    data.extend_from_slice(&[5; 32]);
    data
}

fn encode_complete_spend_orchestration() -> Vec<u8> {
    let mut data = Vec::with_capacity(65);
    data.push(19);
    data.extend_from_slice(&ACTION_HASH);
    data.extend_from_slice(&[6; 32]);
    data
}

fn encode_init_recovery(vault_pubkey: &Pubkey) -> Vec<u8> {
    let mut data = Vec::with_capacity(76);
    data.push(22);
    data.extend_from_slice(vault_pubkey);
    data.extend_from_slice(&[7; 32]);
    data.extend_from_slice(&FUTURE_SLOT.to_le_bytes());
    data.push(2);
    data.push(3);
    data.push(1);
    data
}

fn encode_complete_recovery() -> Vec<u8> {
    let mut data = Vec::with_capacity(65);
    data.push(23);
    data.extend_from_slice(&[8; 32]);
    data.extend_from_slice(&[9; 32]);
    data
}

fn find_pda(mut derive: impl FnMut(u8) -> Result<Pubkey, ProgramError>) -> (Pubkey, u8) {
    for bump in (0..=u8::MAX).rev() {
        if let Ok(pubkey) = derive(bump) {
            return (pubkey, bump);
        }
    }
    panic!("failed to find PDA");
}

fn make_receipt(nonce: u64) -> PolicyReceipt {
    PolicyReceipt {
        action_hash: ACTION_HASH,
        policy_version: 1,
        threshold: ThresholdRequirement::TwoOfThree,
        nonce,
        expiry_slot: FUTURE_SLOT,
    }
}

fn init_vault_account() -> (TestAccount, TestAccount) {
    let (vault_key, vault_bump) =
        find_pda(|bump| pda::derive_vault_registry(&WALLET, bump, &PROGRAM_ID));
    let vault = TestAccount::new(
        vault_key,
        PROGRAM_ID,
        1_000_000,
        VaultRegistry::LEN,
        false,
        true,
    );
    let wallet = TestAccount::new(WALLET, [3; 32], 1_000_000, 0, true, true);
    let mut data = encode_init_vault();
    data[73] = vault_bump;
    process(&data, &[vault.info(), wallet.info()]);
    (vault, wallet)
}

fn make_finalized_eval_bytes(receipt: &PolicyReceipt) -> [u8; 256] {
    let mut bytes = [0u8; 256];
    bytes[0..8].copy_from_slice(b"POLEVAL1");
    bytes[72..104].copy_from_slice(&receipt.action_hash);
    bytes[168..200].copy_from_slice(&receipt.commitment());
    bytes[240] = 2;
    bytes
}

#[test]
fn receipt_session_instruction_flow_consumes_receipt() {
    set_host_test_slot(CURRENT_SLOT);
    let (vault, wallet) = init_vault_account();
    let vault_key = *vault.info().key();
    let receipt = make_receipt(7);

    let (receipt_key, _) = find_pda(|bump| {
        pda::derive_policy_receipt(&vault_key, &receipt.action_hash, bump, &PROGRAM_ID)
    });
    let receipt_account = TestAccount::new(
        receipt_key,
        PROGRAM_ID,
        1_000_000,
        PolicyReceiptState::LEN,
        false,
        true,
    );

    let (session_key, _) = find_pda(|bump| {
        pda::derive_action_session(&vault_key, &receipt.action_hash, bump, &PROGRAM_ID)
    });
    let session_account = TestAccount::new(
        session_key,
        PROGRAM_ID,
        1_000_000,
        ActionSessionState::LEN,
        false,
        true,
    );

    process(
        &encode_receipt_instruction(4, &receipt),
        &[vault.info(), receipt_account.info(), wallet.info()],
    );
    process(
        &encode_receipt_instruction(6, &receipt),
        &[
            receipt_account.info(),
            session_account.info(),
            vault.info(),
            wallet.info(),
        ],
    );
    process(
        &encode_action_hash_instruction(7, &ACTION_HASH),
        &[session_account.info(), vault.info(), wallet.info()],
    );
    process(
        &encode_receipt_instruction(9, &receipt),
        &[
            receipt_account.info(),
            session_account.info(),
            vault.info(),
            wallet.info(),
        ],
    );

    let vault_state = VaultRegistry::decode(&vault.info().try_borrow_data().unwrap()).unwrap();
    let receipt_state =
        PolicyReceiptState::decode(&receipt_account.info().try_borrow_data().unwrap()).unwrap();
    let session_state =
        ActionSessionState::decode(&session_account.info().try_borrow_data().unwrap()).unwrap();

    assert_eq!(vault_state.last_consumed_receipt_nonce, receipt.nonce);
    assert_eq!(receipt_state.consumed, 1);
    assert_eq!(session_state.status, 3);
}

#[test]
fn stage_bridged_receipt_instruction_flow_accepts_finalized_eval() {
    set_host_test_slot(CURRENT_SLOT);
    let (vault, wallet) = init_vault_account();
    let vault_key = *vault.info().key();
    let receipt = make_receipt(9);

    let (receipt_key, _) = find_pda(|bump| {
        pda::derive_policy_receipt(&vault_key, &receipt.action_hash, bump, &PROGRAM_ID)
    });
    let receipt_account = TestAccount::new(
        receipt_key,
        PROGRAM_ID,
        1_000_000,
        PolicyReceiptState::LEN,
        false,
        true,
    );
    let policy_eval = TestAccount::new([0x44; 32], MXE_PROGRAM, 1_000_000, 256, false, false);
    policy_eval
        .info()
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&make_finalized_eval_bytes(&receipt));

    process(
        &encode_receipt_instruction(21, &receipt),
        &[
            vault.info(),
            receipt_account.info(),
            wallet.info(),
            policy_eval.info(),
        ],
    );

    let receipt_state =
        PolicyReceiptState::decode(&receipt_account.info().try_borrow_data().unwrap()).unwrap();
    assert_eq!(receipt_state.action_hash, receipt.action_hash);
    assert_eq!(receipt_state.nonce, receipt.nonce);
}

#[test]
fn spend_orchestration_instruction_flow_reaches_complete() {
    set_host_test_slot(CURRENT_SLOT);
    let (vault, wallet) = init_vault_account();
    let vault_key = *vault.info().key();

    let (orch_key, orch_bump) = find_pda(|bump| {
        pda::derive_spend_orchestration(&vault_key, &ACTION_HASH, bump, &PROGRAM_ID)
    });
    let orch_account = TestAccount::new(
        orch_key,
        PROGRAM_ID,
        1_000_000,
        SpendOrchestrationState::LEN,
        false,
        true,
    );

    process(
        &encode_init_spend_orchestration(orch_bump),
        &[orch_account.info(), vault.info(), wallet.info()],
    );
    process(
        &encode_commit_spend_orchestration(),
        &[orch_account.info(), vault.info(), wallet.info()],
    );
    process(
        &encode_complete_spend_orchestration(),
        &[orch_account.info(), vault.info(), wallet.info()],
    );

    let state =
        SpendOrchestrationState::decode(&orch_account.info().try_borrow_data().unwrap()).unwrap();
    assert_eq!(state.status, OrchestrationStatus::Complete as u8);
    assert_eq!(state.tx_binding, [6; 32]);
}

#[test]
fn recovery_instruction_flow_reaches_complete() {
    set_host_test_slot(CURRENT_SLOT);
    let (vault, wallet) = init_vault_account();
    let vault_key = *vault.info().key();

    process(
        &encode_set_vault_status(VaultStatus::Recovery as u8),
        &[vault.info(), wallet.info()],
    );

    let recovery_account = TestAccount::new(
        [0x55; 32],
        PROGRAM_ID,
        1_000_000,
        RecoveryState::LEN,
        false,
        true,
    );
    process(
        &encode_init_recovery(&vault_key),
        &[recovery_account.info(), vault.info()],
    );
    process(&encode_complete_recovery(), &[recovery_account.info()]);

    let recovery =
        RecoveryState::decode(&recovery_account.info().try_borrow_data().unwrap()).unwrap();
    assert_eq!(recovery.status, RecoveryStatus::Complete as u8);
    assert_eq!(recovery.new_group_key, [8; 32]);
    assert_eq!(recovery.new_authority_hash, [9; 32]);
}
