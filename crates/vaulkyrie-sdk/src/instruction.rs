//! Instruction builders for all `vaulkyrie-core` instructions.
//!
//! Each function returns a `solana_instruction::Instruction` with the correct
//! wire-format data and `AccountMeta` list matching the on-chain processor
//! expectations.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use vaulkyrie_protocol::{
    AuthorityRotationStatement, WinterAuthorityAdvanceStatement, WinterAuthoritySignature,
    WotsAuthProof, AUTHORITY_PROOF_CHUNK_MAX_BYTES,
};

// ─── Discriminators ──────────────────────────────────────────────────────────
const DISC_PING: u8 = 0;
const DISC_INIT_VAULT: u8 = 1;
const DISC_INIT_AUTHORITY: u8 = 2;
const DISC_INIT_QUANTUM_VAULT: u8 = 3;
const DISC_SET_VAULT_STATUS: u8 = 10;
const DISC_ROTATE_AUTHORITY: u8 = 11;
const DISC_INIT_AUTHORITY_PROOF: u8 = 12;
const DISC_WRITE_PROOF_CHUNK: u8 = 13;
const DISC_ROTATE_AUTHORITY_STAGED: u8 = 14;
const DISC_SPLIT_QUANTUM_VAULT: u8 = 15;
const DISC_CLOSE_QUANTUM_VAULT: u8 = 16;
const DISC_INIT_SPEND_ORCH: u8 = 17;
const DISC_COMMIT_SPEND_ORCH: u8 = 18;
const DISC_COMPLETE_SPEND_ORCH: u8 = 19;
const DISC_FAIL_SPEND_ORCH: u8 = 20;
const DISC_INIT_RECOVERY: u8 = 22;
const DISC_COMPLETE_RECOVERY: u8 = 23;
const DISC_MIGRATE_AUTHORITY: u8 = 24;
const DISC_ADVANCE_WINTER_AUTHORITY: u8 = 26;
const DISC_INIT_PQC_WALLET: u8 = 27;
const DISC_ADVANCE_PQC_WALLET: u8 = 28;

fn serialize_authority_rotation_statement(stmt: &AuthorityRotationStatement) -> Vec<u8> {
    let mut v = Vec::with_capacity(80);
    v.extend_from_slice(&stmt.action_hash);
    v.extend_from_slice(&stmt.next_authority_hash);
    v.extend_from_slice(&stmt.sequence.to_le_bytes());
    v.extend_from_slice(&stmt.expiry_slot.to_le_bytes());
    v
}

fn serialize_winter_authority_advance_statement(stmt: &WinterAuthorityAdvanceStatement) -> Vec<u8> {
    let mut v = Vec::with_capacity(112);
    v.extend_from_slice(&stmt.action_hash);
    v.extend_from_slice(&stmt.current_root);
    v.extend_from_slice(&stmt.next_root);
    v.extend_from_slice(&stmt.sequence.to_le_bytes());
    v.extend_from_slice(&stmt.expiry_slot.to_le_bytes());
    v
}

// ─── 0: Ping ─────────────────────────────────────────────────────────────────

pub fn ping(program_id: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(*program_id, &[DISC_PING], vec![])
}

// ─── 1: InitVault ────────────────────────────────────────────────────────────

pub fn init_vault(
    program_id: &Pubkey,
    vault_registry: &Pubkey,
    wallet_signer: &Pubkey,
    wallet_pubkey: [u8; 32],
    authority_hash: [u8; 32],
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 65);
    data.push(DISC_INIT_VAULT);
    data.extend_from_slice(&wallet_pubkey);
    data.extend_from_slice(&authority_hash);
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*vault_registry, false),
            AccountMeta::new(*wallet_signer, true),
            AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
        ],
    )
}

// ─── 2: InitAuthority ────────────────────────────────────────────────────────

pub fn init_authority(
    program_id: &Pubkey,
    authority: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    current_authority_hash: [u8; 32],
    current_authority_root: [u8; 32],
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 65);
    data.push(DISC_INIT_AUTHORITY);
    data.extend_from_slice(&current_authority_hash);
    data.extend_from_slice(&current_authority_root);
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*authority, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new(*wallet_signer, true),
            AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
        ],
    )
}

// ─── 3: InitQuantumVault ─────────────────────────────────────────────────────

pub fn init_quantum_vault(
    program_id: &Pubkey,
    vault: &Pubkey,
    hash: [u8; 32],
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 33);
    data.push(DISC_INIT_QUANTUM_VAULT);
    data.extend_from_slice(&hash);
    data.push(bump);

    Instruction::new_with_bytes(*program_id, &data, vec![AccountMeta::new(*vault, false)])
}

// ─── 27: InitPqcWallet ──────────────────────────────────────────────────────

pub fn init_pqc_wallet(
    program_id: &Pubkey,
    payer: &Pubkey,
    wallet: &Pubkey,
    wallet_id: [u8; 32],
    current_root: [u8; 32],
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 65);
    data.push(DISC_INIT_PQC_WALLET);
    data.extend_from_slice(&wallet_id);
    data.extend_from_slice(&current_root);
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*wallet, false),
            AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
        ],
    )
}

// ─── 10: SetVaultStatus ──────────────────────────────────────────────────────

pub fn set_vault_status(
    program_id: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    status: u8,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[DISC_SET_VAULT_STATUS, status],
        vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 11: RotateAuthority ─────────────────────────────────────────────────────

pub fn rotate_authority(
    program_id: &Pubkey,
    vault: &Pubkey,
    authority: &Pubkey,
    wallet_signer: &Pubkey,
    statement: &AuthorityRotationStatement,
    proof: &WotsAuthProof,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 80 + WotsAuthProof::ENCODED_LEN);
    data.push(DISC_ROTATE_AUTHORITY);
    data.extend_from_slice(&serialize_authority_rotation_statement(statement));
    let mut proof_buf = vec![0u8; WotsAuthProof::ENCODED_LEN];
    proof.encode(&mut proof_buf);
    data.extend_from_slice(&proof_buf);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new(*authority, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 12: InitAuthorityProof ──────────────────────────────────────────────────

pub fn init_authority_proof(
    program_id: &Pubkey,
    proof_account: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    statement_digest: [u8; 32],
    proof_commitment: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 64);
    data.push(DISC_INIT_AUTHORITY_PROOF);
    data.extend_from_slice(&statement_digest);
    data.extend_from_slice(&proof_commitment);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*proof_account, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 13: WriteAuthorityProofChunk ────────────────────────────────────────────

pub fn write_authority_proof_chunk(
    program_id: &Pubkey,
    proof_account: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    offset: u32,
    chunk: &[u8],
) -> Instruction {
    assert!(
        !chunk.is_empty() && chunk.len() <= AUTHORITY_PROOF_CHUNK_MAX_BYTES,
        "chunk must be 1..={AUTHORITY_PROOF_CHUNK_MAX_BYTES} bytes"
    );

    let chunk_len = chunk.len() as u16;
    let mut data = Vec::with_capacity(1 + 6 + chunk.len());
    data.push(DISC_WRITE_PROOF_CHUNK);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(&chunk_len.to_le_bytes());
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*proof_account, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 14: RotateAuthorityStaged ───────────────────────────────────────────────

pub fn rotate_authority_staged(
    program_id: &Pubkey,
    vault: &Pubkey,
    authority: &Pubkey,
    proof_account: &Pubkey,
    wallet_signer: &Pubkey,
    statement: &AuthorityRotationStatement,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 80);
    data.push(DISC_ROTATE_AUTHORITY_STAGED);
    data.extend_from_slice(&serialize_authority_rotation_statement(statement));

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new(*authority, false),
            AccountMeta::new(*proof_account, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 26: AdvanceWinterAuthority ──────────────────────────────────────────────

pub fn advance_winter_authority(
    program_id: &Pubkey,
    vault: &Pubkey,
    authority: &Pubkey,
    wallet_signer: &Pubkey,
    statement: &WinterAuthorityAdvanceStatement,
    signature: &WinterAuthoritySignature,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 112 + WinterAuthoritySignature::ENCODED_LEN);
    data.push(DISC_ADVANCE_WINTER_AUTHORITY);
    data.extend_from_slice(&serialize_winter_authority_advance_statement(statement));
    data.extend_from_slice(&signature.scalars);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new(*authority, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 15: SplitQuantumVault ───────────────────────────────────────────────────

pub fn split_quantum_vault(
    program_id: &Pubkey,
    vault: &Pubkey,
    split_dest: &Pubkey,
    refund_dest: &Pubkey,
    signature: &[u8],
    amount: u64,
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + signature.len() + 9);
    data.push(DISC_SPLIT_QUANTUM_VAULT);
    data.extend_from_slice(signature);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new(*split_dest, false),
            AccountMeta::new(*refund_dest, false),
        ],
    )
}

// ─── 16: CloseQuantumVault ───────────────────────────────────────────────────

pub fn close_quantum_vault(
    program_id: &Pubkey,
    vault: &Pubkey,
    refund_dest: &Pubkey,
    signature: &[u8],
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + signature.len() + 1);
    data.push(DISC_CLOSE_QUANTUM_VAULT);
    data.extend_from_slice(signature);
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*vault, false),
            AccountMeta::new(*refund_dest, false),
        ],
    )
}

// ─── 28: AdvancePqcWallet ───────────────────────────────────────────────────

pub fn advance_pqc_wallet(
    program_id: &Pubkey,
    wallet: &Pubkey,
    destination: &Pubkey,
    signature: &[u8],
    next_root: [u8; 32],
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + signature.len() + 40);
    data.push(DISC_ADVANCE_PQC_WALLET);
    data.extend_from_slice(signature);
    data.extend_from_slice(&next_root);
    data.extend_from_slice(&amount.to_le_bytes());

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*wallet, false),
            AccountMeta::new(*destination, false),
        ],
    )
}

// ─── 17: InitSpendOrchestration ──────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn init_spend_orchestration(
    program_id: &Pubkey,
    orch_account: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    action_hash: [u8; 32],
    session_commitment: [u8; 32],
    signers_commitment: [u8; 32],
    signing_package_hash: [u8; 32],
    expiry_slot: u64,
    threshold: u8,
    participant_count: u8,
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 139);
    data.push(DISC_INIT_SPEND_ORCH);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&session_commitment);
    data.extend_from_slice(&signers_commitment);
    data.extend_from_slice(&signing_package_hash);
    data.extend_from_slice(&expiry_slot.to_le_bytes());
    data.push(threshold);
    data.push(participant_count);
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*orch_account, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new(*wallet_signer, true),
            AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
        ],
    )
}

// ─── 18: CommitSpendOrchestration ────────────────────────────────────────────

pub fn commit_spend_orchestration(
    program_id: &Pubkey,
    orch_account: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    action_hash: [u8; 32],
    signing_package_hash: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 64);
    data.push(DISC_COMMIT_SPEND_ORCH);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&signing_package_hash);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*orch_account, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 19: CompleteSpendOrchestration ──────────────────────────────────────────

pub fn complete_spend_orchestration(
    program_id: &Pubkey,
    orch_account: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    action_hash: [u8; 32],
    tx_binding: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 64);
    data.push(DISC_COMPLETE_SPEND_ORCH);
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(&tx_binding);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*orch_account, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 20: FailSpendOrchestration ──────────────────────────────────────────────

pub fn fail_spend_orchestration(
    program_id: &Pubkey,
    orch_account: &Pubkey,
    vault: &Pubkey,
    wallet_signer: &Pubkey,
    action_hash: [u8; 32],
    reason_code: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 33);
    data.push(DISC_FAIL_SPEND_ORCH);
    data.extend_from_slice(&action_hash);
    data.push(reason_code);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*orch_account, false),
            AccountMeta::new_readonly(*vault, false),
            AccountMeta::new_readonly(*wallet_signer, true),
        ],
    )
}

// ─── 22: InitRecovery ────────────────────────────────────────────────────────

pub fn init_recovery(
    program_id: &Pubkey,
    recovery_account: &Pubkey,
    vault: &Pubkey,
    vault_pubkey: [u8; 32],
    recovery_commitment: [u8; 32],
    expiry_slot: u64,
    new_threshold: u8,
    new_participant_count: u8,
    bump: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 75);
    data.push(DISC_INIT_RECOVERY);
    data.extend_from_slice(&vault_pubkey);
    data.extend_from_slice(&recovery_commitment);
    data.extend_from_slice(&expiry_slot.to_le_bytes());
    data.push(new_threshold);
    data.push(new_participant_count);
    data.push(bump);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new(*recovery_account, false),
            AccountMeta::new_readonly(*vault, false),
        ],
    )
}

// ─── 23: CompleteRecovery ────────────────────────────────────────────────────

pub fn complete_recovery(
    program_id: &Pubkey,
    recovery_account: &Pubkey,
    new_group_key: [u8; 32],
    new_authority_hash: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 64);
    data.push(DISC_COMPLETE_RECOVERY);
    data.extend_from_slice(&new_group_key);
    data.extend_from_slice(&new_authority_hash);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new(*recovery_account, false)],
    )
}

// ─── 24: MigrateAuthority ────────────────────────────────────────────────────

pub fn migrate_authority(
    program_id: &Pubkey,
    authority: &Pubkey,
    new_authority_root: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 32);
    data.push(DISC_MIGRATE_AUTHORITY);
    data.extend_from_slice(&new_authority_root);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new(*authority, false)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> Pubkey {
        Pubkey::from([1u8; 32])
    }

    fn key(b: u8) -> Pubkey {
        Pubkey::from([b; 32])
    }

    #[test]
    fn ping_produces_single_byte() {
        let ix = ping(&pid());
        assert_eq!(ix.data, vec![0]);
        assert!(ix.accounts.is_empty());
    }

    #[test]
    fn init_vault_serializes_correctly() {
        let ix = init_vault(&pid(), &key(2), &key(3), [7; 32], [9; 32], 3);
        assert_eq!(ix.data[0], 1);
        assert_eq!(ix.data.len(), 1 + 65);
        assert_eq!(ix.accounts.len(), 3);
        assert!(ix.accounts[0].is_writable);
        assert!(ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[2].pubkey, Pubkey::from([0u8; 32]));
    }

    #[test]
    fn init_authority_serializes_correctly() {
        let ix = init_authority(&pid(), &key(2), &key(3), &key(4), [5; 32], [6; 32], 1);
        assert_eq!(ix.data[0], 2);
        assert_eq!(ix.data.len(), 1 + 65);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[0].is_writable);
        assert!(ix.accounts[2].is_signer);
        assert!(ix.accounts[2].is_writable);
        assert_eq!(ix.accounts[3].pubkey, Pubkey::from([0u8; 32]));
    }

    #[test]
    fn set_vault_status_serializes_correctly() {
        let ix = set_vault_status(&pid(), &key(2), &key(3), 2);
        assert_eq!(ix.data, vec![10, 2]);
    }

    #[test]
    fn init_authority_proof_serializes_correctly() {
        let ix = init_authority_proof(&pid(), &key(2), &key(3), &key(4), [5; 32], [6; 32]);
        assert_eq!(ix.data[0], 12);
        assert_eq!(ix.data.len(), 1 + 64);
    }

    #[test]
    fn write_proof_chunk_serializes_correctly() {
        let chunk = vec![0xAB; 100];
        let ix = write_authority_proof_chunk(&pid(), &key(2), &key(3), &key(4), 0, &chunk);
        assert_eq!(ix.data[0], 13);
        // 1 (disc) + 4 (offset) + 2 (chunk_len) + 100 (chunk)
        assert_eq!(ix.data.len(), 1 + 4 + 2 + 100);
    }

    #[test]
    fn init_spend_orch_serializes_correctly() {
        let ix = init_spend_orchestration(
            &pid(),
            &key(2),
            &key(3),
            &key(4),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            100,
            2,
            3,
            7,
        );
        assert_eq!(ix.data[0], 17);
        assert_eq!(ix.data.len(), 1 + 139);
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts[3].pubkey, Pubkey::from([0u8; 32]));
    }

    #[test]
    fn commit_spend_orch_serializes_correctly() {
        let ix = commit_spend_orchestration(&pid(), &key(2), &key(3), &key(4), [1; 32], [2; 32]);
        assert_eq!(ix.data[0], 18);
        assert_eq!(ix.data.len(), 1 + 64);
    }

    #[test]
    fn complete_spend_orch_serializes_correctly() {
        let ix = complete_spend_orchestration(&pid(), &key(2), &key(3), &key(4), [1; 32], [2; 32]);
        assert_eq!(ix.data[0], 19);
        assert_eq!(ix.data.len(), 1 + 64);
    }

    #[test]
    fn fail_spend_orch_serializes_correctly() {
        let ix = fail_spend_orchestration(&pid(), &key(2), &key(3), &key(4), [1; 32], 42);
        assert_eq!(ix.data[0], 20);
        assert_eq!(ix.data.len(), 1 + 33);
    }

    #[test]
    fn init_recovery_serializes_correctly() {
        let ix = init_recovery(&pid(), &key(2), &key(3), [1; 32], [2; 32], 500, 2, 3, 5);
        assert_eq!(ix.data[0], 22);
        assert_eq!(ix.data.len(), 1 + 75);
    }

    #[test]
    fn complete_recovery_serializes_correctly() {
        let ix = complete_recovery(&pid(), &key(2), [3; 32], [4; 32]);
        assert_eq!(ix.data[0], 23);
        assert_eq!(ix.data.len(), 1 + 64);
    }

    #[test]
    fn migrate_authority_serializes_correctly() {
        let ix = migrate_authority(&pid(), &key(2), [5; 32]);
        assert_eq!(ix.data[0], 24);
        assert_eq!(ix.data.len(), 1 + 32);
    }

    #[test]
    fn advance_winter_authority_serializes_correctly() {
        let statement = WinterAuthorityAdvanceStatement {
            action_hash: [1; 32],
            current_root: [2; 32],
            next_root: [3; 32],
            sequence: 4,
            expiry_slot: 5,
        };
        let signature = WinterAuthoritySignature {
            scalars: [6; WinterAuthoritySignature::ENCODED_LEN],
        };
        let ix =
            advance_winter_authority(&pid(), &key(2), &key(3), &key(4), &statement, &signature);

        assert_eq!(ix.data[0], 26);
        assert_eq!(
            ix.data.len(),
            1 + 112 + WinterAuthoritySignature::ENCODED_LEN
        );
        assert_eq!(ix.accounts.len(), 3);
        assert!(ix.accounts[0].is_writable);
        assert!(ix.accounts[1].is_writable);
        assert!(ix.accounts[2].is_signer);
    }
}
