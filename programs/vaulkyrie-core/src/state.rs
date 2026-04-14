use core::mem::size_of;
use vaulkyrie_protocol::WotsAuthProof;

pub const VAULT_REGISTRY_DISCRIMINATOR: [u8; 8] = *b"VAULKYR1";
pub const POLICY_RECEIPT_DISCRIMINATOR: [u8; 8] = *b"POLRCPT1";
pub const ACTION_SESSION_DISCRIMINATOR: [u8; 8] = *b"SESSION1";
pub const QUANTUM_STATE_DISCRIMINATOR: [u8; 8] = *b"QSTATE01";
pub const AUTHORITY_PROOF_DISCRIMINATOR: [u8; 8] = *b"AUTHPRF1";
pub const SPEND_ORCH_DISCRIMINATOR: [u8; 8] = *b"SPNDORC1";
pub const RECOVERY_STATE_DISCRIMINATOR: [u8; 8] = *b"RECOV001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VaultStatus {
    Active = 1,
    Recovery = 2,
    Locked = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus {
    Pending = 1,
    Ready = 2,
    Consumed = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VaultRegistry {
    pub discriminator: [u8; 8],
    pub wallet_pubkey: [u8; 32],
    pub current_authority_hash: [u8; 32],
    pub policy_version: u64,
    pub last_consumed_receipt_nonce: u64,
    pub status: u8,
    pub bump: u8,
    pub policy_mxe_program: [u8; 32],
    pub reserved: [u8; 6],
}

impl VaultRegistry {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        wallet_pubkey: [u8; 32],
        current_authority_hash: [u8; 32],
        policy_version: u64,
        status: VaultStatus,
        bump: u8,
        policy_mxe_program: [u8; 32],
    ) -> Self {
        Self {
            discriminator: VAULT_REGISTRY_DISCRIMINATOR,
            wallet_pubkey,
            current_authority_hash,
            policy_version,
            last_consumed_receipt_nonce: 0,
            status: status as u8,
            bump,
            policy_mxe_program,
            reserved: [0; 6],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.wallet_pubkey);
        dst[40..72].copy_from_slice(&self.current_authority_hash);
        dst[72..80].copy_from_slice(&self.policy_version.to_le_bytes());
        dst[80..88].copy_from_slice(&self.last_consumed_receipt_nonce.to_le_bytes());
        dst[88] = self.status;
        dst[89] = self.bump;
        dst[90..122].copy_from_slice(&self.policy_mxe_program);
        dst[122..128].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != VAULT_REGISTRY_DISCRIMINATOR {
            return None;
        }

        let mut wallet_pubkey = [0; 32];
        wallet_pubkey.copy_from_slice(&src[8..40]);

        let mut current_authority_hash = [0; 32];
        current_authority_hash.copy_from_slice(&src[40..72]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[72..80]);

        let mut last_consumed_receipt_nonce = [0; 8];
        last_consumed_receipt_nonce.copy_from_slice(&src[80..88]);

        let mut policy_mxe_program = [0; 32];
        policy_mxe_program.copy_from_slice(&src[90..122]);

        let mut reserved = [0; 6];
        reserved.copy_from_slice(&src[122..128]);

        Some(Self {
            discriminator,
            wallet_pubkey,
            current_authority_hash,
            policy_version: u64::from_le_bytes(policy_version),
            last_consumed_receipt_nonce: u64::from_le_bytes(last_consumed_receipt_nonce),
            status: src[88],
            bump: src[89],
            policy_mxe_program,
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyReceiptState {
    pub discriminator: [u8; 8],
    pub receipt_commitment: [u8; 32],
    pub action_hash: [u8; 32],
    pub nonce: u64,
    pub expiry_slot: u64,
    pub consumed: u8,
    pub reserved: [u8; 7],
}

impl PolicyReceiptState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        receipt_commitment: [u8; 32],
        action_hash: [u8; 32],
        nonce: u64,
        expiry_slot: u64,
    ) -> Self {
        Self {
            discriminator: POLICY_RECEIPT_DISCRIMINATOR,
            receipt_commitment,
            action_hash,
            nonce,
            expiry_slot,
            consumed: 0,
            reserved: [0; 7],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.receipt_commitment);
        dst[40..72].copy_from_slice(&self.action_hash);
        dst[72..80].copy_from_slice(&self.nonce.to_le_bytes());
        dst[80..88].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[88] = self.consumed;
        dst[89..96].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != POLICY_RECEIPT_DISCRIMINATOR {
            return None;
        }

        let mut receipt_commitment = [0; 32];
        receipt_commitment.copy_from_slice(&src[8..40]);

        let mut action_hash = [0; 32];
        action_hash.copy_from_slice(&src[40..72]);

        let mut nonce = [0; 8];
        nonce.copy_from_slice(&src[72..80]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[80..88]);

        let mut reserved = [0; 7];
        reserved.copy_from_slice(&src[89..96]);

        Some(Self {
            discriminator,
            receipt_commitment,
            action_hash,
            nonce: u64::from_le_bytes(nonce),
            expiry_slot: u64::from_le_bytes(expiry_slot),
            consumed: src[88],
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ActionSessionState {
    pub discriminator: [u8; 8],
    pub receipt_commitment: [u8; 32],
    pub action_hash: [u8; 32],
    pub policy_version: u64,
    pub expiry_slot: u64,
    pub threshold: u8,
    pub status: u8,
    pub reserved: [u8; 6],
}

impl ActionSessionState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        receipt_commitment: [u8; 32],
        action_hash: [u8; 32],
        policy_version: u64,
        expiry_slot: u64,
        threshold: u8,
    ) -> Self {
        Self {
            discriminator: ACTION_SESSION_DISCRIMINATOR,
            receipt_commitment,
            action_hash,
            policy_version,
            expiry_slot,
            threshold,
            status: SessionStatus::Pending as u8,
            reserved: [0; 6],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.receipt_commitment);
        dst[40..72].copy_from_slice(&self.action_hash);
        dst[72..80].copy_from_slice(&self.policy_version.to_le_bytes());
        dst[80..88].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[88] = self.threshold;
        dst[89] = self.status;
        dst[90..96].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != ACTION_SESSION_DISCRIMINATOR {
            return None;
        }

        let mut receipt_commitment = [0; 32];
        receipt_commitment.copy_from_slice(&src[8..40]);

        let mut action_hash = [0; 32];
        action_hash.copy_from_slice(&src[40..72]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[72..80]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[80..88]);

        let mut reserved = [0; 6];
        reserved.copy_from_slice(&src[90..96]);

        Some(Self {
            discriminator,
            receipt_commitment,
            action_hash,
            policy_version: u64::from_le_bytes(policy_version),
            expiry_slot: u64::from_le_bytes(expiry_slot),
            threshold: src[88],
            status: src[89],
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct QuantumAuthorityState {
    pub discriminator: [u8; 8],
    pub current_authority_hash: [u8; 32],
    pub current_authority_root: [u8; 32],
    pub last_consumed_digest: [u8; 32],
    pub next_sequence: u64,
    pub next_leaf_index: u32,
    pub bump: u8,
    pub reserved: [u8; 11],
}

impl QuantumAuthorityState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        current_authority_hash: [u8; 32],
        current_authority_root: [u8; 32],
        bump: u8,
    ) -> Self {
        Self {
            discriminator: QUANTUM_STATE_DISCRIMINATOR,
            current_authority_hash,
            current_authority_root,
            last_consumed_digest: [0; 32],
            next_sequence: 0,
            next_leaf_index: 0,
            bump,
            reserved: [0; 11],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.current_authority_hash);
        dst[40..72].copy_from_slice(&self.current_authority_root);
        dst[72..104].copy_from_slice(&self.last_consumed_digest);
        dst[104..112].copy_from_slice(&self.next_sequence.to_le_bytes());
        dst[112..116].copy_from_slice(&self.next_leaf_index.to_le_bytes());
        dst[116] = self.bump;
        dst[117..128].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != QUANTUM_STATE_DISCRIMINATOR {
            return None;
        }

        let mut current_authority_hash = [0; 32];
        current_authority_hash.copy_from_slice(&src[8..40]);

        let mut current_authority_root = [0; 32];
        current_authority_root.copy_from_slice(&src[40..72]);

        let mut last_consumed_digest = [0; 32];
        last_consumed_digest.copy_from_slice(&src[72..104]);

        let mut next_sequence = [0; 8];
        next_sequence.copy_from_slice(&src[104..112]);

        let mut next_leaf_index = [0; 4];
        next_leaf_index.copy_from_slice(&src[112..116]);

        let mut reserved = [0; 11];
        reserved.copy_from_slice(&src[117..128]);

        Some(Self {
            discriminator,
            current_authority_hash,
            current_authority_root,
            last_consumed_digest,
            next_sequence: u64::from_le_bytes(next_sequence),
            next_leaf_index: u32::from_le_bytes(next_leaf_index),
            bump: src[116],
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AuthorityProofState {
    pub discriminator: [u8; 8],
    pub statement_digest: [u8; 32],
    pub proof_commitment: [u8; 32],
    pub bytes_written: u32,
    pub consumed: u8,
    pub reserved: [u8; 3],
    pub proof_bytes: [u8; WotsAuthProof::ENCODED_LEN],
}

impl AuthorityProofState {
    pub const HEADER_LEN: usize = 80;
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(statement_digest: [u8; 32], proof_commitment: [u8; 32]) -> Self {
        Self {
            discriminator: AUTHORITY_PROOF_DISCRIMINATOR,
            statement_digest,
            proof_commitment,
            bytes_written: 0,
            consumed: 0,
            reserved: [0; 3],
            proof_bytes: [0; WotsAuthProof::ENCODED_LEN],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.statement_digest);
        dst[40..72].copy_from_slice(&self.proof_commitment);
        dst[72..76].copy_from_slice(&self.bytes_written.to_le_bytes());
        dst[76] = self.consumed;
        dst[77..80].copy_from_slice(&self.reserved);
        dst[80..Self::LEN].copy_from_slice(&self.proof_bytes);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != AUTHORITY_PROOF_DISCRIMINATOR {
            return None;
        }

        let mut statement_digest = [0; 32];
        statement_digest.copy_from_slice(&src[8..40]);

        let mut proof_commitment = [0; 32];
        proof_commitment.copy_from_slice(&src[40..72]);

        let mut bytes_written = [0; 4];
        bytes_written.copy_from_slice(&src[72..76]);

        let mut reserved = [0; 3];
        reserved.copy_from_slice(&src[77..80]);

        let mut proof_bytes = [0; WotsAuthProof::ENCODED_LEN];
        proof_bytes.copy_from_slice(&src[80..Self::LEN]);

        Some(Self {
            discriminator,
            statement_digest,
            proof_commitment,
            bytes_written: u32::from_le_bytes(bytes_written),
            consumed: src[76],
            reserved,
            proof_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OrchestrationStatus {
    Pending = 1,
    Committed = 2,
    Complete = 3,
    Failed = 4,
}

/// Coordination state for an offchain FROST threshold signing ceremony.
///
/// Layout (152 bytes):
/// ```text
/// [0..8]   discriminator  "SPNDORC1"
/// [8..40]  action_hash
/// [40..72] session_commitment
/// [72..104] signers_commitment
/// [104..136] signing_package_hash
/// [136..144] expiry_slot       (u64 LE)
/// [144]    threshold
/// [145]    participant_count
/// [146]    status
/// [147]    bump
/// [148..152] reserved
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SpendOrchestrationState {
    pub discriminator: [u8; 8],
    pub action_hash: [u8; 32],
    pub session_commitment: [u8; 32],
    pub signers_commitment: [u8; 32],
    pub signing_package_hash: [u8; 32],
    pub tx_binding: [u8; 32],
    pub expiry_slot: u64,
    pub threshold: u8,
    pub participant_count: u8,
    pub status: u8,
    pub bump: u8,
    pub reserved: [u8; 4],
}

impl SpendOrchestrationState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        action_hash: [u8; 32],
        session_commitment: [u8; 32],
        signers_commitment: [u8; 32],
        expiry_slot: u64,
        threshold: u8,
        participant_count: u8,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: SPEND_ORCH_DISCRIMINATOR,
            action_hash,
            session_commitment,
            signers_commitment,
            signing_package_hash: [0; 32],
            tx_binding: [0; 32],
            expiry_slot,
            threshold,
            participant_count,
            status: OrchestrationStatus::Pending as u8,
            bump,
            reserved: [0; 4],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.action_hash);
        dst[40..72].copy_from_slice(&self.session_commitment);
        dst[72..104].copy_from_slice(&self.signers_commitment);
        dst[104..136].copy_from_slice(&self.signing_package_hash);
        dst[136..168].copy_from_slice(&self.tx_binding);
        dst[168..176].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[176] = self.threshold;
        dst[177] = self.participant_count;
        dst[178] = self.status;
        dst[179] = self.bump;
        dst[180..184].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != SPEND_ORCH_DISCRIMINATOR {
            return None;
        }

        let mut action_hash = [0; 32];
        action_hash.copy_from_slice(&src[8..40]);

        let mut session_commitment = [0; 32];
        session_commitment.copy_from_slice(&src[40..72]);

        let mut signers_commitment = [0; 32];
        signers_commitment.copy_from_slice(&src[72..104]);

        let mut signing_package_hash = [0; 32];
        signing_package_hash.copy_from_slice(&src[104..136]);

        let mut tx_binding = [0; 32];
        tx_binding.copy_from_slice(&src[136..168]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[168..176]);

        let mut reserved = [0; 4];
        reserved.copy_from_slice(&src[180..184]);

        Some(Self {
            discriminator,
            action_hash,
            session_commitment,
            signers_commitment,
            signing_package_hash,
            tx_binding,
            expiry_slot: u64::from_le_bytes(expiry_slot),
            threshold: src[176],
            participant_count: src[177],
            status: src[178],
            bump: src[179],
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryStatus {
    Pending = 1,
    Complete = 2,
}

/// Tracks PQC-authorized recovery of a vault whose threshold signing group
/// has been lost. Created by `InitRecovery` (requires WOTS+ proof),
/// finalized by `CompleteRecovery` (binds the new group key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RecoveryState {
    pub discriminator: [u8; 8],
    pub vault_pubkey: [u8; 32],
    pub recovery_commitment: [u8; 32],
    pub new_group_key: [u8; 32],
    pub new_authority_hash: [u8; 32],
    pub expiry_slot: u64,
    pub new_threshold: u8,
    pub new_participant_count: u8,
    pub status: u8,
    pub bump: u8,
    pub reserved: [u8; 4],
}

impl RecoveryState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        vault_pubkey: [u8; 32],
        recovery_commitment: [u8; 32],
        expiry_slot: u64,
        new_threshold: u8,
        new_participant_count: u8,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: RECOVERY_STATE_DISCRIMINATOR,
            vault_pubkey,
            recovery_commitment,
            new_group_key: [0; 32],
            new_authority_hash: [0; 32],
            expiry_slot,
            new_threshold,
            new_participant_count,
            status: RecoveryStatus::Pending as u8,
            bump,
            reserved: [0; 4],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }
        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.vault_pubkey);
        dst[40..72].copy_from_slice(&self.recovery_commitment);
        dst[72..104].copy_from_slice(&self.new_group_key);
        dst[104..136].copy_from_slice(&self.new_authority_hash);
        dst[136..144].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[144] = self.new_threshold;
        dst[145] = self.new_participant_count;
        dst[146] = self.status;
        dst[147] = self.bump;
        dst[148..152].copy_from_slice(&self.reserved);
        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }
        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != RECOVERY_STATE_DISCRIMINATOR {
            return None;
        }
        let mut vault_pubkey = [0; 32];
        vault_pubkey.copy_from_slice(&src[8..40]);
        let mut recovery_commitment = [0; 32];
        recovery_commitment.copy_from_slice(&src[40..72]);
        let mut new_group_key = [0; 32];
        new_group_key.copy_from_slice(&src[72..104]);
        let mut new_authority_hash = [0; 32];
        new_authority_hash.copy_from_slice(&src[104..136]);
        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[136..144]);
        let mut reserved = [0; 4];
        reserved.copy_from_slice(&src[148..152]);
        Some(Self {
            discriminator,
            vault_pubkey,
            recovery_commitment,
            new_group_key,
            new_authority_hash,
            expiry_slot: u64::from_le_bytes(expiry_slot),
            new_threshold: src[144],
            new_participant_count: src[145],
            status: src[146],
            bump: src[147],
            reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActionSessionState, AuthorityProofState, OrchestrationStatus, PolicyReceiptState,
        QuantumAuthorityState, RecoveryState, RecoveryStatus, SessionStatus,
        SpendOrchestrationState, VaultRegistry, VaultStatus, ACTION_SESSION_DISCRIMINATOR,
        AUTHORITY_PROOF_DISCRIMINATOR, POLICY_RECEIPT_DISCRIMINATOR, QUANTUM_STATE_DISCRIMINATOR,
        RECOVERY_STATE_DISCRIMINATOR, SPEND_ORCH_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
    };
    use vaulkyrie_protocol::WotsAuthProof;

    #[test]
    fn vault_registry_layout_is_stable() {
        let state = VaultRegistry::new([1; 32], [2; 32], 7, VaultStatus::Active, 9, [10; 32]);

        assert_eq!(state.discriminator, VAULT_REGISTRY_DISCRIMINATOR);
        assert_eq!(VaultRegistry::LEN, 128);
        assert_eq!(state.status, VaultStatus::Active as u8);
        assert_eq!(state.last_consumed_receipt_nonce, 0);
        assert_eq!(state.policy_mxe_program, [10; 32]);
    }

    #[test]
    fn vault_registry_roundtrips_through_bytes() {
        let state = VaultRegistry::new([1; 32], [2; 32], 7, VaultStatus::Active, 9, [10; 32]);
        let mut bytes = [0; VaultRegistry::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(VaultRegistry::decode(&bytes), Some(state));
    }

    #[test]
    fn policy_receipt_state_defaults_to_unconsumed() {
        let state = PolicyReceiptState::new([3; 32], [4; 32], 5, 6);

        assert_eq!(state.discriminator, POLICY_RECEIPT_DISCRIMINATOR);
        assert_eq!(PolicyReceiptState::LEN, 96);
        assert_eq!(state.consumed, 0);
    }

    #[test]
    fn policy_receipt_roundtrips_through_bytes() {
        let state = PolicyReceiptState::new([3; 32], [4; 32], 5, 6);
        let mut bytes = [0; PolicyReceiptState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(PolicyReceiptState::decode(&bytes), Some(state));
    }

    #[test]
    fn quantum_state_starts_at_sequence_zero() {
        let state = QuantumAuthorityState::new([5; 32], [6; 32], 1);

        assert_eq!(state.discriminator, QUANTUM_STATE_DISCRIMINATOR);
        assert_eq!(QuantumAuthorityState::LEN, 128);
        assert_eq!(state.next_sequence, 0);
        assert_eq!(state.next_leaf_index, 0);
    }

    #[test]
    fn quantum_state_roundtrips_through_bytes() {
        let state = QuantumAuthorityState::new([5; 32], [6; 32], 1);
        let mut bytes = [0; QuantumAuthorityState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(QuantumAuthorityState::decode(&bytes), Some(state));
    }

    #[test]
    fn action_session_roundtrips_through_bytes() {
        let state = ActionSessionState::new([6; 32], [7; 32], 77, 99, 2);
        let mut bytes = [0; ActionSessionState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(ActionSessionState::decode(&bytes), Some(state));
        assert_eq!(state.discriminator, ACTION_SESSION_DISCRIMINATOR);
        assert_eq!(state.policy_version, 77);
        assert_eq!(state.status, SessionStatus::Pending as u8);
        assert_eq!(ActionSessionState::LEN, 96);
    }

    #[test]
    fn authority_proof_state_roundtrips_through_bytes() {
        let mut state = AuthorityProofState::new([7; 32], [8; 32]);
        state.bytes_written = 9;
        state.consumed = 1;
        state.proof_bytes[0] = 3;
        let mut bytes = [0; AuthorityProofState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(AuthorityProofState::decode(&bytes), Some(state));
        assert_eq!(state.discriminator, AUTHORITY_PROOF_DISCRIMINATOR);
        assert_eq!(
            AuthorityProofState::LEN,
            AuthorityProofState::HEADER_LEN + WotsAuthProof::ENCODED_LEN
        );
    }

    #[test]
    fn spend_orchestration_state_layout_is_stable() {
        let state = SpendOrchestrationState::new([1; 32], [2; 32], [3; 32], 500, 2, 3, 7);

        assert_eq!(state.discriminator, SPEND_ORCH_DISCRIMINATOR);
        assert_eq!(SpendOrchestrationState::LEN, 184);
        assert_eq!(state.status, OrchestrationStatus::Pending as u8);
        assert_eq!(state.signing_package_hash, [0; 32]);
        assert_eq!(state.tx_binding, [0; 32]);
    }

    #[test]
    fn spend_orchestration_state_roundtrips_through_bytes() {
        let mut state = SpendOrchestrationState::new([1; 32], [2; 32], [3; 32], 999, 2, 3, 5);
        state.signing_package_hash = [4; 32];
        state.status = OrchestrationStatus::Committed as u8;
        let mut bytes = [0; SpendOrchestrationState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(SpendOrchestrationState::decode(&bytes), Some(state));
    }

    #[test]
    fn recovery_state_layout_is_stable() {
        let state = RecoveryState::new([1; 32], [2; 32], 5000, 2, 3, 255);

        assert_eq!(state.discriminator, RECOVERY_STATE_DISCRIMINATOR);
        assert_eq!(RecoveryState::LEN, 152);
        assert_eq!(state.status, RecoveryStatus::Pending as u8);
        assert_eq!(state.new_group_key, [0; 32]);
        assert_eq!(state.new_authority_hash, [0; 32]);
    }

    #[test]
    fn recovery_state_roundtrips_through_bytes() {
        let mut state = RecoveryState::new([1; 32], [2; 32], 5000, 2, 3, 7);
        state.new_group_key = [3; 32];
        state.new_authority_hash = [4; 32];
        state.status = RecoveryStatus::Complete as u8;
        let mut bytes = [0; RecoveryState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(RecoveryState::decode(&bytes), Some(state));
    }

    #[test]
    fn spend_orchestration_roundtrips_with_nonzero_tx_binding() {
        let mut state = SpendOrchestrationState::new([1; 32], [2; 32], [3; 32], 999, 2, 3, 5);
        state.signing_package_hash = [4; 32];
        state.tx_binding = [0xAB; 32];
        state.status = OrchestrationStatus::Complete as u8;
        let mut bytes = [0; SpendOrchestrationState::LEN];

        assert!(state.encode(&mut bytes));
        let decoded = SpendOrchestrationState::decode(&bytes).unwrap();
        assert_eq!(decoded.tx_binding, [0xAB; 32]);
        assert_eq!(decoded, state);
    }

    #[test]
    fn vault_registry_decode_rejects_wrong_discriminator() {
        let state = VaultRegistry::new([1; 32], [2; 32], 7, VaultStatus::Active, 9, [10; 32]);
        let mut bytes = [0; VaultRegistry::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF; // corrupt discriminator
        assert_eq!(VaultRegistry::decode(&bytes), None);
    }

    #[test]
    fn policy_receipt_decode_rejects_wrong_discriminator() {
        let state = PolicyReceiptState::new([3; 32], [4; 32], 5, 6);
        let mut bytes = [0; PolicyReceiptState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF;
        assert_eq!(PolicyReceiptState::decode(&bytes), None);
    }

    #[test]
    fn action_session_decode_rejects_wrong_discriminator() {
        let state = ActionSessionState::new([6; 32], [7; 32], 77, 99, 2);
        let mut bytes = [0; ActionSessionState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF;
        assert_eq!(ActionSessionState::decode(&bytes), None);
    }

    #[test]
    fn quantum_authority_decode_rejects_wrong_discriminator() {
        let state = QuantumAuthorityState::new([5; 32], [6; 32], 1);
        let mut bytes = [0; QuantumAuthorityState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF;
        assert_eq!(QuantumAuthorityState::decode(&bytes), None);
    }

    #[test]
    fn authority_proof_decode_rejects_wrong_discriminator() {
        let state = AuthorityProofState::new([7; 32], [8; 32]);
        let mut bytes = [0; AuthorityProofState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF;
        assert_eq!(AuthorityProofState::decode(&bytes), None);
    }

    #[test]
    fn spend_orchestration_decode_rejects_wrong_discriminator() {
        let state = SpendOrchestrationState::new([1; 32], [2; 32], [3; 32], 500, 2, 3, 7);
        let mut bytes = [0; SpendOrchestrationState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF;
        assert_eq!(SpendOrchestrationState::decode(&bytes), None);
    }

    #[test]
    fn recovery_state_decode_rejects_wrong_discriminator() {
        let state = RecoveryState::new([1; 32], [2; 32], 5000, 2, 3, 7);
        let mut bytes = [0; RecoveryState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0] = 0xFF;
        assert_eq!(RecoveryState::decode(&bytes), None);
    }
}
