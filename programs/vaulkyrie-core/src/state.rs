use core::mem::size_of;
use vaulkyrie_protocol::WotsAuthProof;

pub const VAULT_REGISTRY_DISCRIMINATOR: [u8; 8] = *b"VAULKYR1";
pub const POLICY_RECEIPT_DISCRIMINATOR: [u8; 8] = *b"POLRCPT1";
pub const ACTION_SESSION_DISCRIMINATOR: [u8; 8] = *b"SESSION1";
pub const QUANTUM_STATE_DISCRIMINATOR: [u8; 8] = *b"QSTATE01";
pub const AUTHORITY_PROOF_DISCRIMINATOR: [u8; 8] = *b"AUTHPRF1";

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
    ) -> Self {
        Self {
            discriminator: VAULT_REGISTRY_DISCRIMINATOR,
            wallet_pubkey,
            current_authority_hash,
            policy_version,
            last_consumed_receipt_nonce: 0,
            status: status as u8,
            bump,
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
        dst[90..96].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);

        let mut wallet_pubkey = [0; 32];
        wallet_pubkey.copy_from_slice(&src[8..40]);

        let mut current_authority_hash = [0; 32];
        current_authority_hash.copy_from_slice(&src[40..72]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[72..80]);

        let mut last_consumed_receipt_nonce = [0; 8];
        last_consumed_receipt_nonce.copy_from_slice(&src[80..88]);

        let mut reserved = [0; 6];
        reserved.copy_from_slice(&src[90..96]);

        Some(Self {
            discriminator,
            wallet_pubkey,
            current_authority_hash,
            policy_version: u64::from_le_bytes(policy_version),
            last_consumed_receipt_nonce: u64::from_le_bytes(last_consumed_receipt_nonce),
            status: src[88],
            bump: src[89],
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

#[cfg(test)]
mod tests {
    use super::{
        ActionSessionState, AuthorityProofState, PolicyReceiptState, QuantumAuthorityState,
        SessionStatus, VaultRegistry, VaultStatus, ACTION_SESSION_DISCRIMINATOR,
        AUTHORITY_PROOF_DISCRIMINATOR, POLICY_RECEIPT_DISCRIMINATOR, QUANTUM_STATE_DISCRIMINATOR,
        VAULT_REGISTRY_DISCRIMINATOR,
    };
    use vaulkyrie_protocol::WotsAuthProof;

    #[test]
    fn vault_registry_layout_is_stable() {
        let state = VaultRegistry::new([1; 32], [2; 32], 7, VaultStatus::Active, 9);

        assert_eq!(state.discriminator, VAULT_REGISTRY_DISCRIMINATOR);
        assert_eq!(VaultRegistry::LEN, 96);
        assert_eq!(state.status, VaultStatus::Active as u8);
        assert_eq!(state.last_consumed_receipt_nonce, 0);
    }

    #[test]
    fn vault_registry_roundtrips_through_bytes() {
        let state = VaultRegistry::new([1; 32], [2; 32], 7, VaultStatus::Active, 9);
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
}
