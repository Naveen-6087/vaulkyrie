use core::mem::size_of;

use vaulkyrie_protocol::WotsAuthProof;

pub const VAULT_REGISTRY_DISCRIMINATOR: [u8; 8] = *b"VAULKYR1";
pub const QUANTUM_STATE_DISCRIMINATOR: [u8; 8] = *b"QSTATE01";
pub const PQC_WALLET_DISCRIMINATOR: [u8; 8] = *b"PQCWALT1";
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
pub enum OrchestrationStatus {
    Pending = 1,
    Committed = 2,
    Complete = 3,
    Failed = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryStatus {
    Pending = 1,
    Complete = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PqcWalletState {
    pub discriminator: [u8; 8],
    pub wallet_id: [u8; 32],
    pub current_root: [u8; 32],
    pub sequence: u64,
    pub bump: u8,
    pub reserved: [u8; 7],
}

impl PqcWalletState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(wallet_id: [u8; 32], current_root: [u8; 32], bump: u8) -> Self {
        Self {
            discriminator: PQC_WALLET_DISCRIMINATOR,
            wallet_id,
            current_root,
            sequence: 0,
            bump,
            reserved: [0; 7],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.wallet_id);
        dst[40..72].copy_from_slice(&self.current_root);
        dst[72..80].copy_from_slice(&self.sequence.to_le_bytes());
        dst[80] = self.bump;
        dst[81..88].copy_from_slice(&self.reserved);
        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != PQC_WALLET_DISCRIMINATOR {
            return None;
        }

        let mut wallet_id = [0; 32];
        wallet_id.copy_from_slice(&src[8..40]);
        let mut current_root = [0; 32];
        current_root.copy_from_slice(&src[40..72]);
        let mut sequence = [0; 8];
        sequence.copy_from_slice(&src[72..80]);
        let mut reserved = [0; 7];
        reserved.copy_from_slice(&src[81..88]);

        Some(Self {
            discriminator,
            wallet_id,
            current_root,
            sequence: u64::from_le_bytes(sequence),
            bump: src[80],
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VaultRegistry {
    pub discriminator: [u8; 8],
    pub wallet_pubkey: [u8; 32],
    pub current_authority_hash: [u8; 32],
    pub status: u8,
    pub bump: u8,
    pub reserved: [u8; 54],
}

impl VaultRegistry {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        wallet_pubkey: [u8; 32],
        current_authority_hash: [u8; 32],
        status: VaultStatus,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: VAULT_REGISTRY_DISCRIMINATOR,
            wallet_pubkey,
            current_authority_hash,
            status: status as u8,
            bump,
            reserved: [0; 54],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.wallet_pubkey);
        dst[40..72].copy_from_slice(&self.current_authority_hash);
        dst[72] = self.status;
        dst[73] = self.bump;
        dst[74..128].copy_from_slice(&self.reserved);
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
        let mut reserved = [0; 54];
        reserved.copy_from_slice(&src[74..128]);

        Some(Self {
            discriminator,
            wallet_pubkey,
            current_authority_hash,
            status: src[72],
            bump: src[73],
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
    use super::*;

    #[test]
    fn vault_registry_roundtrips() {
        let state = VaultRegistry::new([1; 32], [2; 32], VaultStatus::Active, 7);
        let mut bytes = [0u8; VaultRegistry::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(VaultRegistry::decode(&bytes), Some(state));
    }

    #[test]
    fn quantum_authority_roundtrips() {
        let state = QuantumAuthorityState::new([3; 32], [4; 32], 1);
        let mut bytes = [0u8; QuantumAuthorityState::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(QuantumAuthorityState::decode(&bytes), Some(state));
    }

    #[test]
    fn authority_proof_roundtrips() {
        let state = AuthorityProofState::new([5; 32], [6; 32]);
        let mut bytes = vec![0u8; AuthorityProofState::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(AuthorityProofState::decode(&bytes), Some(state));
    }

    #[test]
    fn spend_orchestration_roundtrips() {
        let state = SpendOrchestrationState::new([1; 32], [2; 32], [3; 32], 100, 2, 3, 9);
        let mut bytes = [0u8; SpendOrchestrationState::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(SpendOrchestrationState::decode(&bytes), Some(state));
    }

    #[test]
    fn recovery_state_roundtrips() {
        let state = RecoveryState::new([7; 32], [8; 32], 500, 2, 3, 4);
        let mut bytes = [0u8; RecoveryState::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(RecoveryState::decode(&bytes), Some(state));
    }

    #[test]
    fn pqc_wallet_roundtrips() {
        let state = PqcWalletState::new([9; 32], [10; 32], 2);
        let mut bytes = [0u8; PqcWalletState::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(PqcWalletState::decode(&bytes), Some(state));
    }
}
