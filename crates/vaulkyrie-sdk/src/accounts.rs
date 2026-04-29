//! Account deserialization for all Vaulkyrie on-chain state types.
//!
//! These mirror the layouts defined in `vaulkyrie-core::state` but use only
//! standard Rust (no pinocchio dependency) so the SDK works on host-side
//! targets.

use crate::types::*;
use vaulkyrie_protocol::WotsAuthProof;

/// Vaulkyrie vault registry (128 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultRegistry {
    pub wallet_pubkey: [u8; 32],
    pub current_authority_hash: [u8; 32],
    pub status: u8,
    pub bump: u8,
}

impl VaultRegistry {
    pub const LEN: usize = 128;

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }
        if src[..8] != VAULT_REGISTRY_DISCRIMINATOR {
            return None;
        }

        let mut wallet_pubkey = [0u8; 32];
        wallet_pubkey.copy_from_slice(&src[8..40]);

        let mut current_authority_hash = [0u8; 32];
        current_authority_hash.copy_from_slice(&src[40..72]);

        Some(Self {
            wallet_pubkey,
            current_authority_hash,
            status: src[72],
            bump: src[73],
        })
    }

    pub fn vault_status(&self) -> Option<VaultStatus> {
        VaultStatus::try_from(self.status).ok()
    }
}

/// Quantum authority state (128 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantumAuthorityState {
    pub current_authority_hash: [u8; 32],
    pub current_authority_root: [u8; 32],
    pub last_consumed_digest: [u8; 32],
    pub next_sequence: u64,
    pub next_leaf_index: u32,
    pub bump: u8,
}

impl QuantumAuthorityState {
    pub const LEN: usize = 128;

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }
        if src[..8] != QUANTUM_STATE_DISCRIMINATOR {
            return None;
        }

        let mut current_authority_hash = [0u8; 32];
        current_authority_hash.copy_from_slice(&src[8..40]);
        let mut current_authority_root = [0u8; 32];
        current_authority_root.copy_from_slice(&src[40..72]);
        let mut last_consumed_digest = [0u8; 32];
        last_consumed_digest.copy_from_slice(&src[72..104]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&src[104..112]);
        let mut leaf = [0u8; 4];
        leaf.copy_from_slice(&src[112..116]);

        Some(Self {
            current_authority_hash,
            current_authority_root,
            last_consumed_digest,
            next_sequence: u64::from_le_bytes(seq),
            next_leaf_index: u32::from_le_bytes(leaf),
            bump: src[116],
        })
    }
}

/// Authority proof state (header 80 bytes + proof_bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProofState {
    pub statement_digest: [u8; 32],
    pub proof_commitment: [u8; 32],
    pub bytes_written: u32,
    pub consumed: u8,
    pub proof_bytes: Vec<u8>,
}

impl AuthorityProofState {
    pub const HEADER_LEN: usize = 80;

    pub fn decode(src: &[u8]) -> Option<Self> {
        let expected_len = Self::HEADER_LEN + WotsAuthProof::ENCODED_LEN;
        if src.len() != expected_len {
            return None;
        }
        if src[..8] != AUTHORITY_PROOF_DISCRIMINATOR {
            return None;
        }

        let mut statement_digest = [0u8; 32];
        statement_digest.copy_from_slice(&src[8..40]);
        let mut proof_commitment = [0u8; 32];
        proof_commitment.copy_from_slice(&src[40..72]);
        let mut bw = [0u8; 4];
        bw.copy_from_slice(&src[72..76]);

        Some(Self {
            statement_digest,
            proof_commitment,
            bytes_written: u32::from_le_bytes(bw),
            consumed: src[76],
            proof_bytes: src[80..].to_vec(),
        })
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed != 0
    }
}

/// Spend orchestration state (184 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendOrchestrationState {
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
}

impl SpendOrchestrationState {
    pub const LEN: usize = 184;

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }
        if src[..8] != SPEND_ORCH_DISCRIMINATOR {
            return None;
        }

        let mut action_hash = [0u8; 32];
        action_hash.copy_from_slice(&src[8..40]);
        let mut session_commitment = [0u8; 32];
        session_commitment.copy_from_slice(&src[40..72]);
        let mut signers_commitment = [0u8; 32];
        signers_commitment.copy_from_slice(&src[72..104]);
        let mut signing_package_hash = [0u8; 32];
        signing_package_hash.copy_from_slice(&src[104..136]);
        let mut tx_binding = [0u8; 32];
        tx_binding.copy_from_slice(&src[136..168]);
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&src[168..176]);

        Some(Self {
            action_hash,
            session_commitment,
            signers_commitment,
            signing_package_hash,
            tx_binding,
            expiry_slot: u64::from_le_bytes(expiry),
            threshold: src[176],
            participant_count: src[177],
            status: src[178],
            bump: src[179],
        })
    }

    pub fn orchestration_status(&self) -> Option<OrchestrationStatus> {
        OrchestrationStatus::try_from(self.status).ok()
    }
}

/// Recovery state (152 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryState {
    pub vault_pubkey: [u8; 32],
    pub recovery_commitment: [u8; 32],
    pub new_group_key: [u8; 32],
    pub new_authority_hash: [u8; 32],
    pub expiry_slot: u64,
    pub new_threshold: u8,
    pub new_participant_count: u8,
    pub status: u8,
    pub bump: u8,
}

impl RecoveryState {
    pub const LEN: usize = 152;

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }
        if src[..8] != RECOVERY_STATE_DISCRIMINATOR {
            return None;
        }

        let mut vault_pubkey = [0u8; 32];
        vault_pubkey.copy_from_slice(&src[8..40]);
        let mut recovery_commitment = [0u8; 32];
        recovery_commitment.copy_from_slice(&src[40..72]);
        let mut new_group_key = [0u8; 32];
        new_group_key.copy_from_slice(&src[72..104]);
        let mut new_authority_hash = [0u8; 32];
        new_authority_hash.copy_from_slice(&src[104..136]);
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&src[136..144]);

        Some(Self {
            vault_pubkey,
            recovery_commitment,
            new_group_key,
            new_authority_hash,
            expiry_slot: u64::from_le_bytes(expiry),
            new_threshold: src[144],
            new_participant_count: src[145],
            status: src[146],
            bump: src[147],
        })
    }

    pub fn recovery_status(&self) -> Option<RecoveryStatus> {
        RecoveryStatus::try_from(self.status).ok()
    }
}

/// PQC wallet state (88 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqcWalletState {
    pub wallet_id: [u8; 32],
    pub current_root: [u8; 32],
    pub sequence: u64,
    pub bump: u8,
}

impl PqcWalletState {
    pub const LEN: usize = 88;

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }
        if src[..8] != PQC_WALLET_DISCRIMINATOR {
            return None;
        }

        let mut wallet_id = [0u8; 32];
        wallet_id.copy_from_slice(&src[8..40]);
        let mut current_root = [0u8; 32];
        current_root.copy_from_slice(&src[40..72]);
        let mut sequence = [0u8; 8];
        sequence.copy_from_slice(&src[72..80]);

        Some(Self {
            wallet_id,
            current_root,
            sequence: u64::from_le_bytes(sequence),
            bump: src[80],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vault_bytes() -> [u8; VaultRegistry::LEN] {
        let mut buf = [0u8; 128];
        buf[..8].copy_from_slice(b"VAULKYR1");
        buf[8..40].copy_from_slice(&[1u8; 32]); // wallet_pubkey
        buf[40..72].copy_from_slice(&[2u8; 32]); // authority_hash
        buf[72] = 1; // status = Active
        buf[73] = 3; // bump
        buf
    }

    #[test]
    fn vault_registry_decodes_correctly() {
        let bytes = make_vault_bytes();
        let vault = VaultRegistry::decode(&bytes).unwrap();
        assert_eq!(vault.wallet_pubkey, [1u8; 32]);
        assert_eq!(vault.current_authority_hash, [2u8; 32]);
        assert_eq!(vault.vault_status(), Some(VaultStatus::Active));
        assert_eq!(vault.bump, 3);
    }

    #[test]
    fn vault_registry_rejects_bad_discriminator() {
        let mut bytes = make_vault_bytes();
        bytes[0] = b'X';
        assert!(VaultRegistry::decode(&bytes).is_none());
    }

    #[test]
    fn vault_registry_rejects_wrong_size() {
        assert!(VaultRegistry::decode(&[0u8; 100]).is_none());
    }

    fn make_authority_bytes() -> [u8; QuantumAuthorityState::LEN] {
        let mut buf = [0u8; 128];
        buf[..8].copy_from_slice(b"QSTATE01");
        buf[8..40].copy_from_slice(&[5u8; 32]);
        buf[40..72].copy_from_slice(&[6u8; 32]);
        buf[72..104].copy_from_slice(&[0u8; 32]); // last_consumed_digest
        buf[104..112].copy_from_slice(&0u64.to_le_bytes()); // next_sequence
        buf[112..116].copy_from_slice(&0u32.to_le_bytes()); // next_leaf_index
        buf[116] = 1; // bump
        buf
    }

    #[test]
    fn quantum_authority_decodes_correctly() {
        let bytes = make_authority_bytes();
        let auth = QuantumAuthorityState::decode(&bytes).unwrap();
        assert_eq!(auth.current_authority_hash, [5u8; 32]);
        assert_eq!(auth.current_authority_root, [6u8; 32]);
        assert_eq!(auth.next_sequence, 0);
        assert_eq!(auth.next_leaf_index, 0);
        assert_eq!(auth.bump, 1);
    }

    fn make_orch_bytes() -> [u8; SpendOrchestrationState::LEN] {
        let mut buf = [0u8; 184];
        buf[..8].copy_from_slice(b"SPNDORC1");
        buf[8..40].copy_from_slice(&[1u8; 32]); // action_hash
        buf[40..72].copy_from_slice(&[2u8; 32]); // session_commitment
        buf[72..104].copy_from_slice(&[3u8; 32]); // signers_commitment
        buf[104..136].copy_from_slice(&[4u8; 32]); // signing_package_hash
        buf[136..168].copy_from_slice(&[5u8; 32]); // tx_binding
        buf[168..176].copy_from_slice(&100u64.to_le_bytes()); // expiry_slot
        buf[176] = 2; // threshold
        buf[177] = 3; // participant_count
        buf[178] = 1; // status = Pending
        buf[179] = 7; // bump
        buf
    }

    #[test]
    fn spend_orchestration_decodes_correctly() {
        let bytes = make_orch_bytes();
        let orch = SpendOrchestrationState::decode(&bytes).unwrap();
        assert_eq!(orch.action_hash, [1u8; 32]);
        assert_eq!(orch.threshold, 2);
        assert_eq!(orch.participant_count, 3);
        assert_eq!(
            orch.orchestration_status(),
            Some(OrchestrationStatus::Pending)
        );
    }

    fn make_recovery_bytes() -> [u8; RecoveryState::LEN] {
        let mut buf = [0u8; 152];
        buf[..8].copy_from_slice(b"RECOV001");
        buf[8..40].copy_from_slice(&[1u8; 32]); // vault_pubkey
        buf[40..72].copy_from_slice(&[2u8; 32]); // recovery_commitment
        buf[72..104].copy_from_slice(&[3u8; 32]); // new_group_key
        buf[104..136].copy_from_slice(&[4u8; 32]); // new_authority_hash
        buf[136..144].copy_from_slice(&500u64.to_le_bytes()); // expiry_slot
        buf[144] = 2; // new_threshold
        buf[145] = 3; // new_participant_count
        buf[146] = 1; // status = Pending
        buf[147] = 5; // bump
        buf
    }

    #[test]
    fn recovery_state_decodes_correctly() {
        let bytes = make_recovery_bytes();
        let rec = RecoveryState::decode(&bytes).unwrap();
        assert_eq!(rec.vault_pubkey, [1u8; 32]);
        assert_eq!(rec.new_threshold, 2);
        assert_eq!(rec.recovery_status(), Some(RecoveryStatus::Pending));
    }
}
