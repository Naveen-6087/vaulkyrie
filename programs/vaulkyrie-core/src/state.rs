use core::mem::size_of;

pub const VAULT_REGISTRY_DISCRIMINATOR: [u8; 8] = *b"VAULKYR1";
pub const POLICY_RECEIPT_DISCRIMINATOR: [u8; 8] = *b"POLRCPT1";
pub const QUANTUM_STATE_DISCRIMINATOR: [u8; 8] = *b"QSTATE01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VaultStatus {
    Active = 1,
    Recovery = 2,
    Locked = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VaultRegistry {
    pub discriminator: [u8; 8],
    pub wallet_pubkey: [u8; 32],
    pub current_authority_hash: [u8; 32],
    pub policy_version: u64,
    pub status: u8,
    pub bump: u8,
    pub reserved: [u8; 14],
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
            status: status as u8,
            bump,
            reserved: [0; 14],
        }
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct QuantumAuthorityState {
    pub discriminator: [u8; 8],
    pub current_authority_hash: [u8; 32],
    pub last_consumed_digest: [u8; 32],
    pub next_sequence: u64,
    pub bump: u8,
    pub reserved: [u8; 15],
}

impl QuantumAuthorityState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(current_authority_hash: [u8; 32], bump: u8) -> Self {
        Self {
            discriminator: QUANTUM_STATE_DISCRIMINATOR,
            current_authority_hash,
            last_consumed_digest: [0; 32],
            next_sequence: 0,
            bump,
            reserved: [0; 15],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyReceiptState, QuantumAuthorityState, VaultRegistry, VaultStatus,
        POLICY_RECEIPT_DISCRIMINATOR, QUANTUM_STATE_DISCRIMINATOR, VAULT_REGISTRY_DISCRIMINATOR,
    };

    #[test]
    fn vault_registry_layout_is_stable() {
        let state = VaultRegistry::new([1; 32], [2; 32], 7, VaultStatus::Active, 9);

        assert_eq!(state.discriminator, VAULT_REGISTRY_DISCRIMINATOR);
        assert_eq!(VaultRegistry::LEN, 96);
        assert_eq!(state.status, VaultStatus::Active as u8);
    }

    #[test]
    fn policy_receipt_state_defaults_to_unconsumed() {
        let state = PolicyReceiptState::new([3; 32], [4; 32], 5, 6);

        assert_eq!(state.discriminator, POLICY_RECEIPT_DISCRIMINATOR);
        assert_eq!(PolicyReceiptState::LEN, 96);
        assert_eq!(state.consumed, 0);
    }

    #[test]
    fn quantum_state_starts_at_sequence_zero() {
        let state = QuantumAuthorityState::new([5; 32], 1);

        assert_eq!(state.discriminator, QUANTUM_STATE_DISCRIMINATOR);
        assert_eq!(QuantumAuthorityState::LEN, 96);
        assert_eq!(state.next_sequence, 0);
    }
}
