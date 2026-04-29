//! Re-exported types from the protocol and core layers so SDK consumers
//! do not need to depend on internal crates directly.

pub use vaulkyrie_protocol::{
    ActionDescriptor, ActionKind, AuthorityRotationStatement, ThresholdRequirement, WotsAuthProof,
    AUTHORITY_PROOF_CHUNK_MAX_BYTES, AUTHORITY_PROOF_SEED, PQC_WALLET_SEED, QUANTUM_AUTHORITY_SEED,
    QUANTUM_VAULT_SEED, SPEND_ORCH_SEED, VAULT_REGISTRY_SEED, WOTS_CHAIN_COUNT,
    WOTS_CHAIN_MAX_STEPS, WOTS_ELEMENT_BYTES, WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES,
    XMSS_LEAF_COUNT, XMSS_NODE_BYTES, XMSS_TREE_HEIGHT,
};

// ─── Discriminators ──────────────────────────────────────────────────────────

pub const VAULT_REGISTRY_DISCRIMINATOR: [u8; 8] = *b"VAULKYR1";
pub const QUANTUM_STATE_DISCRIMINATOR: [u8; 8] = *b"QSTATE01";
pub const AUTHORITY_PROOF_DISCRIMINATOR: [u8; 8] = *b"AUTHPRF1";
pub const SPEND_ORCH_DISCRIMINATOR: [u8; 8] = *b"SPNDORC1";
pub const RECOVERY_STATE_DISCRIMINATOR: [u8; 8] = *b"RECOV001";
pub const PQC_WALLET_DISCRIMINATOR: [u8; 8] = *b"PQCWALT1";

// ─── Status enums (mirrored from core, no pinocchio dependency) ──────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VaultStatus {
    Active = 1,
    Recovery = 2,
    Locked = 3,
}

impl TryFrom<u8> for VaultStatus {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            1 => Ok(Self::Active),
            2 => Ok(Self::Recovery),
            3 => Ok(Self::Locked),
            _ => Err(()),
        }
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

impl TryFrom<u8> for OrchestrationStatus {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Committed),
            3 => Ok(Self::Complete),
            4 => Ok(Self::Failed),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryStatus {
    Pending = 1,
    Complete = 2,
}

impl TryFrom<u8> for RecoveryStatus {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Complete),
            _ => Err(()),
        }
    }
}
