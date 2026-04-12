#![cfg_attr(not(test), no_std)]

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionKind {
    Spend = 0,
    PolicyUpdate = 1,
    Rekey = 2,
    Close = 3,
}

impl ActionKind {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDescriptor {
    pub vault_id: [u8; 32],
    pub payload_hash: [u8; 32],
    pub policy_version: u64,
    pub kind: ActionKind,
}

impl ActionDescriptor {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.vault_id);
        hasher.update(self.payload_hash);
        hasher.update(self.policy_version.to_le_bytes());
        hasher.update([self.kind.as_byte()]);

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThresholdRequirement {
    OneOfThree = 1,
    TwoOfThree = 2,
    ThreeOfThree = 3,
    RequirePqcAuth = 255,
}

impl ThresholdRequirement {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReceipt {
    pub action_hash: [u8; 32],
    pub policy_version: u64,
    pub threshold: ThresholdRequirement,
    pub nonce: u64,
    pub expiry_slot: u64,
}

impl PolicyReceipt {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.action_hash);
        hasher.update(self.policy_version.to_le_bytes());
        hasher.update([self.threshold.as_byte()]);
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.expiry_slot.to_le_bytes());

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRotationStatement {
    pub action_hash: [u8; 32],
    pub next_authority_hash: [u8; 32],
    pub sequence: u64,
    pub expiry_slot: u64,
}

impl AuthorityRotationStatement {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.action_hash);
        hasher.update(self.next_authority_hash);
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.expiry_slot.to_le_bytes());

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActionDescriptor, ActionKind, AuthorityRotationStatement, PolicyReceipt,
        ThresholdRequirement,
    };

    fn descriptor(kind: ActionKind) -> ActionDescriptor {
        ActionDescriptor {
            vault_id: [7; 32],
            payload_hash: [9; 32],
            policy_version: 42,
            kind,
        }
    }

    #[test]
    fn action_hash_is_stable_for_identical_inputs() {
        let first = descriptor(ActionKind::Spend).hash();
        let second = descriptor(ActionKind::Spend).hash();

        assert_eq!(first, second);
    }

    #[test]
    fn action_hash_changes_when_action_kind_changes() {
        let spend = descriptor(ActionKind::Spend).hash();
        let rekey = descriptor(ActionKind::Rekey).hash();

        assert_ne!(spend, rekey);
    }

    #[test]
    fn action_kind_encoding_is_fixed() {
        assert_eq!(ActionKind::Spend.as_byte(), 0);
        assert_eq!(ActionKind::PolicyUpdate.as_byte(), 1);
        assert_eq!(ActionKind::Rekey.as_byte(), 2);
        assert_eq!(ActionKind::Close.as_byte(), 3);
    }

    #[test]
    fn policy_receipt_commitment_changes_with_threshold() {
        let receipt = PolicyReceipt {
            action_hash: descriptor(ActionKind::Spend).hash(),
            policy_version: 42,
            threshold: ThresholdRequirement::TwoOfThree,
            nonce: 8,
            expiry_slot: 500,
        };

        let mut changed = receipt.clone();
        changed.threshold = ThresholdRequirement::RequirePqcAuth;

        assert_ne!(receipt.commitment(), changed.commitment());
    }

    #[test]
    fn authority_rotation_digest_changes_with_next_authority() {
        let statement = AuthorityRotationStatement {
            action_hash: descriptor(ActionKind::Rekey).hash(),
            next_authority_hash: [1; 32],
            sequence: 1,
            expiry_slot: 700,
        };

        let mut changed = statement.clone();
        changed.next_authority_hash = [2; 32];

        assert_ne!(statement.digest(), changed.digest());
    }

    #[test]
    fn threshold_encoding_is_fixed() {
        assert_eq!(ThresholdRequirement::OneOfThree.as_byte(), 1);
        assert_eq!(ThresholdRequirement::TwoOfThree.as_byte(), 2);
        assert_eq!(ThresholdRequirement::ThreeOfThree.as_byte(), 3);
        assert_eq!(ThresholdRequirement::RequirePqcAuth.as_byte(), 255);
    }
}
