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

impl TryFrom<u8> for ThresholdRequirement {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OneOfThree),
            2 => Ok(Self::TwoOfThree),
            3 => Ok(Self::ThreeOfThree),
            255 => Ok(Self::RequirePqcAuth),
            _ => Err(()),
        }
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
    pub fn payload_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.next_authority_hash);
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.expiry_slot.to_le_bytes());

        hasher.finalize().into()
    }

    pub fn expected_action_hash(&self, vault_id: [u8; 32], policy_version: u64) -> [u8; 32] {
        ActionDescriptor {
            vault_id,
            payload_hash: self.payload_hash(),
            policy_version,
            kind: ActionKind::Rekey,
        }
        .hash()
    }

    pub fn is_action_bound(&self, vault_id: [u8; 32], policy_version: u64) -> bool {
        self.action_hash == self.expected_action_hash(vault_id, policy_version)
    }

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
        let mut statement = AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: [1; 32],
            sequence: 1,
            expiry_slot: 700,
        };
        statement.action_hash = statement.expected_action_hash([7; 32], 42);

        let mut changed = statement.clone();
        changed.next_authority_hash = [2; 32];
        changed.action_hash = changed.expected_action_hash([7; 32], 42);

        assert_ne!(statement.digest(), changed.digest());
    }

    #[test]
    fn authority_rotation_binding_accepts_expected_action_hash() {
        let mut statement = AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: [3; 32],
            sequence: 4,
            expiry_slot: 900,
        };
        statement.action_hash = statement.expected_action_hash([7; 32], 42);

        assert!(statement.is_action_bound([7; 32], 42));
    }

    #[test]
    fn authority_rotation_binding_rejects_wrong_policy_version() {
        let mut statement = AuthorityRotationStatement {
            action_hash: [0; 32],
            next_authority_hash: [3; 32],
            sequence: 4,
            expiry_slot: 900,
        };
        statement.action_hash = statement.expected_action_hash([7; 32], 42);

        assert!(!statement.is_action_bound([7; 32], 43));
    }

    #[test]
    fn threshold_encoding_is_fixed() {
        assert_eq!(ThresholdRequirement::OneOfThree.as_byte(), 1);
        assert_eq!(ThresholdRequirement::TwoOfThree.as_byte(), 2);
        assert_eq!(ThresholdRequirement::ThreeOfThree.as_byte(), 3);
        assert_eq!(ThresholdRequirement::RequirePqcAuth.as_byte(), 255);
    }

    #[test]
    fn threshold_decoding_accepts_known_values() {
        assert_eq!(ThresholdRequirement::try_from(1), Ok(ThresholdRequirement::OneOfThree));
        assert_eq!(ThresholdRequirement::try_from(2), Ok(ThresholdRequirement::TwoOfThree));
        assert_eq!(
            ThresholdRequirement::try_from(255),
            Ok(ThresholdRequirement::RequirePqcAuth)
        );
        assert_eq!(ThresholdRequirement::try_from(99), Err(()));
    }
}
