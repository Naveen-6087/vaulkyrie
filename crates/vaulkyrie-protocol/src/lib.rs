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

#[cfg(test)]
mod tests {
    use super::{ActionDescriptor, ActionKind};

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
}

