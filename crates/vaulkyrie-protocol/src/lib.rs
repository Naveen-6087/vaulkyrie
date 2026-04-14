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

pub const WOTS_CHAIN_COUNT: usize = 16;
pub const WOTS_ELEMENT_BYTES: usize = 32;
pub const WOTS_CHAIN_MAX_STEPS: u8 = 15;
pub const WOTS_KEY_BYTES: usize = WOTS_CHAIN_COUNT * WOTS_ELEMENT_BYTES;
pub const XMSS_TREE_HEIGHT: usize = 8;
pub const XMSS_NODE_BYTES: usize = 32;
pub const XMSS_AUTH_PATH_BYTES: usize = XMSS_TREE_HEIGHT * XMSS_NODE_BYTES;
pub const XMSS_LEAF_COUNT: u32 = 1u32 << XMSS_TREE_HEIGHT;
pub const AUTHORITY_PROOF_CHUNK_MAX_BYTES: usize = 256;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsAuthProof {
    pub public_key: [u8; WOTS_KEY_BYTES],
    pub signature: [u8; WOTS_KEY_BYTES],
    pub leaf_index: u32,
    pub auth_path: [u8; XMSS_AUTH_PATH_BYTES],
}

impl WotsAuthProof {
    pub const ENCODED_LEN: usize = (WOTS_KEY_BYTES * 2) + 4 + XMSS_AUTH_PATH_BYTES;

    pub fn encode(&self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::ENCODED_LEN {
            return false;
        }

        dst[..WOTS_KEY_BYTES].copy_from_slice(&self.public_key);
        dst[WOTS_KEY_BYTES..(WOTS_KEY_BYTES * 2)].copy_from_slice(&self.signature);
        dst[(WOTS_KEY_BYTES * 2)..((WOTS_KEY_BYTES * 2) + 4)]
            .copy_from_slice(&self.leaf_index.to_le_bytes());
        dst[((WOTS_KEY_BYTES * 2) + 4)..Self::ENCODED_LEN].copy_from_slice(&self.auth_path);
        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::ENCODED_LEN {
            return None;
        }

        let mut public_key = [0; WOTS_KEY_BYTES];
        public_key.copy_from_slice(&src[..WOTS_KEY_BYTES]);

        let mut signature = [0; WOTS_KEY_BYTES];
        signature.copy_from_slice(&src[WOTS_KEY_BYTES..(WOTS_KEY_BYTES * 2)]);

        let mut leaf_index = [0; 4];
        leaf_index.copy_from_slice(&src[(WOTS_KEY_BYTES * 2)..((WOTS_KEY_BYTES * 2) + 4)]);

        let mut auth_path = [0; XMSS_AUTH_PATH_BYTES];
        auth_path.copy_from_slice(&src[((WOTS_KEY_BYTES * 2) + 4)..Self::ENCODED_LEN]);

        Some(Self {
            public_key,
            signature,
            leaf_index: u32::from_le_bytes(leaf_index),
            auth_path,
        })
    }

    pub fn authority_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.public_key);
        hasher.finalize().into()
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut encoded = [0u8; Self::ENCODED_LEN];
        let did_encode = self.encode(&mut encoded);
        debug_assert!(did_encode);

        let mut hasher = Sha256::new();
        hasher.update(encoded);
        hasher.finalize().into()
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        let mut node = self.authority_hash();
        for level in 0..XMSS_TREE_HEIGHT {
            let sibling = xmss_get_node(&self.auth_path, level);
            node = if ((self.leaf_index >> level) & 1) == 0 {
                xmss_parent_hash(node, sibling)
            } else {
                xmss_parent_hash(sibling, node)
            };
        }

        node
    }

    pub fn verify_merkle_root(&self, expected_root: [u8; 32]) -> bool {
        self.merkle_root() == expected_root
    }

    pub fn verify_digest(&self, digest: [u8; 32]) -> bool {
        let digits = wots_message_digits(digest);

        for (chain_index, steps) in digits.iter().enumerate() {
            let sig_element = wots_get_element(&self.signature, chain_index);
            let expected_public_element =
                wots_hash_chain(sig_element, WOTS_CHAIN_MAX_STEPS.saturating_sub(*steps));
            if wots_get_element(&self.public_key, chain_index) != expected_public_element {
                return false;
            }
        }

        true
    }

    pub fn verify_statement(&self, statement: &AuthorityRotationStatement) -> bool {
        self.verify_digest(statement.digest())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsSecretKey {
    pub elements: [u8; WOTS_KEY_BYTES],
}

impl WotsSecretKey {
    pub fn public_key(&self) -> [u8; WOTS_KEY_BYTES] {
        let mut public_key = [0; WOTS_KEY_BYTES];
        for chain_index in 0..WOTS_CHAIN_COUNT {
            let secret_element = wots_get_element(&self.elements, chain_index);
            let public_element = wots_hash_chain(secret_element, WOTS_CHAIN_MAX_STEPS);
            wots_set_element(&mut public_key, chain_index, public_element);
        }

        public_key
    }

    pub fn authority_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.public_key());
        hasher.finalize().into()
    }

    pub fn sign_digest(&self, digest: [u8; 32]) -> WotsAuthProof {
        self.sign_digest_with_auth_path(digest, 0, [0; XMSS_AUTH_PATH_BYTES])
    }

    pub fn sign_digest_with_auth_path(
        &self,
        digest: [u8; 32],
        leaf_index: u32,
        auth_path: [u8; XMSS_AUTH_PATH_BYTES],
    ) -> WotsAuthProof {
        let digits = wots_message_digits(digest);
        let mut signature = [0; WOTS_KEY_BYTES];

        for (chain_index, steps) in digits.iter().enumerate() {
            let secret_element = wots_get_element(&self.elements, chain_index);
            let signature_element = wots_hash_chain(secret_element, *steps);
            wots_set_element(&mut signature, chain_index, signature_element);
        }

        WotsAuthProof {
            public_key: self.public_key(),
            signature,
            leaf_index,
            auth_path,
        }
    }

    pub fn sign_statement(&self, statement: &AuthorityRotationStatement) -> WotsAuthProof {
        self.sign_digest(statement.digest())
    }

    pub fn sign_statement_with_auth_path(
        &self,
        statement: &AuthorityRotationStatement,
        leaf_index: u32,
        auth_path: [u8; XMSS_AUTH_PATH_BYTES],
    ) -> WotsAuthProof {
        self.sign_digest_with_auth_path(statement.digest(), leaf_index, auth_path)
    }
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

fn wots_message_digits(digest: [u8; 32]) -> [u8; WOTS_CHAIN_COUNT] {
    let mut digits = [0; WOTS_CHAIN_COUNT];
    for (index, value) in digest[..8].iter().enumerate() {
        digits[index * 2] = value >> 4;
        digits[(index * 2) + 1] = value & 0x0f;
    }

    digits
}

fn wots_hash_chain(mut element: [u8; WOTS_ELEMENT_BYTES], steps: u8) -> [u8; WOTS_ELEMENT_BYTES] {
    for _ in 0..steps {
        let mut hasher = Sha256::new();
        hasher.update(element);
        element = hasher.finalize().into();
    }

    element
}

fn wots_get_element(data: &[u8; WOTS_KEY_BYTES], chain_index: usize) -> [u8; WOTS_ELEMENT_BYTES] {
    let start = chain_index * WOTS_ELEMENT_BYTES;
    let end = start + WOTS_ELEMENT_BYTES;
    let mut element = [0; WOTS_ELEMENT_BYTES];
    element.copy_from_slice(&data[start..end]);
    element
}

fn wots_set_element(
    dst: &mut [u8; WOTS_KEY_BYTES],
    chain_index: usize,
    value: [u8; WOTS_ELEMENT_BYTES],
) {
    let start = chain_index * WOTS_ELEMENT_BYTES;
    let end = start + WOTS_ELEMENT_BYTES;
    dst[start..end].copy_from_slice(&value);
}

fn xmss_parent_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn xmss_get_node(data: &[u8; XMSS_AUTH_PATH_BYTES], level: usize) -> [u8; XMSS_NODE_BYTES] {
    let start = level * XMSS_NODE_BYTES;
    let end = start + XMSS_NODE_BYTES;
    let mut node = [0; XMSS_NODE_BYTES];
    node.copy_from_slice(&data[start..end]);
    node
}

#[cfg(test)]
mod tests {
    use super::{
        ActionDescriptor, ActionKind, AuthorityRotationStatement, PolicyReceipt,
        ThresholdRequirement, WotsAuthProof, WotsSecretKey, WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES,
    };

    fn descriptor(kind: ActionKind) -> ActionDescriptor {
        ActionDescriptor {
            vault_id: [7; 32],
            payload_hash: [9; 32],
            policy_version: 42,
            kind,
        }
    }

    fn sample_auth_path(seed: u8) -> [u8; XMSS_AUTH_PATH_BYTES] {
        let mut auth_path = [0u8; XMSS_AUTH_PATH_BYTES];
        for (index, byte) in auth_path.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        auth_path
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
        assert_eq!(
            ThresholdRequirement::try_from(1),
            Ok(ThresholdRequirement::OneOfThree)
        );
        assert_eq!(
            ThresholdRequirement::try_from(2),
            Ok(ThresholdRequirement::TwoOfThree)
        );
        assert_eq!(
            ThresholdRequirement::try_from(255),
            Ok(ThresholdRequirement::RequirePqcAuth)
        );
        assert_eq!(ThresholdRequirement::try_from(99), Err(()));
    }

    fn sample_wots_secret(seed: u8) -> WotsSecretKey {
        let mut elements = [0u8; WOTS_KEY_BYTES];
        for (index, byte) in elements.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        WotsSecretKey { elements }
    }

    #[test]
    fn wots_signature_verifies_for_statement_digest() {
        let secret = sample_wots_secret(7);
        let statement = AuthorityRotationStatement {
            action_hash: [11; 32],
            next_authority_hash: [12; 32],
            sequence: 2,
            expiry_slot: 900,
        };
        let proof = secret.sign_statement(&statement);

        assert!(proof.verify_statement(&statement));
    }

    #[test]
    fn wots_signature_rejects_tampered_signature() {
        let secret = sample_wots_secret(7);
        let statement = AuthorityRotationStatement {
            action_hash: [11; 32],
            next_authority_hash: [12; 32],
            sequence: 2,
            expiry_slot: 900,
        };
        let mut proof = secret.sign_statement(&statement);
        proof.signature[0] ^= 1;

        assert!(!proof.verify_statement(&statement));
    }

    #[test]
    fn xmss_proof_derives_merkle_root_from_leaf_index_and_auth_path() {
        let secret = sample_wots_secret(7);
        let statement = AuthorityRotationStatement {
            action_hash: [11; 32],
            next_authority_hash: [12; 32],
            sequence: 2,
            expiry_slot: 900,
        };
        let proof = secret.sign_statement_with_auth_path(&statement, 3, sample_auth_path(21));
        let root = proof.merkle_root();

        assert!(proof.verify_merkle_root(root));
    }

    #[test]
    fn xmss_merkle_root_changes_with_leaf_index() {
        let secret = sample_wots_secret(7);
        let statement = AuthorityRotationStatement {
            action_hash: [11; 32],
            next_authority_hash: [12; 32],
            sequence: 2,
            expiry_slot: 900,
        };
        let auth_path = sample_auth_path(21);
        let first = secret
            .sign_statement_with_auth_path(&statement, 0, auth_path)
            .merkle_root();
        let second = secret
            .sign_statement_with_auth_path(&statement, 1, auth_path)
            .merkle_root();

        assert_ne!(first, second);
    }

    #[test]
    fn wots_proof_roundtrips_through_bytes() {
        let proof = WotsAuthProof {
            public_key: [3; WOTS_KEY_BYTES],
            signature: [4; WOTS_KEY_BYTES],
            leaf_index: 9,
            auth_path: [5; XMSS_AUTH_PATH_BYTES],
        };
        let mut bytes = [0u8; WotsAuthProof::ENCODED_LEN];
        assert!(proof.encode(&mut bytes));
        assert_eq!(WotsAuthProof::decode(&bytes), Some(proof));
    }
}
