#![cfg_attr(not(test), no_std)]

mod privacy_engine;

pub use privacy_engine::*;

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
pub const WINTER_AUTHORITY_MESSAGE_SCALARS: usize = 22;
pub const WINTER_AUTHORITY_CHECKSUM_SCALARS: usize = 2;
pub const WINTER_AUTHORITY_TOTAL_SCALARS: usize =
    WINTER_AUTHORITY_MESSAGE_SCALARS + WINTER_AUTHORITY_CHECKSUM_SCALARS;
pub const WINTER_AUTHORITY_SCALAR_BYTES: usize = 32;
pub const WINTER_AUTHORITY_SIGNATURE_BYTES: usize =
    WINTER_AUTHORITY_TOTAL_SCALARS * WINTER_AUTHORITY_SCALAR_BYTES;
pub const WINTER_AUTHORITY_DOMAIN: &[u8] = b"VAULKYRIE_WINTER_AUTHORITY_V1";
pub const WINTER_AUTHORITY_ADVANCE_DOMAIN: &[u8] = b"VAULKYRIE_WINTER_AUTHORITY_ADVANCE";
pub const AUTHORITY_PROOF_CHUNK_MAX_BYTES: usize = 256;
pub const QUANTUM_SPLIT_MESSAGE_BYTES: usize = 72;
pub const QUANTUM_CLOSE_MESSAGE_BYTES: usize = 32;
pub const PQC_WALLET_ADVANCE_DOMAIN: &[u8] = b"VAULKYRIE_PQC_WALLET_ADVANCE_V1";
pub const PQC_WALLET_ADVANCE_MESSAGE_BYTES: usize = 32 + 32 + 32 + 32 + 32 + 8 + 8;

pub const VAULT_REGISTRY_SEED: &[u8] = b"vault_registry";
pub const POLICY_RECEIPT_SEED: &[u8] = b"policy_receipt";
pub const ACTION_SESSION_SEED: &[u8] = b"action_session";
pub const QUANTUM_AUTHORITY_SEED: &[u8] = b"quantum_authority";
pub const AUTHORITY_PROOF_SEED: &[u8] = b"authority_proof";
pub const QUANTUM_VAULT_SEED: &[u8] = b"quantum_vault";
pub const PQC_WALLET_SEED: &[u8] = b"pqc_wallet";
pub const POLICY_CONFIG_SEED: &[u8] = b"policy_config";
pub const POLICY_EVAL_SEED: &[u8] = b"policy_eval";
pub const SPEND_ORCH_SEED: &[u8] = b"spend_orch";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReceipt {
    pub action_hash: [u8; 32],
    pub policy_version: u64,
    pub threshold: ThresholdRequirement,
    pub nonce: u64,
    pub expiry_slot: u64,
}

impl PolicyReceipt {
    pub const ENCODED_LEN: usize = 57;

    pub fn encode(&self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::ENCODED_LEN {
            return false;
        }

        dst[..32].copy_from_slice(&self.action_hash);
        dst[32..40].copy_from_slice(&self.policy_version.to_le_bytes());
        dst[40] = self.threshold.as_byte();
        dst[41..49].copy_from_slice(&self.nonce.to_le_bytes());
        dst[49..57].copy_from_slice(&self.expiry_slot.to_le_bytes());

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::ENCODED_LEN {
            return None;
        }

        let mut action_hash = [0; 32];
        action_hash.copy_from_slice(&src[..32]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[32..40]);

        let threshold = ThresholdRequirement::try_from(src[40]).ok()?;

        let mut nonce = [0; 8];
        nonce.copy_from_slice(&src[41..49]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[49..57]);

        Some(Self {
            action_hash,
            policy_version: u64::from_le_bytes(policy_version),
            threshold,
            nonce: u64::from_le_bytes(nonce),
            expiry_slot: u64::from_le_bytes(expiry_slot),
        })
    }

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
pub struct PolicyEvaluationRequest {
    pub vault_id: [u8; 32],
    pub action_hash: [u8; 32],
    pub policy_version: u64,
    pub request_nonce: u64,
    pub expiry_slot: u64,
    pub encrypted_input_commitment: [u8; 32],
}

impl PolicyEvaluationRequest {
    pub const ENCODED_LEN: usize = 120;

    pub fn encode(&self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::ENCODED_LEN {
            return false;
        }

        dst[..32].copy_from_slice(&self.vault_id);
        dst[32..64].copy_from_slice(&self.action_hash);
        dst[64..72].copy_from_slice(&self.policy_version.to_le_bytes());
        dst[72..80].copy_from_slice(&self.request_nonce.to_le_bytes());
        dst[80..88].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[88..120].copy_from_slice(&self.encrypted_input_commitment);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::ENCODED_LEN {
            return None;
        }

        let mut vault_id = [0; 32];
        vault_id.copy_from_slice(&src[..32]);

        let mut action_hash = [0; 32];
        action_hash.copy_from_slice(&src[32..64]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[64..72]);

        let mut request_nonce = [0; 8];
        request_nonce.copy_from_slice(&src[72..80]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[80..88]);

        let mut encrypted_input_commitment = [0; 32];
        encrypted_input_commitment.copy_from_slice(&src[88..120]);

        Some(Self {
            vault_id,
            action_hash,
            policy_version: u64::from_le_bytes(policy_version),
            request_nonce: u64::from_le_bytes(request_nonce),
            expiry_slot: u64::from_le_bytes(expiry_slot),
            encrypted_input_commitment,
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.vault_id);
        hasher.update(self.action_hash);
        hasher.update(self.policy_version.to_le_bytes());
        hasher.update(self.request_nonce.to_le_bytes());
        hasher.update(self.expiry_slot.to_le_bytes());
        hasher.update(self.encrypted_input_commitment);

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecisionEnvelope {
    pub request_commitment: [u8; 32],
    pub receipt: PolicyReceipt,
    pub delay_until_slot: u64,
    pub reason_code: u16,
    pub computation_offset: u64,
    pub result_commitment: [u8; 32],
}

impl PolicyDecisionEnvelope {
    pub const ENCODED_LEN: usize = 139;

    pub fn encode(&self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::ENCODED_LEN {
            return false;
        }

        dst[..32].copy_from_slice(&self.request_commitment);
        if !self.receipt.encode(&mut dst[32..89]) {
            return false;
        }
        dst[89..97].copy_from_slice(&self.delay_until_slot.to_le_bytes());
        dst[97..99].copy_from_slice(&self.reason_code.to_le_bytes());
        dst[99..107].copy_from_slice(&self.computation_offset.to_le_bytes());
        dst[107..139].copy_from_slice(&self.result_commitment);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::ENCODED_LEN {
            return None;
        }

        let mut request_commitment = [0; 32];
        request_commitment.copy_from_slice(&src[..32]);

        let receipt = PolicyReceipt::decode(&src[32..89])?;

        let mut delay_until_slot = [0; 8];
        delay_until_slot.copy_from_slice(&src[89..97]);

        let mut reason_code = [0; 2];
        reason_code.copy_from_slice(&src[97..99]);

        let mut computation_offset = [0; 8];
        computation_offset.copy_from_slice(&src[99..107]);

        let mut result_commitment = [0; 32];
        result_commitment.copy_from_slice(&src[107..139]);

        Some(Self {
            request_commitment,
            receipt,
            delay_until_slot: u64::from_le_bytes(delay_until_slot),
            reason_code: u16::from_le_bytes(reason_code),
            computation_offset: u64::from_le_bytes(computation_offset),
            result_commitment,
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut encoded = [0u8; Self::ENCODED_LEN];
        let did_encode = self.encode(&mut encoded);
        debug_assert!(did_encode);

        let mut hasher = Sha256::new();
        hasher.update(encoded);
        hasher.finalize().into()
    }

    pub fn matches_request(&self, request: &PolicyEvaluationRequest) -> bool {
        self.request_commitment == request.commitment()
            && self.receipt.action_hash == request.action_hash
            && self.receipt.policy_version == request.policy_version
            && self.receipt.expiry_slot <= request.expiry_slot
            && self.delay_until_slot <= self.receipt.expiry_slot
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
pub struct WinterAuthorityAdvanceStatement {
    pub action_hash: [u8; 32],
    pub current_root: [u8; 32],
    pub next_root: [u8; 32],
    pub sequence: u64,
    pub expiry_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinterAuthoritySignature {
    pub scalars: [u8; WINTER_AUTHORITY_SIGNATURE_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinterAuthoritySecretKey {
    pub scalars: [u8; WINTER_AUTHORITY_SIGNATURE_BYTES],
}

impl WinterAuthorityAdvanceStatement {
    fn update_hasher(&self, hasher: &mut Sha256) {
        hasher.update(WINTER_AUTHORITY_ADVANCE_DOMAIN);
        hasher.update(self.action_hash);
        hasher.update(self.current_root);
        hasher.update(self.next_root);
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.expiry_slot.to_le_bytes());
    }

    pub fn payload_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.current_root);
        hasher.update(self.next_root);
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

    pub fn digest(&self) -> [u8; WINTER_AUTHORITY_MESSAGE_SCALARS] {
        let mut hasher = Sha256::new();
        hasher.update(WINTER_AUTHORITY_DOMAIN);
        self.update_hasher(&mut hasher);

        let digest: [u8; 32] = hasher.finalize().into();
        let mut out = [0u8; WINTER_AUTHORITY_MESSAGE_SCALARS];
        out.copy_from_slice(&digest[..WINTER_AUTHORITY_MESSAGE_SCALARS]);
        out
    }

    pub fn replay_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(WINTER_AUTHORITY_DOMAIN);
        self.update_hasher(&mut hasher);
        hasher.finalize().into()
    }
}

impl WinterAuthoritySignature {
    pub const ENCODED_LEN: usize = WINTER_AUTHORITY_SIGNATURE_BYTES;

    pub fn encode(&self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::ENCODED_LEN {
            return false;
        }

        dst.copy_from_slice(&self.scalars);
        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::ENCODED_LEN {
            return None;
        }

        let mut scalars = [0u8; WINTER_AUTHORITY_SIGNATURE_BYTES];
        scalars.copy_from_slice(src);
        Some(Self { scalars })
    }

    pub fn recover_public_key(
        &self,
        digest: [u8; WINTER_AUTHORITY_MESSAGE_SCALARS],
    ) -> [u8; WINTER_AUTHORITY_SIGNATURE_BYTES] {
        let checksum = winter_authority_checksum(digest);
        let mut public_key = [0u8; WINTER_AUTHORITY_SIGNATURE_BYTES];

        for (index, digit) in digest.iter().copied().enumerate() {
            let sig_scalar = winter_authority_get_scalar(&self.scalars, index);
            let public_scalar = winter_authority_hash_chain(sig_scalar, 255u8.wrapping_sub(digit));
            winter_authority_set_scalar(&mut public_key, index, public_scalar);
        }

        for (offset, digit) in checksum.iter().copied().enumerate() {
            let scalar_index = WINTER_AUTHORITY_MESSAGE_SCALARS + offset;
            let sig_scalar = winter_authority_get_scalar(&self.scalars, scalar_index);
            let public_scalar = winter_authority_hash_chain(sig_scalar, 255u8.wrapping_sub(digit));
            winter_authority_set_scalar(&mut public_key, scalar_index, public_scalar);
        }

        public_key
    }

    pub fn verify_digest(
        &self,
        digest: [u8; WINTER_AUTHORITY_MESSAGE_SCALARS],
        expected_root: [u8; 32],
    ) -> bool {
        let public_key = self.recover_public_key(digest);
        winter_authority_root(&public_key) == expected_root
    }

    pub fn verify_statement(&self, statement: &WinterAuthorityAdvanceStatement) -> bool {
        self.verify_digest(statement.digest(), statement.current_root)
    }
}

impl WinterAuthoritySecretKey {
    pub fn public_key(&self) -> [u8; WINTER_AUTHORITY_SIGNATURE_BYTES] {
        let mut public_key = [0u8; WINTER_AUTHORITY_SIGNATURE_BYTES];

        for index in 0..WINTER_AUTHORITY_TOTAL_SCALARS {
            let secret_scalar = winter_authority_get_scalar(&self.scalars, index);
            let public_scalar = winter_authority_hash_chain(secret_scalar, u8::MAX);
            winter_authority_set_scalar(&mut public_key, index, public_scalar);
        }

        public_key
    }

    pub fn root(&self) -> [u8; 32] {
        winter_authority_root(&self.public_key())
    }

    pub fn sign_digest(
        &self,
        digest: [u8; WINTER_AUTHORITY_MESSAGE_SCALARS],
    ) -> WinterAuthoritySignature {
        let checksum = winter_authority_checksum(digest);
        let mut scalars = [0u8; WINTER_AUTHORITY_SIGNATURE_BYTES];

        for (index, digit) in digest.iter().copied().enumerate() {
            let secret_scalar = winter_authority_get_scalar(&self.scalars, index);
            let signature_scalar = winter_authority_hash_chain(secret_scalar, digit);
            winter_authority_set_scalar(&mut scalars, index, signature_scalar);
        }

        for (offset, digit) in checksum.iter().copied().enumerate() {
            let scalar_index = WINTER_AUTHORITY_MESSAGE_SCALARS + offset;
            let secret_scalar = winter_authority_get_scalar(&self.scalars, scalar_index);
            let signature_scalar = winter_authority_hash_chain(secret_scalar, digit);
            winter_authority_set_scalar(&mut scalars, scalar_index, signature_scalar);
        }

        WinterAuthoritySignature { scalars }
    }

    pub fn sign_statement(
        &self,
        statement: &WinterAuthorityAdvanceStatement,
    ) -> WinterAuthoritySignature {
        self.sign_digest(statement.digest())
    }
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

pub fn winter_authority_digest(message_parts: &[&[u8]]) -> [u8; WINTER_AUTHORITY_MESSAGE_SCALARS] {
    let mut hasher = Sha256::new();
    hasher.update(WINTER_AUTHORITY_DOMAIN);
    for part in message_parts {
        hasher.update(part);
    }

    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = [0u8; WINTER_AUTHORITY_MESSAGE_SCALARS];
    out.copy_from_slice(&digest[..WINTER_AUTHORITY_MESSAGE_SCALARS]);
    out
}

pub fn winter_authority_root(public_key: &[u8; WINTER_AUTHORITY_SIGNATURE_BYTES]) -> [u8; 32] {
    let mut level = [[0u8; 32]; WINTER_AUTHORITY_TOTAL_SCALARS];
    for index in 0..WINTER_AUTHORITY_TOTAL_SCALARS {
        level[index] = winter_authority_leaf_hash(winter_authority_get_scalar(public_key, index));
    }

    let mut len = WINTER_AUTHORITY_TOTAL_SCALARS;
    while len > 1 {
        let mut next_len = 0;
        let mut index = 0;
        while index < len {
            let left = level[index];
            let right = if index + 1 < len {
                level[index + 1]
            } else {
                left
            };
            level[next_len] = winter_authority_node_hash(left, right);
            next_len += 1;
            index += 2;
        }
        len = next_len;
    }

    level[0]
}

fn winter_authority_checksum(digest: [u8; WINTER_AUTHORITY_MESSAGE_SCALARS]) -> [u8; 2] {
    let mut checksum = 0u16;
    for digit in digest {
        checksum += 255u16 - digit as u16;
    }

    [(checksum >> 8) as u8, checksum as u8]
}

fn winter_authority_hash_chain(
    mut scalar: [u8; WINTER_AUTHORITY_SCALAR_BYTES],
    steps: u8,
) -> [u8; WINTER_AUTHORITY_SCALAR_BYTES] {
    for _ in 0..steps {
        let mut hasher = Sha256::new();
        hasher.update(scalar);
        scalar = hasher.finalize().into();
    }

    scalar
}

fn winter_authority_leaf_hash(scalar: [u8; WINTER_AUTHORITY_SCALAR_BYTES]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0u8]);
    hasher.update(scalar);
    hasher.finalize().into()
}

fn winter_authority_node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn winter_authority_get_scalar(
    data: &[u8; WINTER_AUTHORITY_SIGNATURE_BYTES],
    scalar_index: usize,
) -> [u8; WINTER_AUTHORITY_SCALAR_BYTES] {
    let start = scalar_index * WINTER_AUTHORITY_SCALAR_BYTES;
    let end = start + WINTER_AUTHORITY_SCALAR_BYTES;
    let mut scalar = [0; WINTER_AUTHORITY_SCALAR_BYTES];
    scalar.copy_from_slice(&data[start..end]);
    scalar
}

fn winter_authority_set_scalar(
    dst: &mut [u8; WINTER_AUTHORITY_SIGNATURE_BYTES],
    scalar_index: usize,
    value: [u8; WINTER_AUTHORITY_SCALAR_BYTES],
) {
    let start = scalar_index * WINTER_AUTHORITY_SCALAR_BYTES;
    let end = start + WINTER_AUTHORITY_SCALAR_BYTES;
    dst[start..end].copy_from_slice(&value);
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

pub fn quantum_split_message(
    amount: u64,
    split_pubkey: [u8; 32],
    refund_pubkey: [u8; 32],
) -> [u8; QUANTUM_SPLIT_MESSAGE_BYTES] {
    let mut message = [0u8; QUANTUM_SPLIT_MESSAGE_BYTES];
    message[..8].copy_from_slice(&amount.to_le_bytes());
    message[8..40].copy_from_slice(&split_pubkey);
    message[40..72].copy_from_slice(&refund_pubkey);
    message
}

pub fn quantum_close_message(refund_pubkey: [u8; 32]) -> [u8; QUANTUM_CLOSE_MESSAGE_BYTES] {
    refund_pubkey
}

pub fn pqc_wallet_advance_message(
    wallet_id: [u8; 32],
    current_root: [u8; 32],
    next_root: [u8; 32],
    destination: [u8; 32],
    amount: u64,
    sequence: u64,
) -> [u8; PQC_WALLET_ADVANCE_MESSAGE_BYTES] {
    let mut message = [0u8; PQC_WALLET_ADVANCE_MESSAGE_BYTES];
    let domain_hash: [u8; 32] = Sha256::digest(PQC_WALLET_ADVANCE_DOMAIN).into();
    message[..32].copy_from_slice(&domain_hash);
    message[32..64].copy_from_slice(&wallet_id);
    message[64..96].copy_from_slice(&current_root);
    message[96..128].copy_from_slice(&next_root);
    message[128..160].copy_from_slice(&destination);
    message[160..168].copy_from_slice(&amount.to_le_bytes());
    message[168..176].copy_from_slice(&sequence.to_le_bytes());
    message
}

pub fn quantum_split_digest(
    amount: u64,
    split_pubkey: [u8; 32],
    refund_pubkey: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(quantum_split_message(amount, split_pubkey, refund_pubkey));
    hasher.finalize().into()
}

pub fn quantum_close_digest(refund_pubkey: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(quantum_close_message(refund_pubkey));
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        pqc_wallet_advance_message, quantum_close_digest, quantum_close_message,
        quantum_split_digest, quantum_split_message, ActionDescriptor, ActionKind,
        AuthorityRotationStatement, PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt,
        ThresholdRequirement, WinterAuthorityAdvanceStatement, WinterAuthoritySecretKey,
        WinterAuthoritySignature, WotsAuthProof, WotsSecretKey, WINTER_AUTHORITY_SIGNATURE_BYTES,
        WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES,
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
    fn policy_receipt_roundtrips_through_bytes() {
        let receipt = PolicyReceipt {
            action_hash: descriptor(ActionKind::Spend).hash(),
            policy_version: 42,
            threshold: ThresholdRequirement::ThreeOfThree,
            nonce: 11,
            expiry_slot: 900,
        };
        let mut bytes = [0u8; PolicyReceipt::ENCODED_LEN];

        assert!(receipt.encode(&mut bytes));
        assert_eq!(PolicyReceipt::decode(&bytes), Some(receipt));
    }

    #[test]
    fn policy_request_commitment_changes_with_encrypted_context() {
        let request = PolicyEvaluationRequest {
            vault_id: [3; 32],
            action_hash: descriptor(ActionKind::Spend).hash(),
            policy_version: 42,
            request_nonce: 7,
            expiry_slot: 1_200,
            encrypted_input_commitment: [8; 32],
        };
        let mut changed = request.clone();
        changed.encrypted_input_commitment = [9; 32];

        assert_ne!(request.commitment(), changed.commitment());
    }

    #[test]
    fn policy_decision_envelope_roundtrips_through_bytes() {
        let request = PolicyEvaluationRequest {
            vault_id: [1; 32],
            action_hash: descriptor(ActionKind::Spend).hash(),
            policy_version: 42,
            request_nonce: 3,
            expiry_slot: 700,
            encrypted_input_commitment: [4; 32],
        };
        let envelope = PolicyDecisionEnvelope {
            request_commitment: request.commitment(),
            receipt: PolicyReceipt {
                action_hash: request.action_hash,
                policy_version: request.policy_version,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 5,
                expiry_slot: 650,
            },
            delay_until_slot: 620,
            reason_code: 17,
            computation_offset: 99,
            result_commitment: [6; 32],
        };
        let mut bytes = [0u8; PolicyDecisionEnvelope::ENCODED_LEN];

        assert!(envelope.encode(&mut bytes));
        assert_eq!(PolicyDecisionEnvelope::decode(&bytes), Some(envelope));
    }

    #[test]
    fn policy_decision_envelope_matches_request_binding() {
        let request = PolicyEvaluationRequest {
            vault_id: [1; 32],
            action_hash: descriptor(ActionKind::Spend).hash(),
            policy_version: 42,
            request_nonce: 3,
            expiry_slot: 700,
            encrypted_input_commitment: [4; 32],
        };
        let envelope = PolicyDecisionEnvelope {
            request_commitment: request.commitment(),
            receipt: PolicyReceipt {
                action_hash: request.action_hash,
                policy_version: request.policy_version,
                threshold: ThresholdRequirement::OneOfThree,
                nonce: 8,
                expiry_slot: 680,
            },
            delay_until_slot: 640,
            reason_code: 5,
            computation_offset: 42,
            result_commitment: [9; 32],
        };

        assert!(envelope.matches_request(&request));
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
    fn winter_authority_statement_is_action_bound() {
        let current = sample_winter_secret(3).root();
        let next = sample_winter_secret(4).root();
        let mut statement = WinterAuthorityAdvanceStatement {
            action_hash: [0; 32],
            current_root: current,
            next_root: next,
            sequence: 9,
            expiry_slot: 1_400,
        };
        statement.action_hash = statement.expected_action_hash([7; 32], 42);

        assert!(statement.is_action_bound([7; 32], 42));
        assert!(!statement.is_action_bound([8; 32], 42));
    }

    #[test]
    fn winter_authority_signature_verifies_against_current_root() {
        let current = sample_winter_secret(11);
        let next = sample_winter_secret(12);
        let mut statement = WinterAuthorityAdvanceStatement {
            action_hash: [0; 32],
            current_root: current.root(),
            next_root: next.root(),
            sequence: 1,
            expiry_slot: 900,
        };
        statement.action_hash = statement.expected_action_hash([7; 32], 42);

        let signature = current.sign_statement(&statement);

        assert!(signature.verify_statement(&statement));
    }

    #[test]
    fn winter_authority_signature_rejects_wrong_next_root() {
        let current = sample_winter_secret(21);
        let next = sample_winter_secret(22);
        let mut statement = WinterAuthorityAdvanceStatement {
            action_hash: [0; 32],
            current_root: current.root(),
            next_root: next.root(),
            sequence: 1,
            expiry_slot: 900,
        };
        statement.action_hash = statement.expected_action_hash([7; 32], 42);

        let signature = current.sign_statement(&statement);
        let mut tampered = statement.clone();
        tampered.next_root = sample_winter_secret(23).root();
        tampered.action_hash = tampered.expected_action_hash([7; 32], 42);

        assert!(!signature.verify_statement(&tampered));
    }

    #[test]
    fn winter_authority_signature_roundtrips_through_bytes() {
        let signature = WinterAuthoritySignature {
            scalars: [7; WINTER_AUTHORITY_SIGNATURE_BYTES],
        };
        let mut bytes = [0u8; WinterAuthoritySignature::ENCODED_LEN];

        assert!(signature.encode(&mut bytes));
        assert_eq!(WinterAuthoritySignature::decode(&bytes), Some(signature));
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

    fn sample_winter_secret(seed: u8) -> WinterAuthoritySecretKey {
        let mut scalars = [0u8; WINTER_AUTHORITY_SIGNATURE_BYTES];
        for (index, byte) in scalars.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        WinterAuthoritySecretKey { scalars }
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

    #[test]
    fn quantum_split_message_is_stable() {
        let message = quantum_split_message(55, [7; 32], [8; 32]);

        assert_eq!(&message[..8], &55u64.to_le_bytes());
        assert_eq!(&message[8..40], &[7; 32]);
        assert_eq!(&message[40..72], &[8; 32]);
    }

    #[test]
    fn pqc_wallet_advance_message_is_bound_to_root_and_sequence() {
        let first = pqc_wallet_advance_message([1; 32], [2; 32], [3; 32], [4; 32], 5, 6);
        let second = pqc_wallet_advance_message([1; 32], [2; 32], [3; 32], [4; 32], 5, 7);
        let third = pqc_wallet_advance_message([1; 32], [9; 32], [3; 32], [4; 32], 5, 6);

        assert_ne!(first, second);
        assert_ne!(first, third);
        assert_eq!(&first[32..64], &[1; 32]);
        assert_eq!(&first[64..96], &[2; 32]);
        assert_eq!(&first[160..168], &5u64.to_le_bytes());
        assert_eq!(&first[168..176], &6u64.to_le_bytes());
    }

    #[test]
    fn quantum_split_digest_changes_with_refund_recipient() {
        let first = quantum_split_digest(55, [7; 32], [8; 32]);
        let second = quantum_split_digest(55, [7; 32], [9; 32]);

        assert_ne!(first, second);
    }

    #[test]
    fn quantum_close_message_is_refund_pubkey_bytes() {
        assert_eq!(quantum_close_message([5; 32]), [5; 32]);
    }

    #[test]
    fn quantum_close_digest_changes_with_recipient() {
        let first = quantum_close_digest([5; 32]);
        let second = quantum_close_digest([6; 32]);

        assert_ne!(first, second);
    }
}
