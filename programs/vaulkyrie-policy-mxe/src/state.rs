use core::mem::size_of;

pub const POLICY_CONFIG_DISCRIMINATOR: [u8; 8] = *b"POLCFG01";
pub const POLICY_EVAL_DISCRIMINATOR: [u8; 8] = *b"POLEVAL1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyEvaluationStatus {
    Pending = 1,
    Finalized = 2,
    Aborted = 3,
    /// Arcium MXE computation has been queued; awaiting callback.
    ComputationQueued = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyConfigState {
    pub discriminator: [u8; 8],
    pub core_program: [u8; 32],
    pub arcium_program: [u8; 32],
    pub mxe_account: [u8; 32],
    pub policy_version: u64,
    pub next_request_nonce: u64,
    pub bump: u8,
    pub reserved: [u8; 7],
}

impl PolicyConfigState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        core_program: [u8; 32],
        arcium_program: [u8; 32],
        mxe_account: [u8; 32],
        policy_version: u64,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: POLICY_CONFIG_DISCRIMINATOR,
            core_program,
            arcium_program,
            mxe_account,
            policy_version,
            next_request_nonce: 0,
            bump,
            reserved: [0; 7],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.core_program);
        dst[40..72].copy_from_slice(&self.arcium_program);
        dst[72..104].copy_from_slice(&self.mxe_account);
        dst[104..112].copy_from_slice(&self.policy_version.to_le_bytes());
        dst[112..120].copy_from_slice(&self.next_request_nonce.to_le_bytes());
        dst[120] = self.bump;
        dst[121..128].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != POLICY_CONFIG_DISCRIMINATOR {
            return None;
        }

        let mut core_program = [0; 32];
        core_program.copy_from_slice(&src[8..40]);

        let mut arcium_program = [0; 32];
        arcium_program.copy_from_slice(&src[40..72]);

        let mut mxe_account = [0; 32];
        mxe_account.copy_from_slice(&src[72..104]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[104..112]);

        let mut next_request_nonce = [0; 8];
        next_request_nonce.copy_from_slice(&src[112..120]);

        let mut reserved = [0; 7];
        reserved.copy_from_slice(&src[121..128]);

        Some(Self {
            discriminator,
            core_program,
            arcium_program,
            mxe_account,
            policy_version: u64::from_le_bytes(policy_version),
            next_request_nonce: u64::from_le_bytes(next_request_nonce),
            bump: src[120],
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyEvaluationState {
    pub discriminator: [u8; 8],
    pub request_commitment: [u8; 32],
    pub vault_id: [u8; 32],
    pub action_hash: [u8; 32],
    pub encrypted_input_commitment: [u8; 32],
    pub policy_version: u64,
    pub request_nonce: u64,
    pub expiry_slot: u64,
    pub computation_offset: u64,
    pub receipt_commitment: [u8; 32],
    pub decision_commitment: [u8; 32],
    pub delay_until_slot: u64,
    pub status: u8,
    pub reason_code: u16,
    pub reserved: [u8; 13],
}

impl PolicyEvaluationState {
    pub const LEN: usize = size_of::<Self>();

    pub const fn new(
        request_commitment: [u8; 32],
        vault_id: [u8; 32],
        action_hash: [u8; 32],
        encrypted_input_commitment: [u8; 32],
        policy_version: u64,
        request_nonce: u64,
        expiry_slot: u64,
        computation_offset: u64,
    ) -> Self {
        Self {
            discriminator: POLICY_EVAL_DISCRIMINATOR,
            request_commitment,
            vault_id,
            action_hash,
            encrypted_input_commitment,
            policy_version,
            request_nonce,
            expiry_slot,
            computation_offset,
            receipt_commitment: [0; 32],
            decision_commitment: [0; 32],
            delay_until_slot: 0,
            status: PolicyEvaluationStatus::Pending as u8,
            reason_code: 0,
            reserved: [0; 13],
        }
    }

    pub fn encode(self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::LEN {
            return false;
        }

        dst[..8].copy_from_slice(&self.discriminator);
        dst[8..40].copy_from_slice(&self.request_commitment);
        dst[40..72].copy_from_slice(&self.vault_id);
        dst[72..104].copy_from_slice(&self.action_hash);
        dst[104..136].copy_from_slice(&self.encrypted_input_commitment);
        dst[136..144].copy_from_slice(&self.policy_version.to_le_bytes());
        dst[144..152].copy_from_slice(&self.request_nonce.to_le_bytes());
        dst[152..160].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[160..168].copy_from_slice(&self.computation_offset.to_le_bytes());
        dst[168..200].copy_from_slice(&self.receipt_commitment);
        dst[200..232].copy_from_slice(&self.decision_commitment);
        dst[232..240].copy_from_slice(&self.delay_until_slot.to_le_bytes());
        dst[240] = self.status;
        dst[241..243].copy_from_slice(&self.reason_code.to_le_bytes());
        dst[243..256].copy_from_slice(&self.reserved);

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::LEN {
            return None;
        }

        let mut discriminator = [0; 8];
        discriminator.copy_from_slice(&src[..8]);
        if discriminator != POLICY_EVAL_DISCRIMINATOR {
            return None;
        }

        let mut request_commitment = [0; 32];
        request_commitment.copy_from_slice(&src[8..40]);

        let mut vault_id = [0; 32];
        vault_id.copy_from_slice(&src[40..72]);

        let mut action_hash = [0; 32];
        action_hash.copy_from_slice(&src[72..104]);

        let mut encrypted_input_commitment = [0; 32];
        encrypted_input_commitment.copy_from_slice(&src[104..136]);

        let mut policy_version = [0; 8];
        policy_version.copy_from_slice(&src[136..144]);

        let mut request_nonce = [0; 8];
        request_nonce.copy_from_slice(&src[144..152]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[152..160]);

        let mut computation_offset = [0; 8];
        computation_offset.copy_from_slice(&src[160..168]);

        let mut receipt_commitment = [0; 32];
        receipt_commitment.copy_from_slice(&src[168..200]);

        let mut decision_commitment = [0; 32];
        decision_commitment.copy_from_slice(&src[200..232]);

        let mut delay_until_slot = [0; 8];
        delay_until_slot.copy_from_slice(&src[232..240]);

        let mut reason_code = [0; 2];
        reason_code.copy_from_slice(&src[241..243]);

        let mut reserved = [0; 13];
        reserved.copy_from_slice(&src[243..256]);

        Some(Self {
            discriminator,
            request_commitment,
            vault_id,
            action_hash,
            encrypted_input_commitment,
            policy_version: u64::from_le_bytes(policy_version),
            request_nonce: u64::from_le_bytes(request_nonce),
            expiry_slot: u64::from_le_bytes(expiry_slot),
            computation_offset: u64::from_le_bytes(computation_offset),
            receipt_commitment,
            decision_commitment,
            delay_until_slot: u64::from_le_bytes(delay_until_slot),
            status: src[240],
            reason_code: u16::from_le_bytes(reason_code),
            reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyConfigState, PolicyEvaluationState, PolicyEvaluationStatus,
        POLICY_CONFIG_DISCRIMINATOR, POLICY_EVAL_DISCRIMINATOR,
    };

    #[test]
    fn policy_config_roundtrips_through_bytes() {
        let state = PolicyConfigState::new([1; 32], [2; 32], [3; 32], 9, 4);
        let mut bytes = [0u8; PolicyConfigState::LEN];

        assert!(state.encode(&mut bytes));
        assert_eq!(PolicyConfigState::decode(&bytes), Some(state));
        assert_eq!(state.discriminator, POLICY_CONFIG_DISCRIMINATOR);
    }

    #[test]
    fn policy_evaluation_state_roundtrips_through_bytes() {
        let mut state = PolicyEvaluationState::new([1; 32], [2; 32], [3; 32], [4; 32], 5, 6, 7, 8);
        state.status = PolicyEvaluationStatus::Finalized as u8;
        state.reason_code = 21;
        state.delay_until_slot = 9;
        state.receipt_commitment = [10; 32];
        state.decision_commitment = [11; 32];

        let mut bytes = [0u8; PolicyEvaluationState::LEN];
        assert!(state.encode(&mut bytes));
        assert_eq!(PolicyEvaluationState::decode(&bytes), Some(state));
        assert_eq!(state.discriminator, POLICY_EVAL_DISCRIMINATOR);
    }

    #[test]
    fn policy_config_decode_rejects_wrong_discriminator() {
        let state = PolicyConfigState::new([1; 32], [2; 32], [3; 32], 9, 4);
        let mut bytes = [0u8; PolicyConfigState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0..8].copy_from_slice(b"XXXXXXXX");
        assert_eq!(PolicyConfigState::decode(&bytes), None);
    }

    #[test]
    fn policy_evaluation_state_decode_rejects_wrong_discriminator() {
        let state = PolicyEvaluationState::new([1; 32], [2; 32], [3; 32], [4; 32], 5, 6, 7, 8);
        let mut bytes = [0u8; PolicyEvaluationState::LEN];
        assert!(state.encode(&mut bytes));
        bytes[0..8].copy_from_slice(b"XXXXXXXX");
        assert_eq!(PolicyEvaluationState::decode(&bytes), None);
    }
}
