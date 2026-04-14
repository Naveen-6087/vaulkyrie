//! # Vaulkyrie — Encrypted Policy Instructions (Arcis MXE Circuit)
//!
//! This crate contains the [Arcis](https://docs.arcium.com) circuit definitions
//! for Vaulkyrie's private policy evaluation plane. Arcis circuits run inside
//! Arcium's confidential Multi-party Execution Environment (MXE): inputs are
//! encrypted before they leave the client, the computation runs over encrypted
//! data, and only the commitment to the output is exposed on-chain.
//!
//! ## Flow
//!
//! ```text
//! Client                     Arcium MXE            vaulkyrie-policy-mxe   vaulkyrie-core
//! ──────                     ──────────            ────────────────────   ──────────────
//! encrypt(policy_inputs)
//!   → encrypted_commitment ─────────────────────► init_policy_evaluation
//!                                                  queue_policy_evaluate
//!                            run(policy_evaluate)
//!                              → receipt_commitment ► policy_evaluate_callback
//!                                                                        stage_bridged_receipt
//! ```
//!
//! ## CPI integration
//!
//! The Arcium CPI (`queue_computation`, `init_comp_def`, callbacks) lives in
//! `programs/vaulkyrie-policy-mxe`. That program uses `arcium-anchor` 0.9.3
//! to queue encrypted computations and receive callback results. This crate
//! defines only the circuit logic that runs inside the MXE.
//!
//! ## Build requirements
//!
//! This crate requires the `arcis` toolchain. It cannot be compiled with a
//! standard `cargo build`. When the Arcis toolchain is available:
//!
//! ```sh
//! arcis build --manifest-path crates/encrypted-ixs/Cargo.toml
//! ```
//!
//! The compiled artifacts (`.arcis`, `.idarc`, `.weight`) are consumed by
//! `vaulkyrie-policy-mxe` when calling `init_comp_def` and `queue_computation`.

// ── Policy evaluation circuit ──────────────────────────────────────────────

// NOTE: `#[encrypted]` and `#[instruction]` are Arcis proc-macro attributes.
// They are shown here as documentation of the intended circuit interface.
// Standard Rust compilation will not recognise these attributes.

/// Arcis circuit: evaluate Vaulkyrie spend policy over encrypted inputs.
///
/// # Inputs (encrypted)
///
/// The circuit receives a 75-byte encrypted input packed as:
///
/// | Offset | Size | Field             |
/// |--------|------|-------------------|
/// | 0      | 32   | `vault_id`        |
/// | 32     | 32   | `action_hash`     |
/// | 64     | 1    | `threshold`       |
/// | 65     | 8    | `policy_version`  |
/// | 73     | 1    | `nonce` (u8 slot) |
/// | 74     | 1    | `reserved`        |
///
/// These fields match the `PolicyEvaluationState` stored by
/// `vaulkyrie-policy-mxe::init_policy_evaluation`.
///
/// # Output
///
/// A 32-byte `receipt_commitment` = SHA-256(vault_id || action_hash ||
/// threshold || policy_version || nonce || decision_flags). This commitment
/// is written to the MXE output slot and delivered to the on-chain callback
/// `policy_evaluate_callback` in `vaulkyrie-policy-mxe`.
///
/// # Security properties
///
/// - Policy inputs never leave the client in plaintext.
/// - The MXE output is a deterministic commitment; replaying the circuit
///   with different inputs produces a different commitment.
/// - `vaulkyrie-policy-mxe` only observes the commitment, not the
///   underlying policy parameters.
/// - The commitment is cross-validated by `vaulkyrie-core` via
///   `StageBridgedReceipt` before any vault state transition occurs.
///
/// # Arcis pseudo-code
///
/// ```arcis
/// #[encrypted]
/// mod circuits {
///     use arcis::prelude::*;
///
///     #[instruction]
///     pub fn policy_evaluate(encrypted_input: [u8; 75]) -> [u8; 32] {
///         let vault_id: [u8; 32] = encrypted_input[0..32];
///         let action_hash: [u8; 32] = encrypted_input[32..64];
///         let threshold: u8 = encrypted_input[64];
///         let policy_version: u64 = u64::from_le_bytes(encrypted_input[65..73]);
///         let nonce: u8 = encrypted_input[73];
///
///         // Evaluate risk policy: check threshold config, spending limits,
///         // velocity constraints, and multi-sig requirements.
///         let decision_flags: u8 = evaluate_policy(
///             vault_id, action_hash, threshold, policy_version,
///         );
///
///         // Commit to the full decision.
///         sha256(vault_id || action_hash || threshold
///                || policy_version || nonce || decision_flags)
///     }
/// }
/// ```
pub mod circuits {
    /// Size of the encrypted input payload in bytes.
    pub const POLICY_INPUT_SIZE: usize = 75;

    /// Representation of the `policy_evaluate` circuit output.
    ///
    /// When Arcis compilation is available, replace this with the actual
    /// `#[instruction]` return type.
    pub struct PolicyEvaluateOutput {
        /// SHA-256 commitment over the full policy decision fields.
        pub receipt_commitment: [u8; 32],
    }

    /// Packed representation of policy evaluation input fields.
    ///
    /// This mirrors the encrypted input layout that the Arcis circuit
    /// decrypts inside the MXE. Clients encrypt this struct before
    /// submitting to `init_policy_evaluation`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PolicyEvaluateInput {
        pub vault_id: [u8; 32],
        pub action_hash: [u8; 32],
        pub threshold: u8,
        pub policy_version: u64,
        pub nonce: u8,
        pub reserved: u8,
    }

    impl PolicyEvaluateInput {
        /// Encode into a 75-byte buffer for encryption.
        pub fn encode(&self) -> [u8; POLICY_INPUT_SIZE] {
            let mut buf = [0u8; POLICY_INPUT_SIZE];
            buf[0..32].copy_from_slice(&self.vault_id);
            buf[32..64].copy_from_slice(&self.action_hash);
            buf[64] = self.threshold;
            buf[65..73].copy_from_slice(&self.policy_version.to_le_bytes());
            buf[73] = self.nonce;
            buf[74] = self.reserved;
            buf
        }

        /// Decode from a 75-byte buffer.
        pub fn decode(src: &[u8; POLICY_INPUT_SIZE]) -> Self {
            let mut vault_id = [0u8; 32];
            vault_id.copy_from_slice(&src[0..32]);
            let mut action_hash = [0u8; 32];
            action_hash.copy_from_slice(&src[32..64]);
            let mut pv = [0u8; 8];
            pv.copy_from_slice(&src[65..73]);
            Self {
                vault_id,
                action_hash,
                threshold: src[64],
                policy_version: u64::from_le_bytes(pv),
                nonce: src[73],
                reserved: src[74],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::circuits::{PolicyEvaluateInput, POLICY_INPUT_SIZE};

    #[test]
    fn policy_input_roundtrip() {
        let input = PolicyEvaluateInput {
            vault_id: [0xAA; 32],
            action_hash: [0xBB; 32],
            threshold: 2,
            policy_version: 42,
            nonce: 7,
            reserved: 0,
        };
        let encoded = input.encode();
        assert_eq!(encoded.len(), POLICY_INPUT_SIZE);
        let decoded = PolicyEvaluateInput::decode(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn policy_input_size_matches_mxe_has_size() {
        // Must stay in sync with HasSize::SIZE = 75 in vaulkyrie-policy-mxe.
        assert_eq!(POLICY_INPUT_SIZE, 75);
    }
}
