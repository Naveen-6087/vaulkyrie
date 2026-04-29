//! # Vaulkyrie — Encrypted Policy Instructions (Arcis MXE Circuit)
//!
//! This crate contains the [Arcis](https://docs.arcium.com) circuit definitions
//! for Vaulkyrie's private policy evaluation plane. Arcis circuits run inside
//! Arcium's confidential Multi-party Execution Environment (MXE): inputs are
//! encrypted before they leave the client, the computation runs over encrypted
//! data, and only compact decision material is exposed on-chain.
//!
//! ## Flow
//!
//! ```text
//! Client                     Arcium MXE            vaulkyrie-policy-mxe   vaulkyrie-core
//! ──────                     ──────────            ────────────────────   ──────────────
//! pack(private_policy_signals)
//! encrypt(signal_lanes)
//!   → encrypted_commitment ─────────────────────► init_policy_evaluation
//!                                                  queue_policy_evaluate
//!                            run(policy_evaluate)
//!                              → decision summary ► policy_evaluate_callback
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
//!
//! ## Arcium packing model
//!
//! Arcium recommends packing many small values into fewer field elements. The
//! Vaulkyrie policy engine mirrors that approach by packing all private policy
//! buckets into two `u128` lanes before encryption. The wallet SDK mirrors the
//! same packing logic in `vaulkyrie_protocol::PolicySignals::pack_lanes()`.
//!
//! Vaulkyrie's privacy layer uses the same Arcium constraint model, but for a
//! different purpose: private wallet intents. The privacy circuit receives
//! encrypted signal lanes describing a shield/deposit, private transfer,
//! withdraw, swap intent, or sealed receipt request. It returns compact
//! decision material and a receipt commitment; full note sets, balances, and
//! private metadata stay encrypted or local to the wallet.

// ── Policy evaluation circuit ──────────────────────────────────────────────

// NOTE: `#[encrypted]` and `#[instruction]` are Arcis proc-macro attributes.
// They are shown here as documentation of the intended circuit interface.
// Standard Rust compilation will not recognise these attributes.

/// Arcis circuit: evaluate Vaulkyrie spend/admin policy over packed encrypted
/// signal lanes.
///
/// # Inputs (encrypted)
///
/// The circuit receives two packed `u128` lanes. The host-side wallet SDK packs
/// the following fields into those lanes before encrypting them for the MXE:
///
/// - policy template
/// - scope (spend/admin/recovery)
/// - amount bucket
/// - balance bucket
/// - limit headroom bucket
/// - velocity bucket
/// - recipient class
/// - protocol risk
/// - device trust
/// - history bucket
/// - guardian posture
/// - private policy flags
///
/// The public request state (`action_hash`, `policy_version`, `request_nonce`,
/// `expiry_slot`) remains in `PolicyEvaluationState`; the private signal lanes
/// are bound into that request via `encrypted_input_commitment`.
///
/// # Output
///
/// The MXE returns:
///
/// - `receipt_commitment`
/// - `decision_commitment`
/// - `delay_until_slot`
/// - `reason_code`
/// - `decision_flags`
/// - `approved`
///
/// # Security properties
///
/// - Policy inputs never leave the client in plaintext.
/// - The MXE output is a deterministic decision summary; replaying the circuit
///   with different buckets or flags changes the commitments and flags.
/// - `vaulkyrie-policy-mxe` only observes compact commitments and decision
///   flags, not the underlying policy parameters.
/// - The receipt commitment is cross-validated by `vaulkyrie-core` via
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
///     pub fn policy_evaluate(
///         lane_0: Enc<Shared, u128>,
///         lane_1: Enc<Shared, u128>,
///     ) -> (
///         Enc<Shared, [u8; 32]>,
///         Enc<Shared, [u8; 32]>,
///         u64,
///         u16,
///         u16,
///         u8,
///     ) {
///         let lane_0 = lane_0.to_arcis();
///         let lane_1 = lane_1.to_arcis();
///         let signals = unpack_policy_signals(lane_0, lane_1);
///
///         // Evaluate template-driven risk policy over encrypted buckets.
///         let decision = evaluate_policy(signals);
///
///         (
///             receipt_commitment(decision),
///             decision_commitment(decision),
///             decision.delay_until_slot,
///             decision.reason_code,
///             decision.decision_flags,
///             decision.risk_score,
///             decision.risk_tier,
///             decision.approved,
///         )
///     }
/// }
/// ```
pub mod circuits {
    pub const POLICY_SIGNAL_LANES: usize = 2;
    pub const PRIVACY_SIGNAL_LANES: usize = 2;

    /// Representation of the `policy_evaluate` circuit output.
    /// When Arcis compilation is available, replace this with the generated
    /// output type.
    pub struct PolicyEvaluateOutput {
        pub receipt_commitment: [u8; 32],
        pub decision_commitment: [u8; 32],
        pub delay_until_slot: u64,
        pub reason_code: u16,
        pub decision_flags: u16,
        pub risk_score: u16,
        pub risk_tier: u8,
        pub approved: u8,
    }

    /// Packed representation of the private signal lanes that the wallet will
    /// encrypt before submitting to `queue_policy_evaluate`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PolicyEvaluateInput {
        pub signal_lane_0: u128,
        pub signal_lane_1: u128,
    }

    impl PolicyEvaluateInput {
        pub fn encode(&self) -> [u8; 32] {
            let mut buf = [0u8; 32];
            buf[0..16].copy_from_slice(&self.signal_lane_0.to_le_bytes());
            buf[16..32].copy_from_slice(&self.signal_lane_1.to_le_bytes());
            buf
        }

        pub fn decode(src: &[u8; 32]) -> Self {
            let mut lane_0 = [0u8; 16];
            lane_0.copy_from_slice(&src[0..16]);
            let mut lane_1 = [0u8; 16];
            lane_1.copy_from_slice(&src[16..32]);

            Self {
                signal_lane_0: u128::from_le_bytes(lane_0),
                signal_lane_1: u128::from_le_bytes(lane_1),
            }
        }
    }

    /// Representation of the `privacy_evaluate` circuit output.
    ///
    /// The real Arcis implementation should compute this over encrypted
    /// `PrivacySignals` lanes and bind it to an action-specific
    /// `PrivacyIntent` commitment supplied by the caller program.
    pub struct PrivacyEvaluateOutput {
        pub receipt_commitment: [u8; 32],
        pub intent_commitment: [u8; 32],
        pub decision_flags: u16,
        pub privacy_score: u16,
        pub min_confirmations: u8,
        pub provider_code: u8,
        pub approved: u8,
    }

    /// Packed representation of the private wallet intent signals.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrivacyEvaluateInput {
        pub signal_lane_0: u128,
        pub signal_lane_1: u128,
    }

    impl PrivacyEvaluateInput {
        pub fn encode(&self) -> [u8; 32] {
            let mut buf = [0u8; 32];
            buf[0..16].copy_from_slice(&self.signal_lane_0.to_le_bytes());
            buf[16..32].copy_from_slice(&self.signal_lane_1.to_le_bytes());
            buf
        }

        pub fn decode(src: &[u8; 32]) -> Self {
            let mut lane_0 = [0u8; 16];
            lane_0.copy_from_slice(&src[0..16]);
            let mut lane_1 = [0u8; 16];
            lane_1.copy_from_slice(&src[16..32]);

            Self {
                signal_lane_0: u128::from_le_bytes(lane_0),
                signal_lane_1: u128::from_le_bytes(lane_1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::circuits::{
        PolicyEvaluateInput, PrivacyEvaluateInput, POLICY_SIGNAL_LANES, PRIVACY_SIGNAL_LANES,
    };

    #[test]
    fn policy_input_roundtrip() {
        let input = PolicyEvaluateInput {
            signal_lane_0: 0xAABBCCDDEEFFu128,
            signal_lane_1: 0x1122334455667788u128,
        };
        let encoded = input.encode();
        assert_eq!(encoded.len(), 32);
        let decoded = PolicyEvaluateInput::decode(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn policy_input_keeps_two_fixed_signal_lanes() {
        assert_eq!(POLICY_SIGNAL_LANES, 2);
    }

    #[test]
    fn privacy_input_roundtrip() {
        let input = PrivacyEvaluateInput {
            signal_lane_0: 0x010203040506u128,
            signal_lane_1: 0xFFEEDDCCBBAA9988u128,
        };
        let encoded = input.encode();
        assert_eq!(encoded.len(), 32);
        let decoded = PrivacyEvaluateInput::decode(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn privacy_input_keeps_two_fixed_signal_lanes() {
        assert_eq!(PRIVACY_SIGNAL_LANES, 2);
    }
}
