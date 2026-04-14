//! # Vaulkyrie — Encrypted Policy Instructions (Arcis MXE circuit stub)
//!
//! This crate contains the [Arcis](https://docs.arcium.com) circuit definitions
//! for Vaulkyrie's private policy evaluation plane. Arcis circuits run inside
//! Arcium's confidential Multi-party Execution Environment (MXE): inputs are
//! encrypted before they leave the client, the computation runs over encrypted
//! data, and only the commitment to the output is exposed on-chain.
//!
//! ## Design
//!
//! The policy evaluation flow is:
//!
//! ```text
//! Client                          Arcium MXE                vaulkyrie-policy-mxe
//! ──────                          ──────────                ────────────────────
//! encrypt(policy_inputs)
//!   → encrypted_input_commitment ──────────────────────────► InitPolicyEvaluation
//!                                                            QueueArciumComputation
//!                                 run(policy_evaluate)
//!                                   → receipt_commitment ──► FinalizeEvaluation (callback)
//! ```
//!
//! ## Build requirements
//!
//! This crate requires the `arcis` toolchain. It cannot be compiled with a
//! standard `cargo build`. Until the Arcis Rust SDK is stabilised and its
//! dependency graph is reconciled with the workspace SDK versions (currently
//! `solana-pubkey v4.x`), this module is excluded from the workspace build.
//!
//! When integration is ready, add `"crates/encrypted-ixs"` to
//! `[workspace.members]` in the root `Cargo.toml`.

// ── Policy evaluation circuit ──────────────────────────────────────────────

// NOTE: `#[encrypted]` and `#[instruction]` are Arcis proc-macro attributes.
// They are shown here as documentation of the intended circuit interface.
// Standard Rust compilation will not recognise these attributes.

/// Arcis circuit: evaluate Vaulkyrie spend policy over encrypted inputs.
///
/// # Inputs (encrypted)
/// - `encrypted_input`: 32-byte commitment to the policy evaluation request.
///   Encodes (vault_id, action_hash, threshold, policy_version, nonce,
///   expiry_slot) — encrypted by the client before submission.
///
/// # Output
/// - 32-byte `receipt_commitment` written back to the MXE output slot.
///   This value is compared against the `receipt_commitment` field of
///   `PolicyEvaluationState` in `FinalizeEvaluation`.
///
/// # Security properties
/// - Policy inputs never leave the client in plaintext.
/// - The MXE output is a deterministic commitment; the circuit cannot be
///   replayed with different inputs to produce the same output.
/// - The on-chain program (`vaulkyrie-policy-mxe`) only observes the
///   commitment, not the underlying policy parameters.
///
/// ```arcis
/// #[encrypted]
/// mod circuits {
///     #[instruction]
///     pub fn policy_evaluate(encrypted_input: [u8; 32]) -> [u8; 32] {
///         // Decrypt + evaluate risk policy over the input fields.
///         // Returns the SHA-256 commitment over the decision fields.
///         todo!()
///     }
/// }
/// ```
pub mod circuits {
    /// Placeholder representation of the `policy_evaluate` circuit output.
    /// Replace with the actual Arcis `#[instruction]` invocation.
    pub struct PolicyEvaluateOutput {
        /// SHA-256 commitment over the policy decision fields.
        pub receipt_commitment: [u8; 32],
    }
}

// ── Arcium CPI helpers (mirrors programs/vaulkyrie-policy-mxe/src/arcium_cpi.rs) ──

/// Discriminator for `queue_computation` in the Arcium MXE program.
/// SHA-256("global:queue_computation")[..8]
pub const QUEUE_COMPUTATION_DISCRIMINATOR: [u8; 8] = [1, 149, 103, 13, 102, 227, 93, 164];

/// Arcium MXE program ID on devnet/mainnet.
/// Source: https://docs.arcium.com/developers/program-ids
pub const ARCIUM_MXE_PROGRAM_ID: [u8; 32] = [
    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
    0x67, 0x89,
];
