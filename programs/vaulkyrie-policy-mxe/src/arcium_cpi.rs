/// Arcium MXE CPI interface constants for the Vaulkyrie policy bridge.
///
/// # Current status
///
/// The `QueueArciumComputation` instruction (discriminator `4` in policy-mxe)
/// updates the on-chain evaluation state machine but does **not** yet issue a
/// real CPI to the Arcium MXE program.  Wiring the actual CPI requires the
/// `arcium-anchor` crate which pulls in `anchor-lang = "0.32.1"` and
/// `solana-sdk ~2.2`, conflicting with the workspace's `solana-pubkey = "4.2.0"`.
///
/// When that conflict is resolved (e.g., by migrating this crate to an Anchor
/// workspace or by upstream `arcium-anchor` adopting solana-sdk v4), the
/// helpers below should be used to build the CPI instruction data and account
/// list.
///
/// # CPI call: `queue_computation`
///
/// Instruction data layout (after the 8-byte Anchor discriminator):
/// ```text
/// [0..8]   discriminator  = QUEUE_COMPUTATION_DISCRIMINATOR
/// [8..40]  encrypted_input: [u8; 32]   — encrypted policy input commitment
/// [40..48] computation_offset: u64 le  — correlates to PolicyEvaluationState
/// ```
///
/// Standard accounts (in order, per Arcium documentation):
/// 1. `mxe_account`          — the MXE PDA (readable)
/// 2. `mxe_program`          — Arcium MXE program ID (executable)
/// 3. `comp_def_account`     — computation definition PDA (readable)
/// 4. `cluster_account`      — cluster PDA (readable)
/// 5. `payer`                — fee payer (writable, signer)
/// 6. `system_program`       — system program
///
/// Reference: https://docs.arcium.com/solana-integration-and-multichain-coordination/solana-integration-orchestration-and-execution

/// Anchor discriminator for `queue_computation`.
///
/// Computed as `SHA256("global:queue_computation")[0..8]`.
pub const QUEUE_COMPUTATION_DISCRIMINATOR: [u8; 8] = [1, 149, 103, 13, 102, 227, 93, 164];

/// Anchor discriminator for `init_comp_def`.
///
/// Computed as `SHA256("global:init_comp_def")[0..8]`.
pub const INIT_COMP_DEF_DISCRIMINATOR: [u8; 8] = [100, 218, 60, 123, 106, 175, 186, 116];

/// Placeholder for the Arcium MXE program ID.
///
/// Replace with the real devnet/mainnet address once confirmed.
/// On devnet: `MXE111111111111111111111111111111111111111` (placeholder).
pub const ARCIUM_MXE_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Number of standard Arcium accounts required for a `queue_computation` CPI.
pub const ARCIUM_QUEUE_COMPUTATION_ACCOUNT_COUNT: usize = 6;

/// Build the raw instruction data for a `queue_computation` CPI.
///
/// `encrypted_input`    — 32-byte commitment to the encrypted policy input.
/// `computation_offset` — offset used to correlate the Arcium callback with
///                        the matching `PolicyEvaluationState` account.
pub fn build_queue_computation_data(
    encrypted_input: &[u8; 32],
    computation_offset: u64,
) -> [u8; 48] {
    let mut data = [0u8; 48];
    data[..8].copy_from_slice(&QUEUE_COMPUTATION_DISCRIMINATOR);
    data[8..40].copy_from_slice(encrypted_input);
    data[40..48].copy_from_slice(&computation_offset.to_le_bytes());
    data
}
