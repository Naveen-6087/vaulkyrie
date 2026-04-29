// Vaulkyrie custom error codes for `ProgramError::Custom(code)`.
//
// Each `TransitionError` variant and each processor-level validation gets a
// unique code so clients can distinguish failures without parsing log lines.

// ─── Expiry domain (6000–6009) ───────────────────────────────────────────────
pub const AUTHORITY_STATEMENT_EXPIRED: u32 = 6002;
pub const ORCHESTRATION_EXPIRED: u32 = 6003;
pub const RECOVERY_EXPIRED: u32 = 6004;

// ─── Replay domain (6010–6019) ───────────────────────────────────────────────
pub const AUTHORITY_STATEMENT_REPLAY: u32 = 6011;

// ─── Mismatch domain (6020–6039) ─────────────────────────────────────────────
pub const VAULT_AUTHORITY_MISMATCH: u32 = 6020;
pub const AUTHORITY_ACTION_MISMATCH: u32 = 6024;
pub const ORCHESTRATION_ACTION_MISMATCH: u32 = 6025;
pub const AUTHORITY_SEQUENCE_MISMATCH: u32 = 6026;
pub const AUTHORITY_LEAF_INDEX_MISMATCH: u32 = 6027;
pub const AUTHORITY_PROOF_MISMATCH: u32 = 6028;
pub const AUTHORITY_MERKLE_ROOT_MISMATCH: u32 = 6029;
pub const VAULT_STATUS_BAD_TRANSITION: u32 = 6030;

// ─── Constraint domain (6040–6049) ───────────────────────────────────────────
pub const AUTHORITY_NO_OP: u32 = 6041;
pub const AUTHORITY_TREE_EXHAUSTED: u32 = 6042;
pub const AUTHORITY_MIGRATION_NO_OP: u32 = 6043;

// ─── Proof / validation domain (6050–6059) ───────────────────────────────────
pub const AUTHORITY_PROOF_INVALID: u32 = 6050;

// ─── Processor-level validation (6100–6119) ──────────────────────────────────
pub const DUPLICATE_ACCOUNT_KEYS: u32 = 6100;
pub const PROOF_CHUNK_OFFSET_MISMATCH: u32 = 6101;
pub const PROOF_CHUNK_OVERFLOW: u32 = 6102;
pub const PROOF_CHUNK_TOO_LARGE: u32 = 6103;
pub const PROOF_STATEMENT_MISMATCH: u32 = 6104;
pub const PROOF_COMMITMENT_MISMATCH: u32 = 6105;
pub const AUTHORITY_HASH_MISMATCH: u32 = 6106;
