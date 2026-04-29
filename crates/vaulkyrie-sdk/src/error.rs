//! Error code decoding for Vaulkyrie custom program errors.
//!
//! All error constants mirror those defined in `vaulkyrie-core::error` so
//! SDK consumers can map a `ProgramError::Custom(code)` to a human-readable
//! description without depending on the BPF-only core crate.

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

/// Decode a custom error code to a human-readable description.
///
/// Returns `None` for codes outside the Vaulkyrie error range.
pub fn decode_error(code: u32) -> Option<&'static str> {
    Some(match code {
        AUTHORITY_STATEMENT_EXPIRED => "authority rotation statement has expired",
        ORCHESTRATION_EXPIRED => "spend orchestration has expired",
        RECOVERY_EXPIRED => "recovery has expired",

        AUTHORITY_STATEMENT_REPLAY => "authority statement replayed (already consumed)",

        VAULT_AUTHORITY_MISMATCH => "vault authority hash does not match",
        AUTHORITY_ACTION_MISMATCH => "authority action hash mismatch",
        ORCHESTRATION_ACTION_MISMATCH => "orchestration action hash mismatch",
        AUTHORITY_SEQUENCE_MISMATCH => "authority sequence is not monotonically advancing",
        AUTHORITY_LEAF_INDEX_MISMATCH => "authority XMSS leaf index mismatch",
        AUTHORITY_PROOF_MISMATCH => "authority proof does not match expected",
        AUTHORITY_MERKLE_ROOT_MISMATCH => "authority merkle root does not match",
        VAULT_STATUS_BAD_TRANSITION => "invalid vault status transition",

        AUTHORITY_NO_OP => "authority rotation is a no-op",
        AUTHORITY_TREE_EXHAUSTED => "XMSS authority tree is exhausted",
        AUTHORITY_MIGRATION_NO_OP => "authority migration is a no-op (same root)",

        AUTHORITY_PROOF_INVALID => "WOTS+ authority proof is invalid",

        DUPLICATE_ACCOUNT_KEYS => "duplicate account keys in instruction",
        PROOF_CHUNK_OFFSET_MISMATCH => "proof chunk offset does not match bytes written",
        PROOF_CHUNK_OVERFLOW => "proof chunk would overflow proof buffer",
        PROOF_CHUNK_TOO_LARGE => "proof chunk exceeds maximum size",
        PROOF_STATEMENT_MISMATCH => "proof statement digest does not match",
        PROOF_COMMITMENT_MISMATCH => "proof commitment does not match",
        AUTHORITY_HASH_MISMATCH => "authority hash does not match vault state",

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_decode() {
        assert_eq!(
            decode_error(AUTHORITY_STATEMENT_EXPIRED),
            Some("authority rotation statement has expired")
        );
        assert_eq!(
            decode_error(DUPLICATE_ACCOUNT_KEYS),
            Some("duplicate account keys in instruction")
        );
    }

    #[test]
    fn unknown_code_returns_none() {
        assert_eq!(decode_error(0), None);
        assert_eq!(decode_error(9999), None);
    }

    #[test]
    fn all_codes_have_descriptions() {
        let codes = [
            AUTHORITY_STATEMENT_EXPIRED,
            ORCHESTRATION_EXPIRED,
            RECOVERY_EXPIRED,
            AUTHORITY_STATEMENT_REPLAY,
            VAULT_AUTHORITY_MISMATCH,
            AUTHORITY_ACTION_MISMATCH,
            ORCHESTRATION_ACTION_MISMATCH,
            AUTHORITY_SEQUENCE_MISMATCH,
            AUTHORITY_LEAF_INDEX_MISMATCH,
            AUTHORITY_PROOF_MISMATCH,
            AUTHORITY_MERKLE_ROOT_MISMATCH,
            VAULT_STATUS_BAD_TRANSITION,
            AUTHORITY_NO_OP,
            AUTHORITY_TREE_EXHAUSTED,
            AUTHORITY_MIGRATION_NO_OP,
            AUTHORITY_PROOF_INVALID,
            DUPLICATE_ACCOUNT_KEYS,
            PROOF_CHUNK_OFFSET_MISMATCH,
            PROOF_CHUNK_OVERFLOW,
            PROOF_CHUNK_TOO_LARGE,
            PROOF_STATEMENT_MISMATCH,
            PROOF_COMMITMENT_MISMATCH,
            AUTHORITY_HASH_MISMATCH,
        ];
        for code in codes {
            assert!(
                decode_error(code).is_some(),
                "code {code} has no description"
            );
        }
    }
}
