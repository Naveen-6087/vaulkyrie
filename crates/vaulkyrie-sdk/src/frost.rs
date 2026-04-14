//! FROST DKG and threshold signing orchestration (behind the `frost` feature).
//!
//! This module re-exports key types from `vaulkyrie_frost` and provides
//! ergonomic wrappers for common SDK workflows like running a DKG ceremony,
//! signing a message, and verifying the result against `ed25519-dalek`.

pub use vaulkyrie_frost::{
    HarnessConfig, HarnessError, HarnessReport, RefreshReport, RetryReport, SolanaMessageReport,
    DEFAULT_MAX_SIGNERS, DEFAULT_MIN_SIGNERS,
};

/// Run a full DKG + signing ceremony over an arbitrary byte message using the
/// default 2-of-3 configuration.
pub fn dkg_sign(message: &[u8]) -> Result<HarnessReport, HarnessError> {
    vaulkyrie_frost::run_dkg_signing_harness(message)
}

/// Run a full DKG + signing ceremony with a custom configuration.
pub fn dkg_sign_with_config(
    message: &[u8],
    config: &HarnessConfig,
) -> Result<HarnessReport, HarnessError> {
    vaulkyrie_frost::run_dkg_signing_with_config(message, config)
}

/// Run a DKG and sign a serialized Solana legacy message.
pub fn dkg_sign_legacy_message() -> Result<SolanaMessageReport, HarnessError> {
    vaulkyrie_frost::run_dkg_legacy_message_harness()
}

/// Run a DKG and sign a serialized Solana legacy message with a custom config.
pub fn dkg_sign_legacy_message_with_config(
    config: &HarnessConfig,
) -> Result<SolanaMessageReport, HarnessError> {
    vaulkyrie_frost::run_dkg_legacy_message_with_config(config)
}

/// Run a DKG, refresh all shares, and sign a message with refreshed keys.
pub fn dkg_refresh_and_sign(message: &[u8]) -> Result<RefreshReport, HarnessError> {
    vaulkyrie_frost::run_share_refresh_harness(message)
}

/// Run a DKG with retries across different signer sets.
pub fn dkg_sign_with_retries(
    message: &[u8],
    config: &HarnessConfig,
    retry_signer_sets: &[Vec<u16>],
) -> Result<RetryReport, HarnessError> {
    vaulkyrie_frost::run_dkg_signing_with_retries(message, config, retry_signer_sets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkg_sign_produces_valid_report() {
        let report = dkg_sign(b"test message").unwrap();
        assert_eq!(report.group_public_key.len(), 32);
        assert_eq!(report.signature.len(), 64);
        assert!(!report.signer_set.is_empty());
    }

    #[test]
    fn dkg_sign_with_custom_config() {
        let config = HarnessConfig {
            min_signers: 2,
            max_signers: 3,
            signing_participants: vec![1, 3],
            rng_seed: [42; 32],
        };
        let report = dkg_sign_with_config(b"custom", &config).unwrap();
        assert_eq!(report.signer_set, vec![1, 3]);
    }

    #[test]
    fn legacy_message_signing_works() {
        let report = dkg_sign_legacy_message().unwrap();
        assert!(!report.message_bytes.is_empty());
        assert_eq!(report.report.signature.len(), 64);
    }

    #[test]
    fn share_refresh_preserves_group_key() {
        let report = dkg_refresh_and_sign(b"refresh test").unwrap();
        assert_eq!(
            report.original_group_public_key,
            report.refreshed_group_public_key,
        );
    }

    #[test]
    fn retry_harness_succeeds() {
        let config = HarnessConfig {
            min_signers: 2,
            max_signers: 3,
            signing_participants: vec![1, 2],
            rng_seed: [7; 32],
        };
        let sets = vec![vec![1, 2], vec![1, 3], vec![2, 3]];
        let report = dkg_sign_with_retries(b"retry", &config, &sets).unwrap();
        assert!(report.attempts >= 1);
    }
}
