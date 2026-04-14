use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use frost_ed25519 as frost;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use solana_hash::Hash as SolanaHash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::legacy::Message as LegacyMessage;
use solana_pubkey::Pubkey as SolanaPubkey;

pub const DEFAULT_MIN_SIGNERS: u16 = 2;
pub const DEFAULT_MAX_SIGNERS: u16 = 3;

#[derive(Debug)]
pub enum HarnessError {
    Frost(frost::Error),
    InvalidVerifyingKey(ed25519_dalek::SignatureError),
    InvalidConfig(&'static str),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frost(err) => write!(f, "frost error: {err}"),
            Self::InvalidVerifyingKey(err) => write!(f, "invalid ed25519 verifying key: {err}"),
            Self::InvalidConfig(reason) => write!(f, "invalid harness config: {reason}"),
        }
    }
}

impl std::error::Error for HarnessError {}

impl From<frost::Error> for HarnessError {
    fn from(value: frost::Error) -> Self {
        Self::Frost(value)
    }
}

impl From<ed25519_dalek::SignatureError> for HarnessError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        Self::InvalidVerifyingKey(value)
    }
}

#[derive(Debug, Clone)]
pub struct HarnessReport {
    pub group_public_key: [u8; 32],
    pub signature: [u8; 64],
    pub signer_set: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct RefreshReport {
    pub original_group_public_key: [u8; 32],
    pub refreshed_group_public_key: [u8; 32],
    pub signature: [u8; 64],
    pub signer_set: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct RetryReport {
    pub attempts: u16,
    pub successful_signer_set: Vec<u16>,
    pub report: HarnessReport,
}

#[derive(Debug, Clone)]
pub struct SolanaMessageReport {
    pub message_bytes: Vec<u8>,
    pub report: HarnessReport,
}

pub fn run_dkg_signing_harness(message: &[u8]) -> Result<HarnessReport, HarnessError> {
    let config = HarnessConfig::default();
    run_dkg_signing_with_config(message, &config)
}

pub fn run_dkg_legacy_message_harness() -> Result<SolanaMessageReport, HarnessError> {
    let config = HarnessConfig::default();
    run_dkg_legacy_message_with_config(&config)
}

#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub min_signers: u16,
    pub max_signers: u16,
    pub signing_participants: Vec<u16>,
    pub rng_seed: [u8; 32],
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            min_signers: DEFAULT_MIN_SIGNERS,
            max_signers: DEFAULT_MAX_SIGNERS,
            signing_participants: vec![1, 2],
            rng_seed: [11; 32],
        }
    }
}

pub fn run_dkg_signing_with_config(
    message: &[u8],
    config: &HarnessConfig,
) -> Result<HarnessReport, HarnessError> {
    validate_config(config)?;
    let mut rng = ChaCha20Rng::from_seed(config.rng_seed);
    let signing_participants = parse_signing_participants(config)?;
    let (key_packages, public_key_package) = run_dkg(config, &mut rng)?;
    let (public_key_bytes, signature_bytes) = sign_with_key_packages(
        message,
        &key_packages,
        &public_key_package,
        &signing_participants,
        &mut rng,
    )?;

    Ok(HarnessReport {
        group_public_key: public_key_bytes,
        signature: signature_bytes,
        signer_set: config.signing_participants.clone(),
    })
}

pub fn run_dkg_legacy_message_with_config(
    config: &HarnessConfig,
) -> Result<SolanaMessageReport, HarnessError> {
    let message_bytes = build_sample_legacy_message();
    let report = run_dkg_signing_with_config(&message_bytes, config)?;

    Ok(SolanaMessageReport {
        message_bytes,
        report,
    })
}

pub fn run_share_refresh_harness(message: &[u8]) -> Result<RefreshReport, HarnessError> {
    let config = HarnessConfig::default();
    run_share_refresh_with_config(message, &config)
}

pub fn run_share_refresh_with_config(
    message: &[u8],
    config: &HarnessConfig,
) -> Result<RefreshReport, HarnessError> {
    validate_config(config)?;
    let mut dkg_rng = ChaCha20Rng::from_seed(config.rng_seed);
    let signing_participants = parse_signing_participants(config)?;
    let (initial_key_packages, public_key_package) = run_dkg(config, &mut dkg_rng)?;

    let all_identifiers = participant_identifiers(config.max_signers)?;
    let mut refresh_rng = ChaCha20Rng::from_seed([29; 32]);
    let (refreshing_shares, refreshed_public_key_package) =
        frost::keys::refresh::compute_refreshing_shares::<frost::Ed25519Sha512, _>(
            public_key_package.clone(),
            config.max_signers,
            config.min_signers,
            &all_identifiers,
            &mut refresh_rng,
        )?;

    let mut refreshed_key_packages = BTreeMap::new();
    for (identifier, zero_share) in all_identifiers.iter().zip(refreshing_shares.into_iter()) {
        let old_key_package = initial_key_packages
            .get(identifier)
            .ok_or(HarnessError::InvalidConfig("missing original key package"))?;
        let refreshed_key_package = frost::keys::refresh::refresh_share::<frost::Ed25519Sha512>(
            zero_share,
            old_key_package,
        )?;
        refreshed_key_packages.insert(*identifier, refreshed_key_package);
    }

    let (original_group_public_key, _) = sign_with_key_packages(
        message,
        &initial_key_packages,
        &public_key_package,
        &signing_participants,
        &mut dkg_rng,
    )?;
    let (refreshed_group_public_key, signature) = sign_with_key_packages(
        message,
        &refreshed_key_packages,
        &refreshed_public_key_package,
        &signing_participants,
        &mut refresh_rng,
    )?;

    Ok(RefreshReport {
        original_group_public_key,
        refreshed_group_public_key,
        signature,
        signer_set: config.signing_participants.clone(),
    })
}

pub fn run_dkg_signing_with_retries(
    message: &[u8],
    base_config: &HarnessConfig,
    retry_signer_sets: &[Vec<u16>],
) -> Result<RetryReport, HarnessError> {
    if retry_signer_sets.is_empty() {
        return Err(HarnessError::InvalidConfig(
            "retry signer set list must be non-empty",
        ));
    }

    let mut last_error: Option<HarnessError> = None;

    for (index, signer_set) in retry_signer_sets.iter().enumerate() {
        let mut attempt_config = base_config.clone();
        attempt_config.signing_participants = signer_set.clone();
        match run_dkg_signing_with_config(message, &attempt_config) {
            Ok(report) => {
                return Ok(RetryReport {
                    attempts: u16::try_from(index + 1)
                        .map_err(|_| HarnessError::InvalidConfig("retry attempts exceed u16"))?,
                    successful_signer_set: signer_set.clone(),
                    report,
                });
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or(HarnessError::InvalidConfig(
        "retry attempts exhausted without error",
    )))
}

fn identifier_from_u16(participant: u16) -> Result<frost::Identifier, HarnessError> {
    participant
        .try_into()
        .map_err(|_| HarnessError::InvalidConfig("participant id must be in range"))
}

fn parse_signing_participants(
    config: &HarnessConfig,
) -> Result<Vec<frost::Identifier>, HarnessError> {
    config
        .signing_participants
        .iter()
        .copied()
        .map(identifier_from_u16)
        .collect()
}

fn participant_identifiers(max_signers: u16) -> Result<Vec<frost::Identifier>, HarnessError> {
    (1..=max_signers).map(identifier_from_u16).collect()
}

fn run_dkg(
    config: &HarnessConfig,
    rng: &mut ChaCha20Rng,
) -> Result<
    (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ),
    HarnessError,
> {
    let mut round1_secret_packages = BTreeMap::new();
    let mut round1_public_packages = BTreeMap::new();

    for participant in 1..=config.max_signers {
        let identifier = identifier_from_u16(participant)?;
        let (secret_package, public_package) = frost::keys::dkg::part1(
            identifier,
            config.max_signers,
            config.min_signers,
            &mut *rng,
        )?;
        round1_secret_packages.insert(identifier, secret_package);
        round1_public_packages.insert(identifier, public_package);
    }

    let mut round2_secret_packages = BTreeMap::new();
    let mut round2_public_packages: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();

    for participant in 1..=config.max_signers {
        let identifier = identifier_from_u16(participant)?;
        let peer_round1_packages = round1_public_packages
            .iter()
            .filter(|(peer_identifier, _)| **peer_identifier != identifier)
            .map(|(peer_identifier, package)| (*peer_identifier, package.clone()))
            .collect();

        let round1_secret = round1_secret_packages
            .get(&identifier)
            .ok_or(HarnessError::InvalidConfig("missing round1 secret package"))?
            .clone();
        let (secret_package, packages) =
            frost::keys::dkg::part2(round1_secret, &peer_round1_packages)?;

        round2_secret_packages.insert(identifier, secret_package);

        for (receiver, package) in packages {
            round2_public_packages
                .entry(receiver)
                .or_default()
                .insert(identifier, package);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_key_package = None;

    for participant in 1..=config.max_signers {
        let identifier = identifier_from_u16(participant)?;
        let peer_round1_packages = round1_public_packages
            .iter()
            .filter(|(peer_identifier, _)| **peer_identifier != identifier)
            .map(|(peer_identifier, package)| (*peer_identifier, package.clone()))
            .collect();

        let round2_secret = round2_secret_packages
            .get(&identifier)
            .ok_or(HarnessError::InvalidConfig("missing round2 secret package"))?;
        let round2_packages =
            round2_public_packages
                .get(&identifier)
                .ok_or(HarnessError::InvalidConfig(
                    "missing round2 public package set",
                ))?;
        let (key_package, participant_public_key_package) =
            frost::keys::dkg::part3(round2_secret, &peer_round1_packages, round2_packages)?;

        key_packages.insert(identifier, key_package);
        public_key_package = Some(participant_public_key_package);
    }

    let public_key_package =
        public_key_package.ok_or(HarnessError::InvalidConfig("dkg produced no public key"))?;

    Ok((key_packages, public_key_package))
}

fn sign_with_key_packages(
    message: &[u8],
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: &frost::keys::PublicKeyPackage,
    signing_participants: &[frost::Identifier],
    rng: &mut ChaCha20Rng,
) -> Result<([u8; 32], [u8; 64]), HarnessError> {
    let mut nonce_commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();

    for identifier in signing_participants {
        let key_package = key_packages
            .get(identifier)
            .ok_or(HarnessError::InvalidConfig(
                "missing key package for signer",
            ))?;
        let (nonce, commitments) = frost::round1::commit(key_package.signing_share(), &mut *rng);
        nonces.insert(*identifier, nonce);
        nonce_commitments.insert(*identifier, commitments);
    }

    let signing_package = frost::SigningPackage::new(nonce_commitments, message);
    let mut signature_shares = BTreeMap::new();

    for identifier in signing_participants {
        let key_package = key_packages
            .get(identifier)
            .ok_or(HarnessError::InvalidConfig(
                "missing key package for signer",
            ))?;
        let nonce = nonces
            .get(identifier)
            .ok_or(HarnessError::InvalidConfig("missing nonce for signer"))?;
        let signature_share = frost::round2::sign(&signing_package, nonce, key_package)?;
        signature_shares.insert(*identifier, signature_share);
    }

    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, public_key_package)?;
    public_key_package
        .verifying_key()
        .verify(message, &group_signature)?;

    let public_key_bytes: [u8; 32] = public_key_package
        .verifying_key()
        .serialize()?
        .try_into()
        .map_err(|_| HarnessError::InvalidConfig("ed25519 public key must be 32 bytes"))?;
    let signature_bytes: [u8; 64] = group_signature
        .serialize()?
        .try_into()
        .map_err(|_| HarnessError::InvalidConfig("ed25519 signature must be 64 bytes"))?;

    let dalek_key = DalekVerifyingKey::from_bytes(&public_key_bytes)?;
    let dalek_signature = DalekSignature::from_bytes(&signature_bytes);
    dalek_key
        .verify(message, &dalek_signature)
        .map_err(HarnessError::from)?;

    Ok((public_key_bytes, signature_bytes))
}

fn build_sample_legacy_message() -> Vec<u8> {
    let payer = SolanaPubkey::from([1; 32]);
    let writable_target = SolanaPubkey::from([2; 32]);
    let readonly_target = SolanaPubkey::from([3; 32]);
    let program_id = SolanaPubkey::from([9; 32]);
    let blockhash = SolanaHash::new_from_array([7; 32]);

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(writable_target, false),
            AccountMeta::new_readonly(readonly_target, false),
        ],
        data: vec![1, 3, 3, 7],
    };

    LegacyMessage::new_with_blockhash(&[instruction], Some(&payer), &blockhash).serialize()
}

fn validate_config(config: &HarnessConfig) -> Result<(), HarnessError> {
    if config.min_signers == 0 || config.max_signers == 0 {
        return Err(HarnessError::InvalidConfig(
            "min/max signers must be non-zero",
        ));
    }
    if config.min_signers > config.max_signers {
        return Err(HarnessError::InvalidConfig(
            "min_signers must be <= max_signers",
        ));
    }
    if config.signing_participants.len() < usize::from(config.min_signers) {
        return Err(HarnessError::InvalidConfig(
            "signing participants below threshold",
        ));
    }
    if config.signing_participants.len() > usize::from(config.max_signers) {
        return Err(HarnessError::InvalidConfig(
            "signing participants exceed max_signers",
        ));
    }

    let mut seen = BTreeSet::new();
    for participant in &config.signing_participants {
        if *participant == 0 || *participant > config.max_signers {
            return Err(HarnessError::InvalidConfig(
                "signing participant out of DKG range",
            ));
        }

        if !seen.insert(*participant) {
            return Err(HarnessError::InvalidConfig(
                "signing participants must be unique",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        run_dkg_legacy_message_harness, run_dkg_legacy_message_with_config, run_dkg_signing_harness,
        run_dkg_signing_with_config, run_dkg_signing_with_retries, run_share_refresh_harness,
        HarnessConfig, HarnessError,
    };
    use solana_signature::Signature as SolanaSignature;

    #[test]
    fn dkg_harness_produces_standard_key_and_signature_lengths() {
        let report = run_dkg_signing_harness(b"vaulkyrie frost harness")
            .expect("dealerless dkg and signing should succeed");

        assert_eq!(report.group_public_key.len(), 32);
        assert_eq!(report.signature.len(), 64);
    }

    #[test]
    fn dkg_harness_is_deterministic_for_fixed_rng_seed() {
        let first =
            run_dkg_signing_harness(b"vaulkyrie frost harness").expect("first run should succeed");
        let second =
            run_dkg_signing_harness(b"vaulkyrie frost harness").expect("second run should succeed");

        assert_eq!(first.group_public_key, second.group_public_key);
        assert_eq!(first.signature, second.signature);
    }

    #[test]
    fn dkg_harness_signature_verifies_with_solana_signature_api() {
        let message = b"vaulkyrie frost harness";
        let report = run_dkg_signing_harness(message).expect("run should succeed");

        let solana_signature = SolanaSignature::from(report.signature);

        assert!(solana_signature.verify(&report.group_public_key, message));
    }

    #[test]
    fn legacy_message_harness_signs_serialized_solana_message_bytes() {
        let report =
            run_dkg_legacy_message_harness().expect("legacy message signing harness should succeed");
        let solana_signature = SolanaSignature::from(report.report.signature);

        assert!(!report.message_bytes.is_empty());
        assert!(solana_signature.verify(&report.report.group_public_key, &report.message_bytes));
    }

    #[test]
    fn legacy_message_harness_supports_custom_signer_set() {
        let config = HarnessConfig {
            min_signers: 3,
            max_signers: 5,
            signing_participants: vec![1, 3, 5],
            rng_seed: [41; 32],
        };

        let report = run_dkg_legacy_message_with_config(&config)
            .expect("legacy message harness should support custom signer sets");
        let solana_signature = SolanaSignature::from(report.report.signature);

        assert_eq!(report.report.signer_set, vec![1, 3, 5]);
        assert!(solana_signature.verify(&report.report.group_public_key, &report.message_bytes));
    }

    #[test]
    fn dkg_harness_supports_custom_signer_set() {
        let message = b"vaulkyrie custom signers";
        let config = HarnessConfig {
            min_signers: 3,
            max_signers: 5,
            signing_participants: vec![1, 3, 5],
            rng_seed: [21; 32],
        };

        let report = run_dkg_signing_with_config(message, &config)
            .expect("configured signing ceremony should succeed");
        let solana_signature = SolanaSignature::from(report.signature);

        assert_eq!(report.signer_set, vec![1, 3, 5]);
        assert!(solana_signature.verify(&report.group_public_key, message));
    }

    #[test]
    fn dkg_harness_rejects_insufficient_signers() {
        let config = HarnessConfig {
            min_signers: 3,
            max_signers: 5,
            signing_participants: vec![1, 2],
            rng_seed: [7; 32],
        };

        let error = run_dkg_signing_with_config(b"msg", &config)
            .expect_err("sub-threshold signer set should fail validation");

        assert!(matches!(
            error,
            HarnessError::InvalidConfig("signing participants below threshold")
        ));
    }

    #[test]
    fn dkg_harness_rejects_duplicate_signers() {
        let config = HarnessConfig {
            min_signers: 2,
            max_signers: 3,
            signing_participants: vec![1, 1],
            rng_seed: [8; 32],
        };

        let error = run_dkg_signing_with_config(b"msg", &config)
            .expect_err("duplicate signers should fail validation");

        assert!(matches!(
            error,
            HarnessError::InvalidConfig("signing participants must be unique")
        ));
    }

    #[test]
    fn dkg_harness_rejects_signer_out_of_range() {
        let config = HarnessConfig {
            min_signers: 2,
            max_signers: 3,
            signing_participants: vec![1, 4],
            rng_seed: [9; 32],
        };

        let error = run_dkg_signing_with_config(b"msg", &config)
            .expect_err("out-of-range signer id should fail validation");

        assert!(matches!(
            error,
            HarnessError::InvalidConfig("signing participant out of DKG range")
        ));
    }

    #[test]
    fn share_refresh_harness_preserves_group_key_and_signature_compatibility() {
        let message = b"vaulkyrie refresh harness";
        let report = run_share_refresh_harness(message).expect("refresh harness should succeed");
        let solana_signature = SolanaSignature::from(report.signature);

        assert_eq!(
            report.original_group_public_key,
            report.refreshed_group_public_key
        );
        assert!(solana_signature.verify(&report.refreshed_group_public_key, message));
    }

    #[test]
    fn retry_harness_falls_back_to_later_signer_set() {
        let message = b"vaulkyrie retry harness";
        let base = HarnessConfig {
            min_signers: 3,
            max_signers: 5,
            signing_participants: vec![1, 2, 3],
            rng_seed: [31; 32],
        };
        let retry_sets = vec![vec![1, 2], vec![1, 3, 5]];

        let retry_report = run_dkg_signing_with_retries(message, &base, &retry_sets)
            .expect("retry flow should succeed on second signer set");
        let solana_signature = SolanaSignature::from(retry_report.report.signature);

        assert_eq!(retry_report.attempts, 2);
        assert_eq!(retry_report.successful_signer_set, vec![1, 3, 5]);
        assert!(solana_signature.verify(&retry_report.report.group_public_key, message));
    }

    #[test]
    fn retry_harness_fails_when_all_sets_are_invalid() {
        let base = HarnessConfig {
            min_signers: 3,
            max_signers: 5,
            signing_participants: vec![1, 2, 3],
            rng_seed: [32; 32],
        };
        let retry_sets = vec![vec![1, 2], vec![2, 2, 3], vec![1, 6, 5]];

        let error = run_dkg_signing_with_retries(b"msg", &base, &retry_sets)
            .expect_err("all invalid retry sets should fail");

        assert!(matches!(error, HarnessError::InvalidConfig(_)));
    }
}
