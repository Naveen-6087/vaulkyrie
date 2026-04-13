use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use frost_ed25519 as frost;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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

pub fn run_dkg_signing_harness(message: &[u8]) -> Result<HarnessReport, HarnessError> {
    let config = HarnessConfig::default();
    run_dkg_signing_with_config(message, &config)
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

    let mut round1_secret_packages = BTreeMap::new();
    let mut round1_public_packages = BTreeMap::new();

    for participant in 1..=config.max_signers {
        let identifier = identifier_from_u16(participant)?;
        let (secret_package, public_package) = frost::keys::dkg::part1(
            identifier,
            config.max_signers,
            config.min_signers,
            &mut rng,
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

        let (secret_package, packages) = frost::keys::dkg::part2(
            round1_secret_packages[&identifier].clone(),
            &peer_round1_packages,
        )?;

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

        let (key_package, pubkey_package) = frost::keys::dkg::part3(
            &round2_secret_packages[&identifier],
            &peer_round1_packages,
            &round2_public_packages[&identifier],
        )?;

        key_packages.insert(identifier, key_package);
        public_key_package = Some(pubkey_package);
    }

    let public_key_package = public_key_package.expect("dkg should produce a public key package");

    let mut nonce_commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();

    for identifier in &signing_participants {
        let (nonce, commitments) =
            frost::round1::commit(key_packages[identifier].signing_share(), &mut rng);
        nonces.insert(*identifier, nonce);
        nonce_commitments.insert(*identifier, commitments);
    }

    let signing_package = frost::SigningPackage::new(nonce_commitments, message);
    let mut signature_shares = BTreeMap::new();

    for identifier in &signing_participants {
        let signature_share = frost::round2::sign(
            &signing_package,
            &nonces[identifier],
            &key_packages[identifier],
        )?;
        signature_shares.insert(*identifier, signature_share);
    }

    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &public_key_package)?;

    public_key_package
        .verifying_key()
        .verify(message, &group_signature)?;

    let public_key_bytes: [u8; 32] = public_key_package
        .verifying_key()
        .serialize()?
        .try_into()
        .expect("ed25519 public key serialization should be 32 bytes");

    let signature_bytes: [u8; 64] = group_signature
        .serialize()?
        .try_into()
        .expect("ed25519 signature serialization should be 64 bytes");

    let dalek_key = DalekVerifyingKey::from_bytes(&public_key_bytes)?;
    let dalek_signature = DalekSignature::from_bytes(&signature_bytes);
    dalek_key
        .verify(message, &dalek_signature)
        .map_err(HarnessError::from)?;

    let signer_set = config.signing_participants.clone();

    Ok(HarnessReport {
        group_public_key: public_key_bytes,
        signature: signature_bytes,
        signer_set,
    })
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

fn validate_config(config: &HarnessConfig) -> Result<(), HarnessError> {
    if config.min_signers == 0 || config.max_signers == 0 {
        return Err(HarnessError::InvalidConfig("min/max signers must be non-zero"));
    }
    if config.min_signers > config.max_signers {
        return Err(HarnessError::InvalidConfig("min_signers must be <= max_signers"));
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
    use super::{run_dkg_signing_harness, run_dkg_signing_with_config, HarnessConfig, HarnessError};
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
        let first = run_dkg_signing_harness(b"vaulkyrie frost harness")
            .expect("first run should succeed");
        let second = run_dkg_signing_harness(b"vaulkyrie frost harness")
            .expect("second run should succeed");

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
}
