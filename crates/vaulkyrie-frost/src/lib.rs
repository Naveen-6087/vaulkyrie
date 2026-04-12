use core::fmt;
use std::collections::BTreeMap;

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
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frost(err) => write!(f, "frost error: {err}"),
            Self::InvalidVerifyingKey(err) => write!(f, "invalid ed25519 verifying key: {err}"),
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
}

pub fn run_dkg_signing_harness(message: &[u8]) -> Result<HarnessReport, HarnessError> {
    let mut rng = ChaCha20Rng::from_seed([11; 32]);

    let mut round1_secret_packages = BTreeMap::new();
    let mut round1_public_packages = BTreeMap::new();

    for participant in 1..=DEFAULT_MAX_SIGNERS {
        let identifier = participant.try_into().expect("participant id should fit");
        let (secret_package, public_package) =
            frost::keys::dkg::part1(identifier, DEFAULT_MAX_SIGNERS, DEFAULT_MIN_SIGNERS, &mut rng)?;

        round1_secret_packages.insert(identifier, secret_package);
        round1_public_packages.insert(identifier, public_package);
    }

    let mut round2_secret_packages = BTreeMap::new();
    let mut round2_public_packages: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();

    for participant in 1..=DEFAULT_MAX_SIGNERS {
        let identifier = participant.try_into().expect("participant id should fit");
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

    for participant in 1..=DEFAULT_MAX_SIGNERS {
        let identifier = participant.try_into().expect("participant id should fit");
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

    let signing_participants: Vec<_> = (1..=DEFAULT_MIN_SIGNERS)
        .map(|participant| participant.try_into().expect("participant id should fit"))
        .collect();

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

    Ok(HarnessReport {
        group_public_key: public_key_bytes,
        signature: signature_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::run_dkg_signing_harness;

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
}
