//! Vaulkyrie FROST WASM — browser-side threshold Ed25519 DKG and signing.
//!
//! Exposes a 3-round DKG ceremony and 2-round signing protocol via
//! wasm-bindgen, producing standard Ed25519 signatures compatible with
//! Solana transaction verification.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use frost_ed25519 as frost;
use frost::{
    keys::{
        dkg::{self, round1 as dkg_round1, round2 as dkg_round2},
        KeyPackage, PublicKeyPackage,
    },
    round1, round2, Identifier, SigningPackage,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ── Serializable wire types ──────────────────────────────────────────

/// DKG round 1 output for a single participant.
#[derive(Serialize, Deserialize)]
pub struct DkgRound1Result {
    pub participant_id: u16,
    /// Postcard-serialized `dkg::round1::SecretPackage` (kept locally).
    pub secret_package: Vec<u8>,
    /// Postcard-serialized `dkg::round1::Package` (broadcast to all).
    pub package: Vec<u8>,
}

/// DKG round 2 output for a single participant.
#[derive(Serialize, Deserialize)]
pub struct DkgRound2Result {
    pub participant_id: u16,
    /// Postcard-serialized `dkg::round2::SecretPackage` (kept locally).
    pub secret_package: Vec<u8>,
    /// Map of recipient_id → postcard-serialized `dkg::round2::Package`.
    pub packages: BTreeMap<u16, Vec<u8>>,
}

/// DKG round 3 output — the final key material.
#[derive(Serialize, Deserialize)]
pub struct DkgRound3Result {
    pub participant_id: u16,
    /// Postcard-serialized `KeyPackage` (secret, stored locally).
    pub key_package: Vec<u8>,
    /// Postcard-serialized `PublicKeyPackage` (shared, same for all).
    pub public_key_package: Vec<u8>,
    /// The 32-byte group verifying key (the wallet public key).
    pub group_public_key: Vec<u8>,
}

/// Signing round 1 output for a single participant.
#[derive(Serialize, Deserialize)]
pub struct SigningRound1Result {
    pub participant_id: u16,
    /// Postcard-serialized `round1::SigningNonces` (kept locally).
    pub nonces: Vec<u8>,
    /// Postcard-serialized `round1::SigningCommitments` (broadcast).
    pub commitments: Vec<u8>,
}

/// Signing round 2 output for a single participant.
#[derive(Serialize, Deserialize)]
pub struct SigningRound2Result {
    pub participant_id: u16,
    /// Postcard-serialized `round2::SignatureShare` (sent to coordinator).
    pub signature_share: Vec<u8>,
}

/// The final aggregated signature.
#[derive(Serialize, Deserialize)]
pub struct AggregateResult {
    /// 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// 32-byte group verifying key.
    pub group_public_key: Vec<u8>,
    /// Whether the signature passes ed25519-dalek verification.
    pub verified: bool,
}

// ── Helpers ──────────────────────────────────────────────────────────

fn id(n: u16) -> Identifier {
    Identifier::try_from(n).expect("non-zero participant id")
}

fn postcard_ser<T: serde::Serialize>(val: &T) -> Vec<u8> {
    serde_json::to_vec(val).expect("serialization should not fail")
}

fn postcard_de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    serde_json::from_slice(bytes).expect("deserialization should not fail")
}

fn entropy_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    ChaCha20Rng::from_seed(seed)
}

// ── DKG Round 1 ──────────────────────────────────────────────────────

/// Run DKG round 1 for a single participant.
///
/// `participant_id`: 1-based participant index.
/// `max_signers`: total number of participants.
/// `min_signers`: signing threshold.
///
/// Returns JSON-serialized `DkgRound1Result`.
#[wasm_bindgen]
pub fn dkg_round1(participant_id: u16, max_signers: u16, min_signers: u16) -> String {
    let mut rng = entropy_rng();
    let (secret, package) =
        dkg::part1(id(participant_id), max_signers, min_signers, &mut rng)
            .expect("DKG round 1 failed");

    let result = DkgRound1Result {
        participant_id,
        secret_package: postcard_ser(&secret),
        package: postcard_ser(&package),
    };
    serde_json::to_string(&result).unwrap()
}

/// Run DKG round 1 with a deterministic seed (for testing).
#[wasm_bindgen]
pub fn dkg_round1_deterministic(
    participant_id: u16,
    max_signers: u16,
    min_signers: u16,
    seed: &[u8],
) -> String {
    let mut seed_arr = [0u8; 32];
    let copy_len = seed.len().min(32);
    seed_arr[..copy_len].copy_from_slice(&seed[..copy_len]);
    let mut rng = ChaCha20Rng::from_seed(seed_arr);

    let (secret, package) =
        dkg::part1(id(participant_id), max_signers, min_signers, &mut rng)
            .expect("DKG round 1 failed");

    let result = DkgRound1Result {
        participant_id,
        secret_package: postcard_ser(&secret),
        package: postcard_ser(&package),
    };
    serde_json::to_string(&result).unwrap()
}

// ── DKG Round 2 ──────────────────────────────────────────────────────

/// Run DKG round 2 for a single participant.
///
/// `secret_package_json`: JSON-serialized secret from round 1.
/// `round1_packages_json`: JSON map of participant_id → round 1 package bytes.
///
/// Returns JSON-serialized `DkgRound2Result`.
#[wasm_bindgen]
pub fn dkg_round2(
    participant_id: u16,
    secret_package_json: &str,
    round1_packages_json: &str,
) -> String {
    let secret: dkg_round1::SecretPackage =
        postcard_de(serde_json::from_str::<Vec<u8>>(secret_package_json).unwrap().as_slice());

    let round1_map: BTreeMap<u16, Vec<u8>> =
        serde_json::from_str(round1_packages_json).unwrap();

    let mut round1_packages = BTreeMap::new();
    for (pid, bytes) in &round1_map {
        let pkg: dkg_round1::Package = postcard_de(bytes);
        round1_packages.insert(id(*pid), pkg);
    }

    let (secret2, packages) =
        dkg::part2(secret, &round1_packages).expect("DKG round 2 failed");

    let mut pkg_map = BTreeMap::new();
    for (pid, pkg) in &packages {
        // Identifier for small values: scalar[0] holds the value in LE
        let pid_bytes = pid.serialize();
        let pid_u16 = pid_bytes[0] as u16;
        pkg_map.insert(pid_u16, postcard_ser(pkg));
    }

    let result = DkgRound2Result {
        participant_id,
        secret_package: postcard_ser(&secret2),
        packages: pkg_map,
    };
    serde_json::to_string(&result).unwrap()
}

// ── DKG Round 3 (finalize) ──────────────────────────────────────────

/// Finalize DKG for a single participant.
///
/// `secret_package_json`: JSON-serialized round 2 secret.
/// `round1_packages_json`: JSON map of participant_id → round 1 package bytes.
/// `round2_packages_json`: JSON map of participant_id → round 2 package bytes
///                         (only packages addressed to this participant).
///
/// Returns JSON-serialized `DkgRound3Result`.
#[wasm_bindgen]
pub fn dkg_round3(
    participant_id: u16,
    secret_package_json: &str,
    round1_packages_json: &str,
    round2_packages_json: &str,
) -> String {
    let secret2: dkg_round2::SecretPackage =
        postcard_de(serde_json::from_str::<Vec<u8>>(secret_package_json).unwrap().as_slice());

    let round1_map: BTreeMap<u16, Vec<u8>> =
        serde_json::from_str(round1_packages_json).unwrap();
    let mut round1_packages = BTreeMap::new();
    for (pid, bytes) in &round1_map {
        let pkg: dkg_round1::Package = postcard_de(bytes);
        round1_packages.insert(id(*pid), pkg);
    }

    let round2_map: BTreeMap<u16, Vec<u8>> =
        serde_json::from_str(round2_packages_json).unwrap();
    let mut round2_packages = BTreeMap::new();
    for (pid, bytes) in &round2_map {
        let pkg: dkg_round2::Package = postcard_de(bytes);
        round2_packages.insert(id(*pid), pkg);
    }

    let (key_package, pubkey_package) =
        dkg::part3(&secret2, &round1_packages, &round2_packages)
            .expect("DKG round 3 failed");

    let group_key_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("verifying key serialization")
        .to_vec();

    let result = DkgRound3Result {
        participant_id,
        key_package: postcard_ser(&key_package),
        public_key_package: postcard_ser(&pubkey_package),
        group_public_key: group_key_bytes,
    };
    serde_json::to_string(&result).unwrap()
}

// ── Signing Round 1 ─────────────────────────────────────────────────

/// Generate signing nonces and commitments for a participant.
///
/// `key_package_json`: JSON-serialized `KeyPackage` from DKG round 3.
///
/// Returns JSON-serialized `SigningRound1Result`.
#[wasm_bindgen]
pub fn signing_round1(participant_id: u16, key_package_json: &str) -> String {
    let key_package: KeyPackage =
        postcard_de(serde_json::from_str::<Vec<u8>>(key_package_json).unwrap().as_slice());

    let mut rng = entropy_rng();
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    let result = SigningRound1Result {
        participant_id,
        nonces: postcard_ser(&nonces),
        commitments: postcard_ser(&commitments),
    };
    serde_json::to_string(&result).unwrap()
}

// ── Signing Round 2 ─────────────────────────────────────────────────

/// Produce a signature share for a participant.
///
/// `nonces_json`: JSON-serialized nonces from signing round 1.
/// `key_package_json`: JSON-serialized `KeyPackage` from DKG.
/// `message`: the raw message bytes to sign.
/// `commitments_json`: JSON map of participant_id → commitments bytes.
///
/// Returns JSON-serialized `SigningRound2Result`.
#[wasm_bindgen]
pub fn signing_round2(
    participant_id: u16,
    nonces_json: &str,
    key_package_json: &str,
    message: &[u8],
    commitments_json: &str,
) -> String {
    let nonces: round1::SigningNonces =
        postcard_de(serde_json::from_str::<Vec<u8>>(nonces_json).unwrap().as_slice());
    let key_package: KeyPackage =
        postcard_de(serde_json::from_str::<Vec<u8>>(key_package_json).unwrap().as_slice());

    let commitments_map: BTreeMap<u16, Vec<u8>> =
        serde_json::from_str(commitments_json).unwrap();
    let mut signing_commitments = BTreeMap::new();
    for (pid, bytes) in &commitments_map {
        let c: round1::SigningCommitments = postcard_de(bytes);
        signing_commitments.insert(id(*pid), c);
    }

    let signing_package = SigningPackage::new(signing_commitments, message);

    let share = frost::round2::sign(&signing_package, &nonces, &key_package)
        .expect("signing round 2 failed");

    let result = SigningRound2Result {
        participant_id,
        signature_share: postcard_ser(&share),
    };
    serde_json::to_string(&result).unwrap()
}

// ── Aggregate ────────────────────────────────────────────────────────

/// Aggregate signature shares into a final Ed25519 signature.
///
/// `message`: the raw message bytes that were signed.
/// `commitments_json`: JSON map of participant_id → commitments bytes.
/// `signature_shares_json`: JSON map of participant_id → share bytes.
/// `public_key_package_json`: JSON-serialized `PublicKeyPackage`.
///
/// Returns JSON-serialized `AggregateResult`.
#[wasm_bindgen]
pub fn aggregate_signature(
    message: &[u8],
    commitments_json: &str,
    signature_shares_json: &str,
    public_key_package_json: &str,
) -> String {
    let commitments_map: BTreeMap<u16, Vec<u8>> =
        serde_json::from_str(commitments_json).unwrap();
    let mut signing_commitments = BTreeMap::new();
    for (pid, bytes) in &commitments_map {
        let c: round1::SigningCommitments = postcard_de(bytes);
        signing_commitments.insert(id(*pid), c);
    }

    let shares_map: BTreeMap<u16, Vec<u8>> =
        serde_json::from_str(signature_shares_json).unwrap();
    let mut signature_shares = BTreeMap::new();
    for (pid, bytes) in &shares_map {
        let s: round2::SignatureShare = postcard_de(bytes);
        signature_shares.insert(id(*pid), s);
    }

    let pubkey_package: PublicKeyPackage =
        postcard_de(serde_json::from_str::<Vec<u8>>(public_key_package_json).unwrap().as_slice());

    let signing_package = SigningPackage::new(signing_commitments, message);

    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .expect("signature aggregation failed");

    let sig_bytes = signature.serialize().expect("signature serialization");
    let group_key_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("verifying key serialization")
        .to_vec();

    // Verify with ed25519-dalek to confirm Solana compatibility
    let verifying_key =
        DalekVerifyingKey::from_bytes(group_key_bytes.as_slice().try_into().unwrap()).unwrap();
    let dalek_sig = DalekSignature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    let verified = verifying_key.verify(message, &dalek_sig).is_ok();

    let result = AggregateResult {
        signature: sig_bytes.to_vec(),
        group_public_key: group_key_bytes,
        verified,
    };
    serde_json::to_string(&result).unwrap()
}

// ── Utility ─────────────────────────────────────────────────────────

/// Verify an Ed25519 signature against a public key and message.
#[wasm_bindgen]
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let Ok(vk) = DalekVerifyingKey::from_bytes(public_key.try_into().unwrap()) else {
        return false;
    };
    let sig = DalekSignature::from_bytes(signature.try_into().unwrap());
    vk.verify(message, &sig).is_ok()
}

/// Run a complete 2-of-3 DKG ceremony and return the group public key.
/// Useful for testing the full flow in one call.
#[wasm_bindgen]
pub fn run_full_dkg(min_signers: u16, max_signers: u16) -> String {
    let mut rng = entropy_rng();

    // Round 1: all participants generate commitments
    let mut r1_secrets = BTreeMap::new();
    let mut r1_packages = BTreeMap::new();

    for i in 1..=max_signers {
        let (secret, package) =
            dkg::part1(id(i), max_signers, min_signers, &mut rng)
                .expect("DKG round 1 failed");
        r1_secrets.insert(id(i), secret);
        r1_packages.insert(id(i), package);
    }

    // Round 2: each participant processes others' round 1 packages
    let mut r2_secrets = BTreeMap::new();
    let mut r2_packages: BTreeMap<Identifier, BTreeMap<Identifier, dkg_round2::Package>> =
        BTreeMap::new();

    for i in 1..=max_signers {
        let pid = id(i);
        let my_secret = r1_secrets.remove(&pid).unwrap();
        let others: BTreeMap<_, _> = r1_packages
            .iter()
            .filter(|(k, _)| **k != pid)
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        let (secret2, packages) =
            dkg::part2(my_secret, &others).expect("DKG round 2 failed");
        r2_secrets.insert(pid, secret2);
        for (recipient, pkg) in packages {
            r2_packages
                .entry(recipient)
                .or_default()
                .insert(pid, pkg);
        }
    }

    // Round 3: finalize
    let mut key_packages = BTreeMap::new();
    let mut pubkey_package = None;

    for i in 1..=max_signers {
        let pid = id(i);
        let my_secret2 = r2_secrets.remove(&pid).unwrap();
        let others_r1: BTreeMap<_, _> = r1_packages
            .iter()
            .filter(|(k, _)| **k != pid)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let my_r2_packages = r2_packages.remove(&pid).unwrap();

        let (kp, pkp) =
            dkg::part3(&my_secret2, &others_r1, &my_r2_packages)
                .expect("DKG round 3 failed");
        key_packages.insert(pid, kp);
        pubkey_package = Some(pkp);
    }

    let pkp = pubkey_package.unwrap();
    let group_key = pkp.verifying_key().serialize()
        .expect("verifying key serialization").to_vec();

    // Serialize all key packages for each participant
    let mut participants = BTreeMap::new();
    for i in 1..=max_signers {
        let pid = id(i);
        if let Some(kp) = key_packages.get(&pid) {
            participants.insert(i, postcard_ser(kp));
        }
    }

    let result = serde_json::json!({
        "group_public_key": group_key,
        "public_key_package": postcard_ser(&pkp),
        "key_packages": participants,
        "threshold": min_signers,
        "num_participants": max_signers,
    });
    serde_json::to_string(&result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_dkg_produces_valid_group_key() {
        let result_json = run_full_dkg(2, 3);
        let result: serde_json::Value = serde_json::from_str(&result_json).unwrap();
        let group_key: Vec<u8> = serde_json::from_value(result["group_public_key"].clone()).unwrap();
        assert_eq!(group_key.len(), 32, "group public key should be 32 bytes");
    }

    #[test]
    fn round_by_round_dkg_and_signing_flow() {
        // Round 1 — deterministic for reproducibility
        let r1_1 = dkg_round1_deterministic(1, 3, 2, &[1; 32]);
        let r1_2 = dkg_round1_deterministic(2, 3, 2, &[2; 32]);
        let r1_3 = dkg_round1_deterministic(3, 3, 2, &[3; 32]);

        let r1_1_parsed: DkgRound1Result = serde_json::from_str(&r1_1).unwrap();
        let r1_2_parsed: DkgRound1Result = serde_json::from_str(&r1_2).unwrap();
        let r1_3_parsed: DkgRound1Result = serde_json::from_str(&r1_3).unwrap();

        // Build round1 packages map for each participant (excluding self)
        let all_r1: BTreeMap<u16, Vec<u8>> = [
            (1u16, r1_1_parsed.package.clone()),
            (2, r1_2_parsed.package.clone()),
            (3, r1_3_parsed.package.clone()),
        ]
        .into_iter()
        .collect();

        let r1_for = |exclude: u16| -> String {
            let m: BTreeMap<u16, Vec<u8>> = all_r1
                .iter()
                .filter(|(k, _)| **k != exclude)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            serde_json::to_string(&m).unwrap()
        };

        // Round 2
        let s1 = serde_json::to_string(&r1_1_parsed.secret_package).unwrap();
        let s2 = serde_json::to_string(&r1_2_parsed.secret_package).unwrap();
        let s3 = serde_json::to_string(&r1_3_parsed.secret_package).unwrap();

        let r2_1 = dkg_round2(1, &s1, &r1_for(1));
        let r2_2 = dkg_round2(2, &s2, &r1_for(2));
        let r2_3 = dkg_round2(3, &s3, &r1_for(3));

        let r2_1_parsed: DkgRound2Result = serde_json::from_str(&r2_1).unwrap();
        let r2_2_parsed: DkgRound2Result = serde_json::from_str(&r2_2).unwrap();
        let r2_3_parsed: DkgRound2Result = serde_json::from_str(&r2_3).unwrap();

        // Collect round2 packages addressed to each participant
        let r2_for = |target: u16| -> String {
            let mut m = BTreeMap::new();
            for (src, parsed) in [(1u16, &r2_1_parsed), (2, &r2_2_parsed), (3, &r2_3_parsed)] {
                if let Some(pkg) = parsed.packages.get(&target) {
                    m.insert(src, pkg.clone());
                }
            }
            serde_json::to_string(&m).unwrap()
        };

        let ss1 = serde_json::to_string(&r2_1_parsed.secret_package).unwrap();
        let ss2 = serde_json::to_string(&r2_2_parsed.secret_package).unwrap();
        let ss3 = serde_json::to_string(&r2_3_parsed.secret_package).unwrap();

        // Round 3 — finalize
        let r3_1 = dkg_round3(1, &ss1, &r1_for(1), &r2_for(1));
        let r3_2 = dkg_round3(2, &ss2, &r1_for(2), &r2_for(2));
        let r3_3 = dkg_round3(3, &ss3, &r1_for(3), &r2_for(3));

        let r3_1_parsed: DkgRound3Result = serde_json::from_str(&r3_1).unwrap();
        let r3_2_parsed: DkgRound3Result = serde_json::from_str(&r3_2).unwrap();
        let r3_3_parsed: DkgRound3Result = serde_json::from_str(&r3_3).unwrap();

        // All participants must agree on the group public key
        assert_eq!(r3_1_parsed.group_public_key, r3_2_parsed.group_public_key);
        assert_eq!(r3_2_parsed.group_public_key, r3_3_parsed.group_public_key);
        assert_eq!(r3_1_parsed.group_public_key.len(), 32);

        // Signing with participants 1 and 2 (threshold = 2)
        let message = b"vaulkyrie wasm test transaction";

        let kp1 = serde_json::to_string(&r3_1_parsed.key_package).unwrap();
        let kp2 = serde_json::to_string(&r3_2_parsed.key_package).unwrap();

        let sr1_1 = signing_round1(1, &kp1);
        let sr1_2 = signing_round1(2, &kp2);

        let sr1_1_parsed: SigningRound1Result = serde_json::from_str(&sr1_1).unwrap();
        let sr1_2_parsed: SigningRound1Result = serde_json::from_str(&sr1_2).unwrap();

        let commitments: BTreeMap<u16, Vec<u8>> = [
            (1u16, sr1_1_parsed.commitments.clone()),
            (2, sr1_2_parsed.commitments.clone()),
        ]
        .into_iter()
        .collect();
        let commitments_json = serde_json::to_string(&commitments).unwrap();

        let n1 = serde_json::to_string(&sr1_1_parsed.nonces).unwrap();
        let n2 = serde_json::to_string(&sr1_2_parsed.nonces).unwrap();

        let sr2_1 = signing_round2(1, &n1, &kp1, message, &commitments_json);
        let sr2_2 = signing_round2(2, &n2, &kp2, message, &commitments_json);

        let sr2_1_parsed: SigningRound2Result = serde_json::from_str(&sr2_1).unwrap();
        let sr2_2_parsed: SigningRound2Result = serde_json::from_str(&sr2_2).unwrap();

        let shares: BTreeMap<u16, Vec<u8>> = [
            (1u16, sr2_1_parsed.signature_share),
            (2, sr2_2_parsed.signature_share),
        ]
        .into_iter()
        .collect();
        let shares_json = serde_json::to_string(&shares).unwrap();

        let pkp_json = serde_json::to_string(&r3_1_parsed.public_key_package).unwrap();

        let agg_result_json =
            aggregate_signature(message, &commitments_json, &shares_json, &pkp_json);
        let agg: AggregateResult = serde_json::from_str(&agg_result_json).unwrap();

        assert_eq!(agg.signature.len(), 64, "signature should be 64 bytes");
        assert!(agg.verified, "aggregated signature should verify");

        // Cross-check with standalone verify
        assert!(verify_signature(
            &agg.group_public_key,
            message,
            &agg.signature
        ));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let result_json = run_full_dkg(2, 3);
        let result: serde_json::Value = serde_json::from_str(&result_json).unwrap();
        let group_key: Vec<u8> = serde_json::from_value(result["group_public_key"].clone()).unwrap();

        // A random 64-byte "signature" should not verify
        let fake_sig = [0u8; 64];
        assert!(!verify_signature(&group_key, b"test", &fake_sig));
    }

    #[test]
    fn verify_rejects_wrong_length_inputs() {
        assert!(!verify_signature(&[0; 31], b"msg", &[0; 64]));
        assert!(!verify_signature(&[0; 32], b"msg", &[0; 63]));
    }
}
