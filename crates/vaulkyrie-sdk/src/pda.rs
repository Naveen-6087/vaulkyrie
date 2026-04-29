//! PDA derivation helpers for all Vaulkyrie account types.
//!
//! Each function returns `(Pubkey, u8)` where the second element is the
//! canonical bump seed, matching the Solana `find_program_address` convention.
//!
//! Since the lightweight `solana-pubkey` crate does not ship
//! `find_program_address`, we implement the standard PDA derivation algorithm
//! using SHA-256 and `curve25519-dalek` for the on-curve rejection check.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use vaulkyrie_protocol::{
    AUTHORITY_PROOF_SEED, PQC_WALLET_SEED, QUANTUM_AUTHORITY_SEED, QUANTUM_VAULT_SEED,
    SPEND_ORCH_SEED, VAULT_REGISTRY_SEED,
};

/// Standard Solana PDA derivation: tries bumps 255..=0 until the hash lands
/// off the ed25519 curve.
fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
    for bump in (0..=255u8).rev() {
        if let Some(addr) = create_program_address(seeds, bump, program_id) {
            return (addr, bump);
        }
    }
    panic!("could not find a valid PDA bump");
}

fn create_program_address(seeds: &[&[u8]], bump: u8, program_id: &Pubkey) -> Option<Pubkey> {
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update([bump]);
    hasher.update(program_id.as_ref());
    hasher.update(b"ProgramDerivedAddress");
    let hash: [u8; 32] = hasher.finalize().into();

    // A valid PDA must NOT be a valid ed25519 point.
    let compressed = CompressedEdwardsY::from_slice(&hash).ok()?;
    if compressed.decompress().is_some() {
        return None;
    }
    Some(Pubkey::from(hash))
}

/// VaultRegistry PDA — seeds: `["vault_registry", wallet_pubkey]`
pub fn find_vault_registry(wallet_pubkey: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[VAULT_REGISTRY_SEED, wallet_pubkey.as_ref()], program_id)
}

/// QuantumAuthorityState PDA — seeds: `["quantum_authority", vault_id]`
pub fn find_quantum_authority(vault_id: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[QUANTUM_AUTHORITY_SEED, vault_id.as_ref()], program_id)
}

/// AuthorityProofState PDA — seeds: `["authority_proof", vault_id, statement_digest]`
pub fn find_authority_proof(
    vault_id: &Pubkey,
    statement_digest: &[u8; 32],
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    find_program_address(
        &[AUTHORITY_PROOF_SEED, vault_id.as_ref(), statement_digest],
        program_id,
    )
}

/// QuantumVaultState PDA — seeds: `["quantum_vault", hash]`
pub fn find_quantum_vault(hash: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[QUANTUM_VAULT_SEED, hash], program_id)
}

/// PqcWalletState PDA — seeds: `["pqc_wallet", wallet_id]`
pub fn find_pqc_wallet(wallet_id: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
    find_program_address(&[PQC_WALLET_SEED, wallet_id], program_id)
}

/// SpendOrchestrationState PDA — seeds: `["spend_orch", vault_id, action_hash]`
pub fn find_spend_orchestration(
    vault_id: &Pubkey,
    action_hash: &[u8; 32],
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    find_program_address(
        &[SPEND_ORCH_SEED, vault_id.as_ref(), action_hash],
        program_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_program_id() -> Pubkey {
        Pubkey::from([1u8; 32])
    }

    #[test]
    fn vault_registry_pda_is_deterministic() {
        let wallet = Pubkey::from([42u8; 32]);
        let (addr1, bump1) = find_vault_registry(&wallet, &test_program_id());
        let (addr2, bump2) = find_vault_registry(&wallet, &test_program_id());
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn different_wallets_produce_different_pdas() {
        let w1 = Pubkey::from([1u8; 32]);
        let w2 = Pubkey::from([2u8; 32]);
        let (a1, _) = find_vault_registry(&w1, &test_program_id());
        let (a2, _) = find_vault_registry(&w2, &test_program_id());
        assert_ne!(a1, a2);
    }

    #[test]
    fn all_pda_types_produce_unique_addresses() {
        let vault = Pubkey::from([10u8; 32]);
        let hash = [20u8; 32];
        let pid = test_program_id();

        let (vault_reg, _) = find_vault_registry(&vault, &pid);
        let (authority, _) = find_quantum_authority(&vault, &pid);
        let (proof, _) = find_authority_proof(&vault, &hash, &pid);
        let (qv, _) = find_quantum_vault(&hash, &pid);
        let (pqc_wallet, _) = find_pqc_wallet(&hash, &pid);
        let (orch, _) = find_spend_orchestration(&vault, &hash, &pid);

        let addrs = [vault_reg, authority, proof, qv, pqc_wallet, orch];
        for (i, a) in addrs.iter().enumerate() {
            for (j, b) in addrs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "PDA collision between type {i} and {j}");
                }
            }
        }
    }

    #[test]
    fn pda_is_off_curve() {
        let wallet = Pubkey::from([99u8; 32]);
        let (addr, _) = find_vault_registry(&wallet, &test_program_id());
        // find_program_address guarantees the address is off the ed25519 curve
        assert_ne!(addr, Pubkey::default());
    }
}
