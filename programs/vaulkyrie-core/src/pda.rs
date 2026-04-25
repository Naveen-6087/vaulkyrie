#[cfg(feature = "bpf-entrypoint")]
use pinocchio::pubkey::create_program_address;
use pinocchio::{program_error::ProgramError, pubkey::Pubkey};
use vaulkyrie_protocol::{
    ACTION_SESSION_SEED, AUTHORITY_PROOF_SEED, POLICY_RECEIPT_SEED, QUANTUM_AUTHORITY_SEED,
    QUANTUM_VAULT_SEED, SPEND_ORCH_SEED, VAULT_REGISTRY_SEED,
};

fn create_pda_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<Pubkey, ProgramError> {
    #[cfg(feature = "bpf-entrypoint")]
    {
        create_program_address(seeds, program_id)
    }

    #[cfg(not(feature = "bpf-entrypoint"))]
    {
        host_pda::create_program_address(seeds, program_id).ok_or(ProgramError::InvalidSeeds)
    }
}

// ── VaultRegistry PDA ──────────────────────────────────────────────────────
// Seeds: ["vault_registry", wallet_pubkey, bump]

pub fn derive_vault_registry(
    wallet_pubkey: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(
        &[VAULT_REGISTRY_SEED, wallet_pubkey, &bump_slice],
        program_id,
    )
}

pub fn verify_vault_registry(
    expected_key: &Pubkey,
    wallet_pubkey: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_vault_registry(wallet_pubkey, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── PolicyReceiptState PDA ─────────────────────────────────────────────────
// Seeds: ["policy_receipt", vault_id, action_hash, bump]

pub fn derive_policy_receipt(
    vault_id: &[u8; 32],
    action_hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(
        &[POLICY_RECEIPT_SEED, vault_id, action_hash, &bump_slice],
        program_id,
    )
}

pub fn verify_policy_receipt(
    expected_key: &Pubkey,
    vault_id: &[u8; 32],
    action_hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_policy_receipt(vault_id, action_hash, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── ActionSessionState PDA ─────────────────────────────────────────────────
// Seeds: ["action_session", vault_id, action_hash, bump]

pub fn derive_action_session(
    vault_id: &[u8; 32],
    action_hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(
        &[ACTION_SESSION_SEED, vault_id, action_hash, &bump_slice],
        program_id,
    )
}

pub fn verify_action_session(
    expected_key: &Pubkey,
    vault_id: &[u8; 32],
    action_hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_action_session(vault_id, action_hash, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── QuantumAuthorityState PDA ──────────────────────────────────────────────
// Seeds: ["quantum_authority", vault_id, bump]

pub fn derive_quantum_authority(
    vault_id: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(&[QUANTUM_AUTHORITY_SEED, vault_id, &bump_slice], program_id)
}

pub fn verify_quantum_authority(
    expected_key: &Pubkey,
    vault_id: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_quantum_authority(vault_id, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── AuthorityProofState PDA ────────────────────────────────────────────────
// Seeds: ["authority_proof", authority_key, bump]

pub fn derive_authority_proof(
    authority_key: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(
        &[AUTHORITY_PROOF_SEED, authority_key, &bump_slice],
        program_id,
    )
}

pub fn verify_authority_proof(
    expected_key: &Pubkey,
    authority_key: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_authority_proof(authority_key, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── QuantumVault PDA ───────────────────────────────────────────────────────
// Seeds: ["quantum_vault", hash, bump]

pub fn derive_quantum_vault(
    hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(&[QUANTUM_VAULT_SEED, hash, &bump_slice], program_id)
}

pub fn verify_quantum_vault(
    expected_key: &Pubkey,
    hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_quantum_vault(hash, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── SpendOrchestrationState PDA ────────────────────────────────────────────
// Seeds: ["spend_orch", vault_id, action_hash, bump]

pub fn derive_spend_orchestration(
    vault_id: &[u8; 32],
    action_hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    let bump_slice = [bump];
    create_pda_address(
        &[SPEND_ORCH_SEED, vault_id, action_hash, &bump_slice],
        program_id,
    )
}

pub fn verify_spend_orchestration(
    expected_key: &Pubkey,
    vault_id: &[u8; 32],
    action_hash: &[u8; 32],
    bump: u8,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let derived = derive_spend_orchestration(vault_id, action_hash, bump, program_id)?;
    if &derived != expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

// ── Host-side PDA helpers (test only) ──────────────────────────────────────
// Pinocchio's `create_program_address` and `find_program_address` are
// BPF-only syscalls.  For host-side unit tests we re-implement the
// derivation in pure Rust using `solana-nostd-sha256` and
// `curve25519-dalek`.

#[cfg(not(feature = "bpf-entrypoint"))]
mod host_pda {
    use solana_nostd_sha256::hashv;

    /// Check whether a 32-byte compressed Edwards-Y coordinate is on the
    /// ed25519 curve (i.e. has a corresponding private key).  PDAs must
    /// NOT be on the curve.
    fn is_on_curve(bytes: &[u8; 32]) -> bool {
        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*bytes);
        compressed.decompress().is_some()
    }

    /// Pure-Rust equivalent of `solana_program::pubkey::Pubkey::create_program_address`.
    pub fn create_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<[u8; 32]> {
        if seeds.len() > 16 {
            return None;
        }
        for s in seeds {
            if s.len() > 32 {
                return None;
            }
        }
        let mut inputs: Vec<&[u8]> = seeds.to_vec();
        inputs.push(program_id);
        inputs.push(b"ProgramDerivedAddress");
        let hash = hashv(&inputs);
        if is_on_curve(&hash) {
            return None;
        }
        Some(hash)
    }

    /// Pure-Rust equivalent of `solana_program::pubkey::Pubkey::find_program_address`.
    #[cfg(test)]
    pub fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<([u8; 32], u8)> {
        let mut bump = 255u8;
        loop {
            let bump_slice = [bump];
            let mut extended: Vec<&[u8]> = seeds.to_vec();
            extended.push(&bump_slice);
            if let Some(addr) = create_program_address(&extended, program_id) {
                return Some((addr, bump));
            }
            if bump == 0 {
                return None;
            }
            bump -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_pda;
    use vaulkyrie_protocol::{
        ACTION_SESSION_SEED, AUTHORITY_PROOF_SEED, POLICY_RECEIPT_SEED, QUANTUM_AUTHORITY_SEED,
        QUANTUM_VAULT_SEED, SPEND_ORCH_SEED, VAULT_REGISTRY_SEED,
    };

    const PROGRAM_ID: [u8; 32] = [
        0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7, 0xE8,
        0xF9, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE,
        0xEF, 0xF0,
    ];

    #[test]
    fn vault_registry_pda_derivation() {
        let wallet = [42u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[VAULT_REGISTRY_SEED, &wallet], &PROGRAM_ID)
                .expect("should find PDA");

        let derived =
            host_pda::create_program_address(&[VAULT_REGISTRY_SEED, &wallet, &[bump]], &PROGRAM_ID)
                .expect("should derive PDA");
        assert_eq!(derived, expected);
    }

    #[test]
    fn vault_registry_wrong_bump_yields_different_address() {
        let wallet = [42u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[VAULT_REGISTRY_SEED, &wallet], &PROGRAM_ID).unwrap();

        let wrong_bump = bump.wrapping_sub(1);
        // Different bump may produce a different valid PDA or None.
        if let Some(other) = host_pda::create_program_address(
            &[VAULT_REGISTRY_SEED, &wallet, &[wrong_bump]],
            &PROGRAM_ID,
        ) {
            assert_ne!(
                other, expected,
                "different bump should give different address"
            );
        }
    }

    #[test]
    fn policy_receipt_pda_derivation() {
        let vault = [10u8; 32];
        let action = [20u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[POLICY_RECEIPT_SEED, &vault, &action], &PROGRAM_ID)
                .unwrap();

        let derived = host_pda::create_program_address(
            &[POLICY_RECEIPT_SEED, &vault, &action, &[bump]],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn action_session_pda_derivation() {
        let vault = [11u8; 32];
        let action = [22u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[ACTION_SESSION_SEED, &vault, &action], &PROGRAM_ID)
                .unwrap();

        let derived = host_pda::create_program_address(
            &[ACTION_SESSION_SEED, &vault, &action, &[bump]],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn quantum_authority_pda_derivation() {
        let vault = [33u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[QUANTUM_AUTHORITY_SEED, &vault], &PROGRAM_ID).unwrap();

        let derived = host_pda::create_program_address(
            &[QUANTUM_AUTHORITY_SEED, &vault, &[bump]],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn authority_proof_pda_derivation() {
        let auth_key = [55u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[AUTHORITY_PROOF_SEED, &auth_key], &PROGRAM_ID)
                .unwrap();

        let derived = host_pda::create_program_address(
            &[AUTHORITY_PROOF_SEED, &auth_key, &[bump]],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn quantum_vault_pda_derivation() {
        let hash = [77u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[QUANTUM_VAULT_SEED, &hash], &PROGRAM_ID).unwrap();

        let derived =
            host_pda::create_program_address(&[QUANTUM_VAULT_SEED, &hash, &[bump]], &PROGRAM_ID)
                .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn spend_orchestration_pda_derivation() {
        let vault = [88u8; 32];
        let action = [99u8; 32];
        let (expected, bump) =
            host_pda::find_program_address(&[SPEND_ORCH_SEED, &vault, &action], &PROGRAM_ID)
                .unwrap();

        let derived = host_pda::create_program_address(
            &[SPEND_ORCH_SEED, &vault, &action, &[bump]],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn cross_type_seeds_do_not_collide() {
        let id = [42u8; 32];
        let (vault_key, _) =
            host_pda::find_program_address(&[VAULT_REGISTRY_SEED, &id], &PROGRAM_ID).unwrap();
        let (authority_key, _) =
            host_pda::find_program_address(&[QUANTUM_AUTHORITY_SEED, &id], &PROGRAM_ID).unwrap();
        assert_ne!(vault_key, authority_key);
    }

    #[test]
    fn all_seed_prefixes_are_unique() {
        let seeds: &[&[u8]] = &[
            VAULT_REGISTRY_SEED,
            POLICY_RECEIPT_SEED,
            ACTION_SESSION_SEED,
            QUANTUM_AUTHORITY_SEED,
            AUTHORITY_PROOF_SEED,
            QUANTUM_VAULT_SEED,
            SPEND_ORCH_SEED,
        ];
        for (i, a) in seeds.iter().enumerate() {
            for b in seeds.iter().skip(i + 1) {
                assert_ne!(a, b, "PDA seed prefixes must be unique");
            }
        }
    }
}
