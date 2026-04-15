use clap::Subcommand;
use vaulkyrie_protocol::AuthorityRotationStatement;

use super::{parse_hash, parse_pubkey, print_instruction_json};

#[derive(Subcommand)]
pub enum AuthorityCmd {
    /// Initialize quantum authority state
    Init {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        authority_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Current authority hash (hex, 32 bytes)
        #[arg(long)]
        authority_hash: String,
        /// Current authority root (hex, 32 bytes)
        #[arg(long)]
        authority_root: String,
        #[arg(long)]
        bump: u8,
    },
    /// Initialize authority proof staging
    InitProof {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        proof_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Statement digest (hex, 32 bytes)
        #[arg(long)]
        statement_digest: String,
        /// Proof commitment (hex, 32 bytes)
        #[arg(long)]
        proof_commitment: String,
    },
    /// Write a chunk of proof data
    WriteChunk {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        proof_account: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        wallet_signer: String,
        /// Byte offset into the proof
        #[arg(long)]
        offset: u32,
        /// Chunk data (hex-encoded)
        #[arg(long)]
        data: String,
    },
    /// Rotate authority using staged proof
    RotateStaged {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        vault_registry: String,
        #[arg(long)]
        authority_account: String,
        #[arg(long)]
        proof_account: String,
        #[arg(long)]
        wallet_signer: String,
        /// Action hash (hex, 32 bytes)
        #[arg(long)]
        action_hash: String,
        /// Next authority hash (hex, 32 bytes)
        #[arg(long)]
        next_authority_hash: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        expiry_slot: u64,
    },
}

pub fn run(cmd: AuthorityCmd) -> Result<(), String> {
    match cmd {
        AuthorityCmd::Init {
            program_id,
            authority_account,
            vault_registry,
            wallet_signer,
            authority_hash,
            authority_root,
            bump,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let auth = parse_pubkey(&authority_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let hash = parse_hash(&authority_hash)?;
            let root = parse_hash(&authority_root)?;
            let ix = vaulkyrie_sdk::instruction::init_authority(
                &pid, &auth, &vault, &signer, hash, root, bump,
            );
            print_instruction_json("InitAuthority", &ix);
            Ok(())
        }
        AuthorityCmd::InitProof {
            program_id,
            proof_account,
            vault_registry,
            wallet_signer,
            statement_digest,
            proof_commitment,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let proof = parse_pubkey(&proof_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let stmt = parse_hash(&statement_digest)?;
            let commitment = parse_hash(&proof_commitment)?;
            let ix = vaulkyrie_sdk::instruction::init_authority_proof(
                &pid, &proof, &vault, &signer, stmt, commitment,
            );
            print_instruction_json("InitAuthorityProof", &ix);
            Ok(())
        }
        AuthorityCmd::WriteChunk {
            program_id,
            proof_account,
            vault_registry,
            wallet_signer,
            offset,
            data,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let proof = parse_pubkey(&proof_account)?;
            let vault = parse_pubkey(&vault_registry)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let chunk = hex::decode(&data).map_err(|e| format!("invalid hex data: {e}"))?;
            let ix = vaulkyrie_sdk::instruction::write_authority_proof_chunk(
                &pid, &proof, &vault, &signer, offset, &chunk,
            );
            print_instruction_json("WriteAuthorityProofChunk", &ix);
            Ok(())
        }
        AuthorityCmd::RotateStaged {
            program_id,
            vault_registry,
            authority_account,
            proof_account,
            wallet_signer,
            action_hash,
            next_authority_hash,
            sequence,
            expiry_slot,
        } => {
            let pid = parse_pubkey(&program_id)?;
            let vault = parse_pubkey(&vault_registry)?;
            let auth = parse_pubkey(&authority_account)?;
            let proof = parse_pubkey(&proof_account)?;
            let signer = parse_pubkey(&wallet_signer)?;
            let ah = parse_hash(&action_hash)?;
            let next_hash = parse_hash(&next_authority_hash)?;
            let statement = AuthorityRotationStatement {
                action_hash: ah,
                next_authority_hash: next_hash,
                sequence,
                expiry_slot,
            };
            let ix = vaulkyrie_sdk::instruction::rotate_authority_staged(
                &pid, &vault, &auth, &proof, &signer, &statement,
            );
            print_instruction_json("RotateAuthorityStaged", &ix);
            Ok(())
        }
    }
}
