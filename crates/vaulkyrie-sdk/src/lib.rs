//! Vaulkyrie Client SDK
//!
//! Instruction builders, PDA derivation, account deserialization, error
//! decoding, and optional FROST orchestration for the Vaulkyrie threshold
//! wallet.
//!
//! # Feature flags
//!
//! - **`frost`** *(default)* — enables the `frost` module with DKG and
//!   threshold signing orchestration via `vaulkyrie-frost` and
//!   `frost-ed25519`.

pub mod accounts;
pub mod error;
pub mod instruction;
pub mod pda;
pub mod policy;
pub mod privacy;
pub mod types;

#[cfg(feature = "frost")]
pub mod frost;

pub use types::*;

pub use solana_instruction::Instruction;
pub use solana_pubkey::Pubkey;

pub use vaulkyrie_protocol;
