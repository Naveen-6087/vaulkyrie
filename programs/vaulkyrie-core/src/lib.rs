#![cfg_attr(any(feature = "bpf-entrypoint", target_os = "solana"), no_std)]

use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
#[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
use pinocchio::{default_allocator, default_panic_handler, program_entrypoint};

pub mod error;
pub mod instruction;
pub mod pda;
pub mod processor;
pub mod state;
pub mod transition;

#[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
program_entrypoint!(process_instruction);
#[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
default_allocator!();
#[cfg(any(feature = "bpf-entrypoint", target_os = "solana"))]
default_panic_handler!();

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction::CoreInstruction::try_from(instruction_data)?;
    processor::process(program_id, accounts, instruction)
}
