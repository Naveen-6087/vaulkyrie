#![cfg_attr(feature = "bpf-entrypoint", no_std)]

use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
#[cfg(feature = "bpf-entrypoint")]
use pinocchio::{default_allocator, default_panic_handler, program_entrypoint};

pub mod error;
pub mod instruction;
pub mod pda;
pub mod processor;
pub mod state;
pub mod transition;

#[cfg(feature = "bpf-entrypoint")]
program_entrypoint!(process_instruction);
#[cfg(feature = "bpf-entrypoint")]
default_allocator!();
#[cfg(feature = "bpf-entrypoint")]
default_panic_handler!();

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction::CoreInstruction::try_from(instruction_data)?;
    processor::process(program_id, accounts, instruction)
}
