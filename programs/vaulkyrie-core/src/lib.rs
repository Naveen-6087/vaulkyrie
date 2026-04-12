#![cfg_attr(feature = "bpf-entrypoint", no_std)]

use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};
#[cfg(feature = "bpf-entrypoint")]
use pinocchio::{default_allocator, default_panic_handler, program_entrypoint};

pub mod instruction;

#[cfg(feature = "bpf-entrypoint")]
program_entrypoint!(process_instruction);
#[cfg(feature = "bpf-entrypoint")]
default_allocator!();
#[cfg(feature = "bpf-entrypoint")]
default_panic_handler!();

#[cfg(feature = "bpf-entrypoint")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let _ = instruction::CoreInstruction::try_from(instruction_data)?;
    Ok(())
}
