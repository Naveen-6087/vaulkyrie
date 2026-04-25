use anchor_lang::prelude::*;

// Arcium SDK re-exports: MXE account types, CPI helpers, and the program macro.
use arcium_anchor::prelude::*;
use arcium_anchor::traits::{InitCompDefAccs, QueueCompAccs};
use arcium_client::idl::arcium::cpi::accounts::QueueComputation;
use arcium_client::idl::arcium::types::{CallbackAccount, CallbackInstruction, Output, Parameter};

pub mod errors;
pub mod state;
pub mod transition;

// Placeholder program ID — replace with actual deployed address.
declare_id!("6XVfpzDXRDQXLHfvwkLA6So3WTriQfWQphsHzfWSSGr7");

pub const POLICY_CONFIG_SEED: &[u8] = b"policy_config";
pub const POLICY_EVAL_SEED: &[u8] = b"policy_eval";

/// Arcium computation definition offset for "policy_evaluate" circuit.
/// Deterministic u32 derived from SHA-256("policy_evaluate")[0..4].
pub const POLICY_EVALUATE_COMP_DEF_OFFSET: u32 = arcium_anchor::comp_def_offset("policy_evaluate");

/// Vaulkyrie policy evaluation output produced by the Arcium MXE circuit.
///
/// The callback instruction receives this struct inside
/// `SignedComputationOutputs<PolicyEvaluateOutput>`. Fields match the Arcis
/// circuit return type (see `crates/encrypted-ixs`).
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PolicyEvaluateOutput {
    /// SHA-256 commitment over the policy receipt fields.
    pub receipt_commitment: [u8; 32],
    /// SHA-256 commitment over the full decision envelope.
    pub decision_commitment: [u8; 32],
    /// Earliest slot the action may execute (time-lock).
    pub delay_until_slot: u64,
    /// Machine-readable reason code (0 = approved without conditions).
    pub reason_code: u16,
    /// 1 = approved, 0 = denied.
    pub approved: u8,
}

impl arcium_anchor::HasSize for PolicyEvaluateOutput {
    const SIZE: usize = 75; // 32 + 32 + 8 + 2 + 1
}

// `#[arcium_program]` wraps Anchor's `#[program]` and generates:
//   - `ArciumSignerAccount` struct (PDA signer, space=9)
//   - `CallbackError` enum for callback validation errors
//   - `validate_callback_ixs()` security function for callback instructions
#[arcium_program]
pub mod vaulkyrie_policy_mxe {
    use super::*;

    /// Initialize the policy configuration account.
    pub fn init_policy_config(
        ctx: Context<InitPolicyConfig>,
        core_program: [u8; 32],
        arcium_program: [u8; 32],
        mxe_account: [u8; 32],
        policy_version: u64,
        bump: u8,
    ) -> Result<()> {
        handlers::process_init_policy_config(
            ctx,
            core_program,
            arcium_program,
            mxe_account,
            policy_version,
            bump,
        )
    }

    /// Open a new policy evaluation request.
    pub fn open_policy_evaluation(
        ctx: Context<OpenPolicyEvaluation>,
        vault_id: [u8; 32],
        action_hash: [u8; 32],
        encrypted_input_commitment: [u8; 32],
        request_nonce: u64,
        expiry_slot: u64,
        computation_offset: u64,
    ) -> Result<()> {
        handlers::process_open_policy_evaluation(
            ctx,
            vault_id,
            action_hash,
            encrypted_input_commitment,
            request_nonce,
            expiry_slot,
            computation_offset,
        )
    }

    /// Finalize an evaluation with a signed decision envelope.
    pub fn finalize_policy_evaluation(
        ctx: Context<FinalizePolicyEvaluation>,
        request_commitment: [u8; 32],
        action_hash: [u8; 32],
        policy_version: u64,
        threshold: u8,
        nonce: u64,
        receipt_expiry_slot: u64,
        delay_until_slot: u64,
        reason_code: u16,
        computation_offset: u64,
        result_commitment: [u8; 32],
    ) -> Result<()> {
        handlers::process_finalize_policy_evaluation(
            ctx,
            request_commitment,
            action_hash,
            policy_version,
            threshold,
            nonce,
            receipt_expiry_slot,
            delay_until_slot,
            reason_code,
            computation_offset,
            result_commitment,
        )
    }

    /// Abort a pending evaluation.
    pub fn abort_policy_evaluation(
        ctx: Context<AbortPolicyEvaluation>,
        reason_code: u16,
    ) -> Result<()> {
        handlers::process_abort_policy_evaluation(ctx, reason_code)
    }

    /// Queue an Arcium MXE computation for this evaluation (local state transition).
    pub fn queue_arcium_computation(
        ctx: Context<QueueArciumComputation>,
        computation_offset: u64,
    ) -> Result<()> {
        handlers::process_queue_arcium_computation(ctx, computation_offset)
    }

    // ── Arcium CPI instructions ───────────────────────────────────────────

    /// One-time initialization of the `policy_evaluate` computation definition
    /// account on the Arcium MXE.
    ///
    /// Must be called once after program deployment, before any policy
    /// evaluations can be queued. Creates the `ComputationDefinitionAccount`
    /// PDA that stores the circuit interface (parameter/output types).
    pub fn init_policy_evaluate_comp_def(ctx: Context<InitPolicyEvaluateCompDef>) -> Result<()> {
        handlers::process_init_policy_evaluate_comp_def(ctx)
    }

    /// Queue the encrypted policy evaluation via Arcium MXE CPI.
    ///
    /// Sends encrypted policy inputs to the MXE cluster for private
    /// evaluation and registers a callback that will finalize the
    /// evaluation state when the computation completes.
    pub fn queue_policy_evaluate(
        ctx: Context<QueuePolicyEvaluate>,
        computation_offset: u64,
        encrypted_input: [u8; 32],
        x25519_pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        handlers::process_queue_policy_evaluate(
            ctx,
            computation_offset,
            encrypted_input,
            x25519_pubkey,
            nonce,
        )
    }

    /// Arcium callback: receives the MPC computation result.
    ///
    /// Called by the Arcium MXE program after the `policy_evaluate` circuit
    /// completes. Validates the callback transaction structure, verifies
    /// the computation output signature, and finalizes the evaluation state
    /// with the receipt and decision commitments.
    pub fn policy_evaluate_callback(
        ctx: Context<PolicyEvaluateCallback>,
        output: arcium_anchor::SignedComputationOutputs<PolicyEvaluateOutput>,
    ) -> Result<()> {
        handlers::process_policy_evaluate_callback(ctx, output)
    }
}

// ── Accounts structs ──────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitPolicyConfig<'info> {
    /// CHECK: manual validation — preserves custom `POLCFG01` discriminator
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OpenPolicyEvaluation<'info> {
    /// CHECK: manual validation — preserves custom `POLCFG01` discriminator
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    /// CHECK: manual validation — preserves custom `POLEVAL1` discriminator
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub clock: Sysvar<'info, Clock>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FinalizePolicyEvaluation<'info> {
    /// CHECK: manual validation — preserves custom `POLEVAL1` discriminator
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct AbortPolicyEvaluation<'info> {
    /// CHECK: manual validation — preserves custom `POLEVAL1` discriminator
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct QueueArciumComputation<'info> {
    /// CHECK: manual validation — preserves custom `POLEVAL1` discriminator
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    pub clock: Sysvar<'info, Clock>,
}

// ── Arcium CPI account structs (manual — no compiled circuit required) ────

/// Accounts for one-time computation definition initialization.
///
/// Manually implements `InitCompDefAccs` instead of using
/// `#[init_computation_definition_accounts("policy_evaluate", payer)]`,
/// which requires compiled circuit artifacts. The trait maps these accounts
/// to the fields that `arcium_anchor::init_comp_def()` expects.
#[derive(Accounts)]
pub struct InitPolicyEvaluateCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Arcium MXE global state account.
    #[account(
        mut,
        address = arcium_anchor::derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    /// CHECK: Computation definition PDA — checked by Arcium CPI.
    #[account(mut)]
    pub comp_def_account: UncheckedAccount<'info>,

    /// CHECK: Address lookup table for MXE — checked by Arcium CPI.
    #[account(mut)]
    pub address_lookup_table: UncheckedAccount<'info>,

    /// CHECK: Solana Address Lookup Table program.
    #[account(address = LUT_PROGRAM_ID)]
    pub lut_program: UncheckedAccount<'info>,

    /// Arcium MXE program.
    pub arcium_program: Program<'info, Arcium>,

    pub system_program: Program<'info, System>,
}

/// Manual `InitCompDefAccs` implementation — equivalent to what
/// `#[init_computation_definition_accounts("policy_evaluate", payer)]`
/// would generate.
///
/// The `params()` and `outputs()` define the computation signature:
///   - 3 inputs: x25519 pubkey, u128 nonce, encrypted policy payload
///   - 5 outputs: 2×ciphertext (commitments), u64, u16, u8
impl<'info> InitCompDefAccs<'info> for InitPolicyEvaluateCompDef<'info> {
    fn arcium_program(&self) -> AccountInfo<'info> {
        self.arcium_program.to_account_info()
    }

    fn mxe_program(&self) -> Pubkey {
        crate::ID
    }

    fn signer(&self) -> AccountInfo<'info> {
        self.payer.to_account_info()
    }

    fn mxe_acc(&self) -> AccountInfo<'info> {
        self.mxe_account.to_account_info()
    }

    fn comp_def_acc(&self) -> AccountInfo<'info> {
        self.comp_def_account.to_account_info()
    }

    fn address_lookup_table(&self) -> AccountInfo<'info> {
        self.address_lookup_table.to_account_info()
    }

    fn lut_program(&self) -> AccountInfo<'info> {
        self.lut_program.to_account_info()
    }

    fn system_program(&self) -> AccountInfo<'info> {
        self.system_program.to_account_info()
    }

    fn params(&self) -> Vec<Parameter> {
        vec![
            Parameter::ArcisX25519Pubkey,
            Parameter::PlaintextU128,
            Parameter::Ciphertext,
        ]
    }

    fn outputs(&self) -> Vec<Output> {
        vec![
            Output::Ciphertext,   // receipt_commitment  (32 bytes)
            Output::Ciphertext,   // decision_commitment (32 bytes)
            Output::PlaintextU64, // delay_until_slot
            Output::PlaintextU16, // reason_code
            Output::PlaintextU8,  // approved flag
        ]
    }

    fn comp_def_offset(&self) -> u32 {
        POLICY_EVALUATE_COMP_DEF_OFFSET
    }

    fn compiled_circuit_len(&self) -> u32 {
        0 // Circuit stored offchain — bytecode not uploaded onchain
    }

    fn weight(&self) -> u64 {
        0 // Placeholder — actual weight set during `arcium deploy`
    }
}

/// Accounts required to queue a policy evaluation computation via Arcium CPI.
///
/// Manually implements `QueueCompAccs` instead of using the
/// `#[queue_computation_accounts]` macro, which requires a compiled circuit
/// in `build/policy_evaluate.arcis`. The trait implementation is below.
#[derive(Accounts)]
pub struct QueuePolicyEvaluate<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Vaulkyrie evaluation state — validated in handler
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,

    /// Arcium MXE global state account.
    pub mxe_account: Account<'info, MXEAccount>,

    /// Program-owned PDA signer (seeds = [SIGN_PDA_SEED]).
    #[account(mut)]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,

    /// CHECK: Arcium mempool account (writable, validated by Arcium CPI)
    #[account(mut)]
    pub mempool_account: UncheckedAccount<'info>,

    /// CHECK: Arcium executing pool (writable, validated by Arcium CPI)
    #[account(mut)]
    pub executing_pool: UncheckedAccount<'info>,

    /// CHECK: Arcium computation account (writable, validated by Arcium CPI)
    #[account(mut)]
    pub computation_account: UncheckedAccount<'info>,

    /// Arcium computation definition account.
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

    /// Arcium cluster account.
    #[account(mut)]
    pub cluster_account: Account<'info, Cluster>,

    /// Arcium fee pool account.
    #[account(mut)]
    pub pool_account: Account<'info, FeePool>,

    pub clock_account: Sysvar<'info, Clock>,
    pub system_program: Program<'info, System>,

    /// Arcium MXE program.
    pub arcium_program: Program<'info, Arcium>,
}

/// Manual `QueueCompAccs` implementation — equivalent to what
/// `#[queue_computation_accounts("policy_evaluate", payer)]` would generate.
impl<'info> QueueCompAccs<'info> for QueuePolicyEvaluate<'info> {
    fn comp_def_offset(&self) -> u32 {
        POLICY_EVALUATE_COMP_DEF_OFFSET
    }

    fn queue_comp_accs(&self) -> QueueComputation<'info> {
        QueueComputation {
            signer: self.payer.to_account_info(),
            sign_seed: self.sign_pda_account.to_account_info(),
            comp: self.computation_account.to_account_info(),
            mxe: self.mxe_account.to_account_info(),
            mempool: self.mempool_account.to_account_info(),
            executing_pool: self.executing_pool.to_account_info(),
            comp_def_acc: self.comp_def_account.to_account_info(),
            cluster: self.cluster_account.to_account_info(),
            pool_account: self.pool_account.to_account_info(),
            system_program: self.system_program.to_account_info(),
            clock: self.clock_account.to_account_info(),
        }
    }

    fn arcium_program(&self) -> AccountInfo<'info> {
        self.arcium_program.to_account_info()
    }

    fn mxe_program(&self) -> Pubkey {
        crate::ID
    }

    fn signer_pda_bump(&self) -> u8 {
        self.sign_pda_account.bump
    }
}

/// Accounts for the Arcium callback after policy evaluation completes.
///
/// Manually defined instead of using `#[callback_accounts("policy_evaluate")]`
/// which requires compiled circuit artifacts.
#[derive(Accounts)]
pub struct PolicyEvaluateCallback<'info> {
    /// CHECK: Vaulkyrie evaluation state — validated in handler
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,

    /// Arcium MXE program.
    pub arcium_program: Program<'info, Arcium>,

    /// Arcium computation definition for `policy_evaluate`.
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

    /// Arcium MXE global state.
    pub mxe_account: Account<'info, MXEAccount>,

    /// CHECK: Arcium computation account (validated by output verification)
    pub computation_account: UncheckedAccount<'info>,

    /// Arcium cluster that executed the computation.
    pub cluster_account: Account<'info, Cluster>,

    /// CHECK: Instructions sysvar — used by `validate_callback_ixs`
    pub instructions_sysvar: UncheckedAccount<'info>,
}

// ── Handlers (internal) ───────────────────────────────────────────────────

mod handlers {
    use super::*;
    use crate::errors::PolicyMxeError;
    use crate::state::{
        PolicyConfigState, PolicyEvaluationState, POLICY_CONFIG_DISCRIMINATOR,
        POLICY_EVAL_DISCRIMINATOR,
    };
    use anchor_lang::solana_program::{
        program::invoke_signed, system_instruction, system_program, sysvar::rent::Rent,
    };
    use vaulkyrie_protocol::{
        PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt, ThresholdRequirement,
    };

    fn bootstrap_program_account<'info>(
        payer: &Signer<'info>,
        target: &UncheckedAccount<'info>,
        system_program_account: &Program<'info, System>,
        seeds_without_bump: &[&[u8]],
        space: usize,
    ) -> Result<()> {
        let (expected, bump) = Pubkey::find_program_address(seeds_without_bump, &crate::ID);
        if expected != target.key() {
            return Err(PolicyMxeError::InvalidInstructionData.into());
        }

        if target.owner == &crate::ID {
            return Ok(());
        }

        if target.owner != &system_program::ID || target.lamports() != 0 || target.data_len() != 0 {
            return Err(PolicyMxeError::AccountOwnerMismatch.into());
        }

        let lamports = Rent::get()?.minimum_balance(space);
        let bump_seed = [bump];
        let mut signer_seeds = seeds_without_bump.to_vec();
        signer_seeds.push(&bump_seed);
        let signer = [signer_seeds.as_slice()];

        invoke_signed(
            &system_instruction::create_account(
                &payer.key(),
                &target.key(),
                lamports,
                space as u64,
                &crate::ID,
            ),
            &[
                payer.to_account_info(),
                target.to_account_info(),
                system_program_account.to_account_info(),
            ],
            &signer,
        )?;

        Ok(())
    }

    pub fn process_init_policy_config(
        ctx: Context<InitPolicyConfig>,
        core_program: [u8; 32],
        arcium_program: [u8; 32],
        mxe_account: [u8; 32],
        policy_version: u64,
        bump: u8,
    ) -> Result<()> {
        let config_info = &ctx.accounts.config;
        let authority_key = ctx.accounts.authority.key();
        bootstrap_program_account(
            &ctx.accounts.authority,
            config_info,
            &ctx.accounts.system_program,
            &[POLICY_CONFIG_SEED, authority_key.as_ref()],
            PolicyConfigState::LEN,
        )?;
        let mut data = config_info.try_borrow_mut_data()?;

        if data.len() != PolicyConfigState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        if data[..8] == POLICY_CONFIG_DISCRIMINATOR {
            return Err(PolicyMxeError::AlreadyInitialized.into());
        }

        let new_state = transition::initialize_policy_config(
            core_program,
            arcium_program,
            mxe_account,
            policy_version,
            bump,
        );
        new_state.encode(&mut data);
        Ok(())
    }

    pub fn process_open_policy_evaluation(
        ctx: Context<OpenPolicyEvaluation>,
        vault_id: [u8; 32],
        action_hash: [u8; 32],
        encrypted_input_commitment: [u8; 32],
        request_nonce: u64,
        expiry_slot: u64,
        computation_offset: u64,
    ) -> Result<()> {
        let config_info = &ctx.accounts.config;
        let eval_info = &ctx.accounts.evaluation;
        let current_slot = ctx.accounts.clock.slot;

        // Decode and validate config.
        let mut config_data = config_info.try_borrow_mut_data()?;
        if config_data.len() != PolicyConfigState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        let mut config =
            PolicyConfigState::decode(&config_data).ok_or(PolicyMxeError::NotInitialized)?;
        if config.discriminator != POLICY_CONFIG_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }
        let config_key = config_info.key();

        bootstrap_program_account(
            &ctx.accounts.authority,
            eval_info,
            &ctx.accounts.system_program,
            &[POLICY_EVAL_SEED, config_key.as_ref(), &action_hash],
            PolicyEvaluationState::LEN,
        )?;

        // Validate evaluation account.
        let mut eval_data = eval_info.try_borrow_mut_data()?;
        if eval_data.len() != PolicyEvaluationState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        if eval_data[..8] == POLICY_EVAL_DISCRIMINATOR {
            return Err(PolicyMxeError::AlreadyInitialized.into());
        }

        let request = PolicyEvaluationRequest {
            vault_id,
            action_hash,
            policy_version: config.policy_version,
            request_nonce,
            expiry_slot,
            encrypted_input_commitment,
        };

        let eval_state = transition::open_policy_evaluation(
            &mut config,
            &request,
            computation_offset,
            current_slot,
        )
        .map_err(PolicyMxeError::from)?;

        config.encode(&mut config_data);
        eval_state.encode(&mut eval_data);
        Ok(())
    }

    pub fn process_finalize_policy_evaluation(
        ctx: Context<FinalizePolicyEvaluation>,
        request_commitment: [u8; 32],
        action_hash: [u8; 32],
        policy_version: u64,
        threshold: u8,
        nonce: u64,
        receipt_expiry_slot: u64,
        delay_until_slot: u64,
        reason_code: u16,
        computation_offset: u64,
        result_commitment: [u8; 32],
    ) -> Result<()> {
        let eval_info = &ctx.accounts.evaluation;
        let current_slot = ctx.accounts.clock.slot;

        let mut eval_data = eval_info.try_borrow_mut_data()?;
        if eval_data.len() != PolicyEvaluationState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        let mut eval_state =
            PolicyEvaluationState::decode(&eval_data).ok_or(PolicyMxeError::NotInitialized)?;
        if eval_state.discriminator != POLICY_EVAL_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }

        let threshold_req = ThresholdRequirement::try_from(threshold)
            .map_err(|_| PolicyMxeError::InvalidInstructionData)?;

        let envelope = PolicyDecisionEnvelope {
            request_commitment,
            receipt: PolicyReceipt {
                action_hash,
                policy_version,
                threshold: threshold_req,
                nonce,
                expiry_slot: receipt_expiry_slot,
            },
            delay_until_slot,
            reason_code,
            computation_offset,
            result_commitment,
        };

        transition::finalize_policy_evaluation(&mut eval_state, &envelope, current_slot)
            .map_err(PolicyMxeError::from)?;

        eval_state.encode(&mut eval_data);
        Ok(())
    }

    pub fn process_abort_policy_evaluation(
        ctx: Context<AbortPolicyEvaluation>,
        reason_code: u16,
    ) -> Result<()> {
        let eval_info = &ctx.accounts.evaluation;

        let mut eval_data = eval_info.try_borrow_mut_data()?;
        if eval_data.len() != PolicyEvaluationState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        let mut eval_state =
            PolicyEvaluationState::decode(&eval_data).ok_or(PolicyMxeError::NotInitialized)?;
        if eval_state.discriminator != POLICY_EVAL_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }

        transition::abort_policy_evaluation(&mut eval_state, reason_code)
            .map_err(PolicyMxeError::from)?;

        eval_state.encode(&mut eval_data);
        Ok(())
    }

    pub fn process_queue_arcium_computation(
        ctx: Context<QueueArciumComputation>,
        computation_offset: u64,
    ) -> Result<()> {
        let eval_info = &ctx.accounts.evaluation;
        let current_slot = ctx.accounts.clock.slot;

        let mut eval_data = eval_info.try_borrow_mut_data()?;
        if eval_data.len() != PolicyEvaluationState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        let mut eval_state =
            PolicyEvaluationState::decode(&eval_data).ok_or(PolicyMxeError::NotInitialized)?;
        if eval_state.discriminator != POLICY_EVAL_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }

        transition::queue_arcium_computation(&mut eval_state, computation_offset, current_slot)
            .map_err(PolicyMxeError::from)?;

        eval_state.encode(&mut eval_data);
        Ok(())
    }

    // ── Arcium CPI handlers ──────────────────────────────────────────────

    /// Initialize the `policy_evaluate` computation definition on the Arcium MXE.
    ///
    /// This is a one-time setup instruction called after program deployment.
    /// It creates the `ComputationDefinitionAccount` PDA that stores the
    /// circuit interface (parameter types, output types, and metadata).
    pub fn process_init_policy_evaluate_comp_def(
        ctx: Context<InitPolicyEvaluateCompDef>,
    ) -> Result<()> {
        arcium_anchor::init_comp_def(&*ctx.accounts, None, None)?;
        Ok(())
    }

    /// Queue the encrypted policy evaluation through the Arcium MXE.
    ///
    /// 1. Validates and transitions evaluation state to `ComputationQueued`
    /// 2. Builds encrypted arguments via `ArgBuilder`
    /// 3. Registers a callback instruction so the MXE calls
    ///    `policy_evaluate_callback` when the computation finishes
    /// 4. Calls `queue_computation` CPI into the Arcium program
    pub fn process_queue_policy_evaluate(
        ctx: Context<QueuePolicyEvaluate>,
        computation_offset: u64,
        encrypted_input: [u8; 32],
        x25519_pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        // Transition evaluation state to ComputationQueued.
        let eval_info = &ctx.accounts.evaluation;
        let current_slot = ctx.accounts.clock_account.slot;
        {
            let mut eval_data = eval_info.try_borrow_mut_data()?;
            if eval_data.len() != PolicyEvaluationState::LEN {
                return Err(PolicyMxeError::InvalidAccountSize.into());
            }
            let mut eval_state =
                PolicyEvaluationState::decode(&eval_data).ok_or(PolicyMxeError::NotInitialized)?;
            if eval_state.discriminator != POLICY_EVAL_DISCRIMINATOR {
                return Err(PolicyMxeError::NotInitialized.into());
            }

            transition::queue_arcium_computation(&mut eval_state, computation_offset, current_slot)
                .map_err(PolicyMxeError::from)?;

            eval_state.encode(&mut eval_data);
        }

        // Build Arcium encrypted arguments:
        //   arg0: x25519 public key (for shared encryption envelope)
        //   arg1: nonce (128-bit plaintext)
        //   arg2: encrypted policy input (32-byte ciphertext)
        let args = ArgBuilder::new()
            .x25519_pubkey(x25519_pubkey)
            .plaintext_u128(nonce)
            .encrypted_u8(encrypted_input)
            .build();

        // Build callback instruction so the MXE routes the result back to us.
        // The callback needs our evaluation account as a writable extra account.
        let callback_extra_accs = vec![CallbackAccount {
            pubkey: eval_info.key(),
            is_writable: true,
        }];

        let callback_ix = build_callback_instruction(
            computation_offset,
            &ctx.accounts.mxe_account,
            &callback_extra_accs,
        )?;

        // CPI into Arcium to queue the computation.
        arcium_anchor::queue_computation(
            &*ctx.accounts,
            computation_offset,
            args,
            vec![callback_ix],
            1, // single callback transaction
            0, // no priority fee
        )?;

        Ok(())
    }

    /// Process the MXE callback after the policy evaluation circuit completes.
    ///
    /// Validates the callback transaction structure (must follow Arcium's
    /// `callback_computation` instruction), verifies the output signature
    /// against the cluster, and finalizes the evaluation with the MPC result.
    pub fn process_policy_evaluate_callback(
        ctx: Context<PolicyEvaluateCallback>,
        output: arcium_anchor::SignedComputationOutputs<PolicyEvaluateOutput>,
    ) -> Result<()> {
        // Security: ensure this instruction immediately follows Arcium's
        // callback_computation instruction with no trailing instructions.
        validate_callback_ixs(
            &ctx.accounts.instructions_sysvar,
            &ctx.accounts.arcium_program.key(),
        )?;

        // Verify the computation output against the cluster's signing key.
        let verified_output = output
            .verify_output(
                &ctx.accounts.cluster_account,
                &ctx.accounts.computation_account,
            )
            .map_err(|_| PolicyMxeError::InvalidInstructionData)?;

        // Extract the MPC result and finalize evaluation state.
        let eval_info = &ctx.accounts.evaluation;
        let mut eval_data = eval_info.try_borrow_mut_data()?;
        if eval_data.len() != PolicyEvaluationState::LEN {
            return Err(PolicyMxeError::InvalidAccountSize.into());
        }
        let mut eval_state =
            PolicyEvaluationState::decode(&eval_data).ok_or(PolicyMxeError::NotInitialized)?;
        if eval_state.discriminator != POLICY_EVAL_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }

        // Route through the transition layer so denied evaluations are aborted
        // instead of finalized — preventing them from passing the core bridge.
        transition::apply_mxe_callback(
            &mut eval_state,
            verified_output.receipt_commitment,
            verified_output.decision_commitment,
            verified_output.delay_until_slot,
            verified_output.reason_code,
            verified_output.approved == 1,
        )
        .map_err(PolicyMxeError::from)?;

        eval_state.encode(&mut eval_data);
        Ok(())
    }
}

// ── Callback instruction builder ──────────────────────────────────────────

/// Builds the `CallbackInstruction` metadata that tells the Arcium MXE
/// how to route the computation result back to `policy_evaluate_callback`.
///
/// This is the manual equivalent of what `#[callback_accounts("policy_evaluate")]`
/// would generate via the `CallbackCompAccs` trait.
fn build_callback_instruction(
    _computation_offset: u64,
    _mxe_account: &MXEAccount,
    extra_accs: &[CallbackAccount],
) -> Result<CallbackInstruction> {
    let mut accounts = Vec::with_capacity(extra_accs.len() + 6);

    // Standard Arcium callback accounts (order matters).
    accounts.push(CallbackAccount {
        pubkey: ARCIUM_PROG_ID,
        is_writable: false,
    });
    accounts.push(CallbackAccount {
        pubkey: arcium_anchor::derive_comp_def_pda!(POLICY_EVALUATE_COMP_DEF_OFFSET),
        is_writable: false,
    });
    accounts.push(CallbackAccount {
        pubkey: arcium_anchor::derive_mxe_pda!(),
        is_writable: false,
    });
    // Computation and cluster PDAs are resolved at runtime by the MXE cranker,
    // but we pass placeholders since the macro-generated code does the same
    // derivation. The Arcium runtime fills in the actual addresses.
    accounts.push(CallbackAccount {
        pubkey: Pubkey::default(),
        is_writable: false,
    });
    accounts.push(CallbackAccount {
        pubkey: Pubkey::default(),
        is_writable: false,
    });
    // Instructions sysvar
    accounts.push(CallbackAccount {
        pubkey: anchor_lang::solana_program::sysvar::instructions::ID,
        is_writable: false,
    });

    // Extra accounts (e.g., our evaluation state).
    accounts.extend_from_slice(extra_accs);

    Ok(CallbackInstruction {
        program_id: crate::ID,
        discriminator: crate::instruction::PolicyEvaluateCallback::DISCRIMINATOR.to_vec(),
        accounts,
    })
}
