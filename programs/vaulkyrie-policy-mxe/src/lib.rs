use anchor_lang::prelude::*;

pub mod errors;
pub mod state;
pub mod transition;

// Placeholder program ID — replace with actual deployed address.
declare_id!("99gQafBBNAZitScYub5BnJcA7asqdRVndwvCj2Zt7m7L");

#[program]
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

    /// Queue an Arcium MXE computation for this evaluation.
    pub fn queue_arcium_computation(
        ctx: Context<QueueArciumComputation>,
        computation_offset: u64,
    ) -> Result<()> {
        handlers::process_queue_arcium_computation(ctx, computation_offset)
    }
}

// ── Accounts structs ──────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitPolicyConfig<'info> {
    /// CHECK: manual validation — preserves custom `POLCFG01` discriminator
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct OpenPolicyEvaluation<'info> {
    /// CHECK: manual validation — preserves custom `POLCFG01` discriminator
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    /// CHECK: manual validation — preserves custom `POLEVAL1` discriminator
    #[account(mut)]
    pub evaluation: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    pub clock: Sysvar<'info, Clock>,
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

// ── Handlers (internal) ───────────────────────────────────────────────────

mod handlers {
    use super::*;
    use crate::errors::PolicyMxeError;
    use crate::state::{
        PolicyConfigState, PolicyEvaluationState, POLICY_CONFIG_DISCRIMINATOR,
        POLICY_EVAL_DISCRIMINATOR,
    };
    use vaulkyrie_protocol::{
        PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt, ThresholdRequirement,
    };

    pub fn process_init_policy_config(
        ctx: Context<InitPolicyConfig>,
        core_program: [u8; 32],
        arcium_program: [u8; 32],
        mxe_account: [u8; 32],
        policy_version: u64,
        bump: u8,
    ) -> Result<()> {
        let config_info = &ctx.accounts.config;
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
        let mut config = PolicyConfigState::decode(&config_data)
            .ok_or(PolicyMxeError::NotInitialized)?;
        if config.discriminator != POLICY_CONFIG_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }

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
        let mut eval_state = PolicyEvaluationState::decode(&eval_data)
            .ok_or(PolicyMxeError::NotInitialized)?;
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
        let mut eval_state = PolicyEvaluationState::decode(&eval_data)
            .ok_or(PolicyMxeError::NotInitialized)?;
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
        let mut eval_state = PolicyEvaluationState::decode(&eval_data)
            .ok_or(PolicyMxeError::NotInitialized)?;
        if eval_state.discriminator != POLICY_EVAL_DISCRIMINATOR {
            return Err(PolicyMxeError::NotInitialized.into());
        }

        transition::queue_arcium_computation(&mut eval_state, computation_offset, current_slot)
            .map_err(PolicyMxeError::from)?;

        eval_state.encode(&mut eval_data);
        Ok(())
    }
}
