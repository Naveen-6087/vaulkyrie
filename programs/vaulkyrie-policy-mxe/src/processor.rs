use pinocchio::{
    account_info::AccountInfo,
    get_account_info,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use vaulkyrie_protocol::PolicyDecisionEnvelope;

use crate::{
    instruction::{
        AbortPolicyEvaluationArgs, InitPolicyConfigArgs, OpenPolicyEvaluationArgs,
        PolicyMxeInstruction, QueueArciumComputationArgs,
    },
    state::{
        PolicyConfigState, PolicyEvaluationState, POLICY_CONFIG_DISCRIMINATOR,
        POLICY_EVAL_DISCRIMINATOR,
    },
    transition,
};

/// Dispatch table for the vaulkyrie-policy-mxe program.
///
/// Account layouts per instruction variant:
/// - `InitPolicyConfig`:         [0: config (writable, owned), 1: authority (signer)]
/// - `OpenPolicyEvaluation`:     [0: config (writable, owned), 1: eval (writable, owned), 2: authority (signer)]
/// - `FinalizePolicyEvaluation`: [0: eval (writable, owned), 1: config (owned), 2: arcium_caller (signer)]
/// - `AbortPolicyEvaluation`:    [0: eval (writable, owned), 1: config (owned), 2: authority (signer)]
/// - `QueueArciumComputation`:   [0: eval (writable, owned), 1: authority (signer), 2+: Arcium accounts (future CPI)]
pub fn process(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    instruction: PolicyMxeInstruction,
) -> ProgramResult {
    match instruction {
        PolicyMxeInstruction::InitPolicyConfig(args) => {
            let authority = get_account_info!(accounts, 1);
            if !authority.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }

            let config_account = get_account_info!(accounts, 0);
            require_writable(config_account)?;
            require_program_owner(program_id, config_account)?;
            let mut data = config_account.try_borrow_mut_data()?;
            process_init_policy_config_data(&mut data, args)
        }
        PolicyMxeInstruction::OpenPolicyEvaluation(args) => {
            let current_slot = current_slot()?;

            let authority = get_account_info!(accounts, 2);
            if !authority.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }

            let config_account = get_account_info!(accounts, 0);
            require_writable(config_account)?;
            require_program_owner(program_id, config_account)?;

            let eval_account = get_account_info!(accounts, 1);
            require_writable(eval_account)?;
            require_program_owner(program_id, eval_account)?;

            let mut config_data = config_account.try_borrow_mut_data()?;
            let mut eval_data = eval_account.try_borrow_mut_data()?;
            process_open_policy_evaluation_data(
                &mut config_data,
                &mut eval_data,
                args,
                current_slot,
            )
        }
        PolicyMxeInstruction::FinalizePolicyEvaluation(envelope) => {
            let current_slot = current_slot()?;

            let eval_account = get_account_info!(accounts, 0);
            require_writable(eval_account)?;
            require_program_owner(program_id, eval_account)?;

            let config_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, config_account)?;

            {
                let config_data = config_account.try_borrow_data()?;
                let config = PolicyConfigState::decode(&config_data)
                    .ok_or(ProgramError::InvalidAccountData)?;
                require_discriminator(&config.discriminator, &POLICY_CONFIG_DISCRIMINATOR)?;

                let arcium_caller = get_account_info!(accounts, 2);
                if !arcium_caller.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                if arcium_caller.key() != &config.arcium_program {
                    return Err(ProgramError::IncorrectAuthority);
                }
            }

            let mut eval_data = eval_account.try_borrow_mut_data()?;
            process_finalize_policy_evaluation_data(&mut eval_data, &envelope, current_slot)
        }
        PolicyMxeInstruction::AbortPolicyEvaluation(args) => {
            let eval_account = get_account_info!(accounts, 0);
            require_writable(eval_account)?;
            require_program_owner(program_id, eval_account)?;

            let config_account = get_account_info!(accounts, 1);
            require_program_owner(program_id, config_account)?;

            {
                let config_data = config_account.try_borrow_data()?;
                let config = PolicyConfigState::decode(&config_data)
                    .ok_or(ProgramError::InvalidAccountData)?;
                require_discriminator(&config.discriminator, &POLICY_CONFIG_DISCRIMINATOR)?;

                let authority = get_account_info!(accounts, 2);
                if !authority.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                // Either the Arcium program or the registered core program may abort.
                if authority.key() != &config.arcium_program
                    && authority.key() != &config.core_program
                {
                    return Err(ProgramError::IncorrectAuthority);
                }
            }

            let mut eval_data = eval_account.try_borrow_mut_data()?;
            process_abort_policy_evaluation_data(&mut eval_data, args)
        }
        PolicyMxeInstruction::QueueArciumComputation(args) => {
            let current_slot = current_slot()?;

            let authority = get_account_info!(accounts, 1);
            if !authority.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }

            let eval_account = get_account_info!(accounts, 0);
            require_writable(eval_account)?;
            require_program_owner(program_id, eval_account)?;

            let mut eval_data = eval_account.try_borrow_mut_data()?;
            process_queue_arcium_computation_data(&mut eval_data, args, current_slot)
        }
    }
}

pub fn process_init_policy_config_data(
    dst: &mut [u8],
    args: InitPolicyConfigArgs,
) -> ProgramResult {
    if !is_zeroed(dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = transition::initialize_policy_config(
        args.core_program,
        args.arcium_program,
        args.mxe_account,
        args.policy_version,
        args.bump,
    );

    if !state.encode(dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_open_policy_evaluation_data(
    config_dst: &mut [u8],
    eval_dst: &mut [u8],
    args: OpenPolicyEvaluationArgs,
    current_slot: u64,
) -> ProgramResult {
    if !is_zeroed(eval_dst) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let mut config =
        PolicyConfigState::decode(config_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&config.discriminator, &POLICY_CONFIG_DISCRIMINATOR)?;

    let eval_state = transition::open_policy_evaluation(
        &mut config,
        &args.request,
        args.computation_offset,
        current_slot,
    )
    .map_err(map_transition_error)?;

    if !config.encode(config_dst) {
        return Err(ProgramError::InvalidAccountData);
    }
    if !eval_state.encode(eval_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_finalize_policy_evaluation_data(
    eval_dst: &mut [u8],
    envelope: &PolicyDecisionEnvelope,
    current_slot: u64,
) -> ProgramResult {
    let mut state =
        PolicyEvaluationState::decode(eval_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &POLICY_EVAL_DISCRIMINATOR)?;

    transition::finalize_policy_evaluation(&mut state, envelope, current_slot)
        .map_err(map_transition_error)?;

    if !state.encode(eval_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub fn process_abort_policy_evaluation_data(
    eval_dst: &mut [u8],
    args: AbortPolicyEvaluationArgs,
) -> ProgramResult {
    let mut state =
        PolicyEvaluationState::decode(eval_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &POLICY_EVAL_DISCRIMINATOR)?;

    if state.request_commitment != args.request_commitment {
        return Err(ProgramError::InvalidArgument);
    }

    transition::abort_policy_evaluation(&mut state, args.reason_code)
        .map_err(map_transition_error)?;

    if !state.encode(eval_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

/// Updates the evaluation account status to `ComputationQueued` and stores
/// the `computation_offset` for the pending Arcium MXE callback.
///
/// The actual CPI to the Arcium program is documented in `arcium_cpi.rs` and
/// will be wired in a future phase once the Anchor/Arcium dependency conflict
/// is resolved.
pub fn process_queue_arcium_computation_data(
    eval_dst: &mut [u8],
    args: QueueArciumComputationArgs,
    current_slot: u64,
) -> ProgramResult {
    let mut state =
        PolicyEvaluationState::decode(eval_dst).ok_or(ProgramError::InvalidAccountData)?;
    require_discriminator(&state.discriminator, &POLICY_EVAL_DISCRIMINATOR)?;

    if state.request_commitment != args.request_commitment {
        return Err(ProgramError::InvalidArgument);
    }

    transition::queue_arcium_computation(&mut state, args.computation_offset, current_slot)
        .map_err(map_transition_error)?;

    if !state.encode(eval_dst) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

fn require_writable(account: &AccountInfo) -> ProgramResult {
    if account.is_writable() {
        Ok(())
    } else {
        Err(ProgramError::Immutable)
    }
}

fn require_program_owner(
    program_id: &pinocchio::pubkey::Pubkey,
    account: &AccountInfo,
) -> ProgramResult {
    if account.owner() == program_id {
        Ok(())
    } else {
        Err(ProgramError::IncorrectProgramId)
    }
}

fn is_zeroed(data: &[u8]) -> bool {
    data.iter().all(|byte| *byte == 0)
}

fn require_discriminator(actual: &[u8; 8], expected: &[u8; 8]) -> ProgramResult {
    if actual == expected {
        Ok(())
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}

fn current_slot() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

fn map_transition_error(error: transition::TransitionError) -> ProgramError {
    match error {
        transition::TransitionError::PolicyVersionMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::RequestNonceMismatch => ProgramError::InvalidArgument,
        transition::TransitionError::RequestExpired => ProgramError::InvalidArgument,
        transition::TransitionError::RequestAlreadyFinalized => {
            ProgramError::AccountAlreadyInitialized
        }
        transition::TransitionError::RequestAlreadyAborted => {
            ProgramError::AccountAlreadyInitialized
        }
        transition::TransitionError::DecisionMismatch => ProgramError::InvalidAccountData,
        transition::TransitionError::DelayExceedsExpiry => ProgramError::InvalidArgument,
        transition::TransitionError::ComputationAlreadyQueued => {
            ProgramError::AccountAlreadyInitialized
        }
        transition::TransitionError::InvalidComputationStatus => {
            ProgramError::InvalidInstructionData
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        process_abort_policy_evaluation_data, process_finalize_policy_evaluation_data,
        process_init_policy_config_data, process_open_policy_evaluation_data,
        process_queue_arcium_computation_data,
    };
    use crate::{
        instruction::{
            AbortPolicyEvaluationArgs, InitPolicyConfigArgs, OpenPolicyEvaluationArgs,
            QueueArciumComputationArgs,
        },
        state::{
            PolicyConfigState, PolicyEvaluationState, PolicyEvaluationStatus,
            POLICY_CONFIG_DISCRIMINATOR, POLICY_EVAL_DISCRIMINATOR,
        },
    };
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{
        PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt, ThresholdRequirement,
    };

    fn sample_config_args() -> InitPolicyConfigArgs {
        InitPolicyConfigArgs {
            core_program: [1; 32],
            arcium_program: [2; 32],
            mxe_account: [3; 32],
            policy_version: 9,
            bump: 4,
        }
    }

    fn sample_request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            vault_id: [5; 32],
            action_hash: [6; 32],
            policy_version: 9,
            request_nonce: 0,
            expiry_slot: 900,
            encrypted_input_commitment: [7; 32],
        }
    }

    #[test]
    fn init_policy_config_writes_state() {
        let mut buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut buf, sample_config_args()).expect("should init");

        let decoded = PolicyConfigState::decode(&buf).expect("should decode");
        assert_eq!(decoded.discriminator, POLICY_CONFIG_DISCRIMINATOR);
        assert_eq!(decoded.policy_version, 9);
        assert_eq!(decoded.bump, 4);
    }

    #[test]
    fn init_policy_config_rejects_non_zeroed_account() {
        let mut buf = vec![0u8; PolicyConfigState::LEN];
        buf[0] = 1;
        assert_eq!(
            process_init_policy_config_data(&mut buf, sample_config_args()),
            Err(ProgramError::AccountAlreadyInitialized),
        );
    }

    #[test]
    fn open_policy_evaluation_advances_config_nonce() {
        let mut config_buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut config_buf, sample_config_args()).unwrap();

        let mut eval_buf = vec![0u8; PolicyEvaluationState::LEN];
        let args = OpenPolicyEvaluationArgs {
            request: sample_request(),
            computation_offset: 33,
        };
        process_open_policy_evaluation_data(&mut config_buf, &mut eval_buf, args, 400)
            .expect("should open");

        let config = PolicyConfigState::decode(&config_buf).unwrap();
        assert_eq!(config.next_request_nonce, 1);

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        assert_eq!(eval.discriminator, POLICY_EVAL_DISCRIMINATOR);
        assert_eq!(eval.policy_version, 9);
        assert_eq!(eval.status, PolicyEvaluationStatus::Pending as u8);
    }

    #[test]
    fn finalize_policy_evaluation_records_decision() {
        let mut config_buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut config_buf, sample_config_args()).unwrap();

        let request = sample_request();
        let mut eval_buf = vec![0u8; PolicyEvaluationState::LEN];
        let args = OpenPolicyEvaluationArgs {
            request: request.clone(),
            computation_offset: 77,
        };
        process_open_policy_evaluation_data(&mut config_buf, &mut eval_buf, args, 400).unwrap();

        let envelope = PolicyDecisionEnvelope {
            request_commitment: request.commitment(),
            receipt: PolicyReceipt {
                action_hash: request.action_hash,
                policy_version: request.policy_version,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 9,
                expiry_slot: 880,
            },
            delay_until_slot: 840,
            reason_code: 31,
            computation_offset: 77,
            result_commitment: [8; 32],
        };

        process_finalize_policy_evaluation_data(&mut eval_buf, &envelope, 500)
            .expect("should finalize");

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        assert_eq!(eval.status, PolicyEvaluationStatus::Finalized as u8);
        assert_eq!(eval.reason_code, 31);
    }

    #[test]
    fn abort_policy_evaluation_marks_aborted() {
        let mut config_buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut config_buf, sample_config_args()).unwrap();

        let request = sample_request();
        let mut eval_buf = vec![0u8; PolicyEvaluationState::LEN];
        let args = OpenPolicyEvaluationArgs {
            request: request.clone(),
            computation_offset: 33,
        };
        process_open_policy_evaluation_data(&mut config_buf, &mut eval_buf, args, 400).unwrap();

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        let abort_args = AbortPolicyEvaluationArgs {
            request_commitment: eval.request_commitment,
            reason_code: 99,
        };
        process_abort_policy_evaluation_data(&mut eval_buf, abort_args).expect("should abort");

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        assert_eq!(eval.status, PolicyEvaluationStatus::Aborted as u8);
        assert_eq!(eval.reason_code, 99);
    }

    #[test]
    fn queue_arcium_computation_advances_to_computation_queued() {
        let mut config_buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut config_buf, sample_config_args()).unwrap();

        let request = sample_request();
        let mut eval_buf = vec![0u8; PolicyEvaluationState::LEN];
        let open_args = OpenPolicyEvaluationArgs {
            request: request.clone(),
            computation_offset: 33,
        };
        process_open_policy_evaluation_data(&mut config_buf, &mut eval_buf, open_args, 400)
            .unwrap();

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        let queue_args = QueueArciumComputationArgs {
            request_commitment: eval.request_commitment,
            computation_offset: 88,
        };
        process_queue_arcium_computation_data(&mut eval_buf, queue_args, 400)
            .expect("should queue");

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        assert_eq!(eval.status, PolicyEvaluationStatus::ComputationQueued as u8);
        assert_eq!(eval.computation_offset, 88);
    }

    #[test]
    fn queue_arcium_computation_rejects_wrong_commitment() {
        let mut config_buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut config_buf, sample_config_args()).unwrap();

        let request = sample_request();
        let mut eval_buf = vec![0u8; PolicyEvaluationState::LEN];
        let open_args = OpenPolicyEvaluationArgs {
            request,
            computation_offset: 33,
        };
        process_open_policy_evaluation_data(&mut config_buf, &mut eval_buf, open_args, 400)
            .unwrap();

        let queue_args = QueueArciumComputationArgs {
            request_commitment: [0xff; 32], // wrong commitment
            computation_offset: 88,
        };
        assert_eq!(
            process_queue_arcium_computation_data(&mut eval_buf, queue_args, 400),
            Err(pinocchio::program_error::ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn queue_arcium_computation_rejects_double_queue() {
        let mut config_buf = vec![0u8; PolicyConfigState::LEN];
        process_init_policy_config_data(&mut config_buf, sample_config_args()).unwrap();

        let request = sample_request();
        let mut eval_buf = vec![0u8; PolicyEvaluationState::LEN];
        let open_args = OpenPolicyEvaluationArgs {
            request: request.clone(),
            computation_offset: 33,
        };
        process_open_policy_evaluation_data(&mut config_buf, &mut eval_buf, open_args, 400)
            .unwrap();

        let eval = PolicyEvaluationState::decode(&eval_buf).unwrap();
        let queue_args = QueueArciumComputationArgs {
            request_commitment: eval.request_commitment,
            computation_offset: 88,
        };
        process_queue_arcium_computation_data(&mut eval_buf, queue_args, 400)
            .expect("first queue should succeed");

        let queue_args2 = QueueArciumComputationArgs {
            request_commitment: eval.request_commitment,
            computation_offset: 88,
        };
        assert_eq!(
            process_queue_arcium_computation_data(&mut eval_buf, queue_args2, 400),
            Err(pinocchio::program_error::ProgramError::AccountAlreadyInitialized)
        );
    }
}
