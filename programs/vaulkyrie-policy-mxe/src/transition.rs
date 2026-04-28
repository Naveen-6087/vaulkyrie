use vaulkyrie_protocol::{PolicyDecisionEnvelope, PolicyEvaluationRequest};

use crate::state::{PolicyConfigState, PolicyEvaluationState, PolicyEvaluationStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    PolicyVersionMismatch,
    RequestNonceMismatch,
    RequestExpired,
    RequestAlreadyFinalized,
    RequestAlreadyAborted,
    DecisionMismatch,
    DelayExceedsExpiry,
    /// `QueueArciumComputation` called when computation is already queued.
    ComputationAlreadyQueued,
    /// Status value does not allow the requested transition.
    InvalidComputationStatus,
}

pub fn initialize_policy_config(
    core_program: [u8; 32],
    arcium_program: [u8; 32],
    mxe_account: [u8; 32],
    policy_version: u64,
    bump: u8,
) -> PolicyConfigState {
    PolicyConfigState::new(
        core_program,
        arcium_program,
        mxe_account,
        policy_version,
        bump,
    )
}

pub fn open_policy_evaluation(
    config: &mut PolicyConfigState,
    request: &PolicyEvaluationRequest,
    computation_offset: u64,
    current_slot: u64,
) -> Result<PolicyEvaluationState, TransitionError> {
    if request.policy_version != config.policy_version {
        return Err(TransitionError::PolicyVersionMismatch);
    }
    if request.request_nonce != config.next_request_nonce {
        return Err(TransitionError::RequestNonceMismatch);
    }
    if request.expiry_slot < current_slot {
        return Err(TransitionError::RequestExpired);
    }

    config.next_request_nonce += 1;

    Ok(PolicyEvaluationState::new(
        request.commitment(),
        request.vault_id,
        request.action_hash,
        request.encrypted_input_commitment,
        request.policy_version,
        request.request_nonce,
        request.expiry_slot,
        computation_offset,
    ))
}

pub fn finalize_policy_evaluation(
    state: &mut PolicyEvaluationState,
    envelope: &PolicyDecisionEnvelope,
    current_slot: u64,
) -> Result<(), TransitionError> {
    match state.status {
        value if value == PolicyEvaluationStatus::Finalized as u8 => {
            return Err(TransitionError::RequestAlreadyFinalized);
        }
        value if value == PolicyEvaluationStatus::Aborted as u8 => {
            return Err(TransitionError::RequestAlreadyAborted);
        }
        // Allow finalization from Pending or ComputationQueued.
        value
            if value == PolicyEvaluationStatus::Pending as u8
                || value == PolicyEvaluationStatus::ComputationQueued as u8 => {}
        _ => return Err(TransitionError::InvalidComputationStatus),
    }

    if state.expiry_slot < current_slot || !matches_envelope(state, envelope) {
        return Err(TransitionError::DecisionMismatch);
    }
    if envelope.delay_until_slot > envelope.receipt.expiry_slot {
        return Err(TransitionError::DelayExceedsExpiry);
    }

    state.receipt_commitment = envelope.receipt.commitment();
    state.decision_commitment = envelope.commitment();
    state.delay_until_slot = envelope.delay_until_slot;
    state.reason_code = envelope.reason_code;
    state.status = PolicyEvaluationStatus::Finalized as u8;

    Ok(())
}

pub fn abort_policy_evaluation(
    state: &mut PolicyEvaluationState,
    reason_code: u16,
) -> Result<(), TransitionError> {
    match state.status {
        value if value == PolicyEvaluationStatus::Finalized as u8 => {
            return Err(TransitionError::RequestAlreadyFinalized);
        }
        value if value == PolicyEvaluationStatus::Aborted as u8 => {
            return Err(TransitionError::RequestAlreadyAborted);
        }
        // Allow abort from Pending or ComputationQueued.
        value
            if value == PolicyEvaluationStatus::Pending as u8
                || value == PolicyEvaluationStatus::ComputationQueued as u8 => {}
        _ => return Err(TransitionError::InvalidComputationStatus),
    }

    state.reason_code = reason_code;
    state.status = PolicyEvaluationStatus::Aborted as u8;

    Ok(())
}

/// Records that an Arcium computation has been queued for this evaluation.
///
/// Transitions the status from `Pending` to `ComputationQueued` and stores
/// the supplied `computation_offset` so the callback can correlate results.
/// Calling this twice returns `ComputationAlreadyQueued`.
pub fn queue_arcium_computation(
    state: &mut PolicyEvaluationState,
    computation_offset: u64,
    current_slot: u64,
) -> Result<(), TransitionError> {
    match state.status {
        value if value == PolicyEvaluationStatus::Finalized as u8 => {
            return Err(TransitionError::RequestAlreadyFinalized);
        }
        value if value == PolicyEvaluationStatus::Aborted as u8 => {
            return Err(TransitionError::RequestAlreadyAborted);
        }
        value if value == PolicyEvaluationStatus::ComputationQueued as u8 => {
            return Err(TransitionError::ComputationAlreadyQueued);
        }
        value if value == PolicyEvaluationStatus::Pending as u8 => {}
        _ => return Err(TransitionError::InvalidComputationStatus),
    }

    if state.expiry_slot < current_slot {
        return Err(TransitionError::RequestExpired);
    }

    state.computation_offset = computation_offset;
    state.status = PolicyEvaluationStatus::ComputationQueued as u8;

    Ok(())
}

/// Apply the Arcium MXE callback result to an evaluation in `ComputationQueued`
/// status.  If the circuit approved the action the state transitions to
/// `Finalized` with the computed commitments.  If denied, it transitions to
/// `Aborted` — preventing the core bridge from accepting the evaluation.
pub fn apply_mxe_callback(
    state: &mut PolicyEvaluationState,
    receipt_commitment: [u8; 32],
    decision_commitment: [u8; 32],
    delay_until_slot: u64,
    reason_code: u16,
    decision_flags: u16,
    approved: bool,
) -> Result<(), TransitionError> {
    if state.status != PolicyEvaluationStatus::ComputationQueued as u8 {
        return Err(TransitionError::InvalidComputationStatus);
    }

    state.reason_code = reason_code;
    state.set_decision_flags(decision_flags);

    if approved {
        state.receipt_commitment = receipt_commitment;
        state.decision_commitment = decision_commitment;
        state.delay_until_slot = delay_until_slot;
        state.status = PolicyEvaluationStatus::Finalized as u8;
    } else {
        state.status = PolicyEvaluationStatus::Aborted as u8;
    }

    Ok(())
}

fn matches_envelope(state: &PolicyEvaluationState, envelope: &PolicyDecisionEnvelope) -> bool {
    state.request_commitment == envelope.request_commitment
        && state.action_hash == envelope.receipt.action_hash
        && state.policy_version == envelope.receipt.policy_version
        && state.computation_offset == envelope.computation_offset
        && envelope.receipt.expiry_slot <= state.expiry_slot
}

#[cfg(test)]
mod tests {
    use super::{
        abort_policy_evaluation, apply_mxe_callback, finalize_policy_evaluation,
        initialize_policy_config, open_policy_evaluation, queue_arcium_computation,
        TransitionError,
    };
    use crate::state::PolicyEvaluationStatus;
    use vaulkyrie_protocol::{
        PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt, ThresholdRequirement,
    };

    fn sample_request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            vault_id: [1; 32],
            action_hash: [2; 32],
            policy_version: 9,
            request_nonce: 0,
            expiry_slot: 900,
            encrypted_input_commitment: [3; 32],
        }
    }

    #[test]
    fn opening_policy_evaluation_advances_nonce() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();

        let state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        assert_eq!(config.next_request_nonce, 1);
        assert_eq!(state.request_commitment, request.commitment());
        assert_eq!(state.status, PolicyEvaluationStatus::Pending as u8);
    }

    #[test]
    fn opening_policy_evaluation_rejects_policy_mismatch() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 10, 2);

        assert_eq!(
            open_policy_evaluation(&mut config, &sample_request(), 77, 400),
            Err(TransitionError::PolicyVersionMismatch)
        );
    }

    #[test]
    fn finalizing_policy_evaluation_records_commitments() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");
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
            result_commitment: [7; 32],
        };

        finalize_policy_evaluation(&mut state, &envelope, 500)
            .expect("decision envelope should finalize");

        assert_eq!(state.receipt_commitment, envelope.receipt.commitment());
        assert_eq!(state.decision_commitment, envelope.commitment());
        assert_eq!(state.delay_until_slot, 840);
        assert_eq!(state.reason_code, 31);
        assert_eq!(state.status, PolicyEvaluationStatus::Finalized as u8);
    }

    #[test]
    fn finalizing_policy_evaluation_rejects_mismatched_envelope() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");
        let mut envelope = PolicyDecisionEnvelope {
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
            result_commitment: [7; 32],
        };
        envelope.computation_offset = 88;

        assert_eq!(
            finalize_policy_evaluation(&mut state, &envelope, 500),
            Err(TransitionError::DecisionMismatch)
        );
    }

    #[test]
    fn aborting_policy_evaluation_marks_state_aborted() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        abort_policy_evaluation(&mut state, 44).expect("abort should succeed");

        assert_eq!(state.reason_code, 44);
        assert_eq!(state.status, PolicyEvaluationStatus::Aborted as u8);
    }

    #[test]
    fn queue_arcium_computation_transitions_to_computation_queued() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        queue_arcium_computation(&mut state, 55, 400).expect("queue should succeed");

        assert_eq!(
            state.status,
            PolicyEvaluationStatus::ComputationQueued as u8
        );
        assert_eq!(state.computation_offset, 55);
    }

    #[test]
    fn queue_arcium_computation_rejects_double_queue() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        queue_arcium_computation(&mut state, 55, 400).expect("first queue should succeed");

        assert_eq!(
            queue_arcium_computation(&mut state, 55, 400),
            Err(TransitionError::ComputationAlreadyQueued)
        );
    }

    #[test]
    fn queue_arcium_computation_rejects_expired_request() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request(); // expiry_slot = 900
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        assert_eq!(
            queue_arcium_computation(&mut state, 55, 1000),
            Err(TransitionError::RequestExpired)
        );
    }

    #[test]
    fn finalize_allows_computation_queued_state() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        queue_arcium_computation(&mut state, 77, 400).expect("queue should succeed");

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
            reason_code: 5,
            computation_offset: 77,
            result_commitment: [9; 32],
        };

        finalize_policy_evaluation(&mut state, &envelope, 500)
            .expect("finalize from ComputationQueued should succeed");

        assert_eq!(state.status, PolicyEvaluationStatus::Finalized as u8);
    }

    #[test]
    fn abort_allows_computation_queued_state() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");

        queue_arcium_computation(&mut state, 77, 400).expect("queue should succeed");
        abort_policy_evaluation(&mut state, 11)
            .expect("abort from ComputationQueued should succeed");

        assert_eq!(state.status, PolicyEvaluationStatus::Aborted as u8);
        assert_eq!(state.reason_code, 11);
    }

    // ── apply_mxe_callback tests ──────────────────────────────────────────

    #[test]
    fn mxe_callback_approved_finalizes_evaluation() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");
        queue_arcium_computation(&mut state, 77, 400).expect("queue should succeed");

        apply_mxe_callback(&mut state, [10; 32], [11; 32], 850, 0, 0x33, true)
            .expect("approved callback should finalize");

        assert_eq!(state.status, PolicyEvaluationStatus::Finalized as u8);
        assert_eq!(state.receipt_commitment, [10; 32]);
        assert_eq!(state.decision_commitment, [11; 32]);
        assert_eq!(state.delay_until_slot, 850);
        assert_eq!(state.decision_flags(), 0x33);
        assert_eq!(state.reason_code, 0);
    }

    #[test]
    fn mxe_callback_denied_aborts_evaluation() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");
        queue_arcium_computation(&mut state, 77, 400).expect("queue should succeed");

        apply_mxe_callback(&mut state, [10; 32], [11; 32], 850, 42, 0x55, false)
            .expect("denied callback should abort");

        assert_eq!(state.status, PolicyEvaluationStatus::Aborted as u8);
        assert_eq!(state.reason_code, 42);
        assert_eq!(state.decision_flags(), 0x55);
        // Commitments should NOT be written on denial.
        assert_eq!(state.receipt_commitment, [0; 32]);
        assert_eq!(state.decision_commitment, [0; 32]);
    }

    #[test]
    fn mxe_callback_rejects_non_queued_status() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");
        // State is Pending, not ComputationQueued.
        assert_eq!(
            apply_mxe_callback(&mut state, [10; 32], [11; 32], 850, 0, 0, true),
            Err(TransitionError::InvalidComputationStatus)
        );
    }

    #[test]
    fn mxe_callback_rejects_already_finalized() {
        let mut config = initialize_policy_config([4; 32], [5; 32], [6; 32], 9, 2);
        let request = sample_request();
        let mut state =
            open_policy_evaluation(&mut config, &request, 77, 400).expect("request should open");
        queue_arcium_computation(&mut state, 77, 400).expect("queue should succeed");
        apply_mxe_callback(&mut state, [10; 32], [11; 32], 850, 0, 0, true)
            .expect("first callback should succeed");

        // Second callback on already-finalized state should fail.
        assert_eq!(
            apply_mxe_callback(&mut state, [10; 32], [11; 32], 850, 0, 0, true),
            Err(TransitionError::InvalidComputationStatus)
        );
    }
}
