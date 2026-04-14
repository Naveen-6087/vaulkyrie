use pinocchio::program_error::ProgramError;
use vaulkyrie_protocol::{PolicyDecisionEnvelope, PolicyEvaluationRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitPolicyConfigArgs {
    pub core_program: [u8; 32],
    pub arcium_program: [u8; 32],
    pub mxe_account: [u8; 32],
    pub policy_version: u64,
    pub bump: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPolicyEvaluationArgs {
    pub request: PolicyEvaluationRequest,
    pub computation_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbortPolicyEvaluationArgs {
    pub request_commitment: [u8; 32],
    pub reason_code: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueArciumComputationArgs {
    /// Commitment binding this computation to the originating evaluation request.
    pub request_commitment: [u8; 32],
    /// Arcium computation offset used to correlate the MXE callback.
    pub computation_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMxeInstruction {
    InitPolicyConfig(InitPolicyConfigArgs),
    OpenPolicyEvaluation(OpenPolicyEvaluationArgs),
    FinalizePolicyEvaluation(PolicyDecisionEnvelope),
    AbortPolicyEvaluation(AbortPolicyEvaluationArgs),
    /// Queue an Arcium MXE computation for a `Pending` evaluation.
    QueueArciumComputation(QueueArciumComputationArgs),
}

impl TryFrom<&[u8]> for PolicyMxeInstruction {
    type Error = ProgramError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        match data {
            [0, rest @ ..] => Ok(Self::InitPolicyConfig(parse_init_policy_config(rest)?)),
            [1, rest @ ..] => Ok(Self::OpenPolicyEvaluation(parse_open_policy_evaluation(
                rest,
            )?)),
            [2, rest @ ..] => Ok(Self::FinalizePolicyEvaluation(
                PolicyDecisionEnvelope::decode(rest).ok_or(ProgramError::InvalidInstructionData)?,
            )),
            [3, rest @ ..] => Ok(Self::AbortPolicyEvaluation(parse_abort_policy_evaluation(
                rest,
            )?)),
            [4, rest @ ..] => Ok(Self::QueueArciumComputation(
                parse_queue_arcium_computation(rest)?,
            )),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

fn parse_init_policy_config(data: &[u8]) -> Result<InitPolicyConfigArgs, ProgramError> {
    if data.len() != 105 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut core_program = [0; 32];
    core_program.copy_from_slice(&data[..32]);

    let mut arcium_program = [0; 32];
    arcium_program.copy_from_slice(&data[32..64]);

    let mut mxe_account = [0; 32];
    mxe_account.copy_from_slice(&data[64..96]);

    let mut policy_version = [0; 8];
    policy_version.copy_from_slice(&data[96..104]);

    Ok(InitPolicyConfigArgs {
        core_program,
        arcium_program,
        mxe_account,
        policy_version: u64::from_le_bytes(policy_version),
        bump: data[104],
    })
}

fn parse_open_policy_evaluation(data: &[u8]) -> Result<OpenPolicyEvaluationArgs, ProgramError> {
    if data.len() != PolicyEvaluationRequest::ENCODED_LEN + 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let request = PolicyEvaluationRequest::decode(&data[..PolicyEvaluationRequest::ENCODED_LEN])
        .ok_or(ProgramError::InvalidInstructionData)?;

    let mut computation_offset = [0; 8];
    computation_offset.copy_from_slice(&data[PolicyEvaluationRequest::ENCODED_LEN..]);

    Ok(OpenPolicyEvaluationArgs {
        request,
        computation_offset: u64::from_le_bytes(computation_offset),
    })
}

fn parse_abort_policy_evaluation(data: &[u8]) -> Result<AbortPolicyEvaluationArgs, ProgramError> {
    if data.len() != 34 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut request_commitment = [0; 32];
    request_commitment.copy_from_slice(&data[..32]);

    let mut reason_code = [0; 2];
    reason_code.copy_from_slice(&data[32..34]);

    Ok(AbortPolicyEvaluationArgs {
        request_commitment,
        reason_code: u16::from_le_bytes(reason_code),
    })
}

fn parse_queue_arcium_computation(
    data: &[u8],
) -> Result<QueueArciumComputationArgs, ProgramError> {
    // 32 bytes request_commitment + 8 bytes computation_offset.
    if data.len() != 40 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut request_commitment = [0; 32];
    request_commitment.copy_from_slice(&data[..32]);

    let mut computation_offset = [0; 8];
    computation_offset.copy_from_slice(&data[32..40]);

    Ok(QueueArciumComputationArgs {
        request_commitment,
        computation_offset: u64::from_le_bytes(computation_offset),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AbortPolicyEvaluationArgs, InitPolicyConfigArgs, OpenPolicyEvaluationArgs,
        PolicyMxeInstruction,
    };
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{
        PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt, ThresholdRequirement,
    };

    fn sample_request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            vault_id: [1; 32],
            action_hash: [2; 32],
            policy_version: 9,
            request_nonce: 3,
            expiry_slot: 700,
            encrypted_input_commitment: [4; 32],
        }
    }

    #[test]
    fn parses_init_policy_config_instruction() {
        let mut data = vec![0];
        data.extend_from_slice(&[7; 32]);
        data.extend_from_slice(&[8; 32]);
        data.extend_from_slice(&[9; 32]);
        data.extend_from_slice(&11u64.to_le_bytes());
        data.push(2);

        assert_eq!(
            PolicyMxeInstruction::try_from(data.as_slice()),
            Ok(PolicyMxeInstruction::InitPolicyConfig(
                InitPolicyConfigArgs {
                    core_program: [7; 32],
                    arcium_program: [8; 32],
                    mxe_account: [9; 32],
                    policy_version: 11,
                    bump: 2,
                }
            ))
        );
    }

    #[test]
    fn parses_open_policy_evaluation_instruction() {
        let request = sample_request();
        let mut encoded_request = [0u8; PolicyEvaluationRequest::ENCODED_LEN];
        assert!(request.encode(&mut encoded_request));

        let mut data = vec![1];
        data.extend_from_slice(&encoded_request);
        data.extend_from_slice(&44u64.to_le_bytes());

        assert_eq!(
            PolicyMxeInstruction::try_from(data.as_slice()),
            Ok(PolicyMxeInstruction::OpenPolicyEvaluation(
                OpenPolicyEvaluationArgs {
                    request,
                    computation_offset: 44,
                }
            ))
        );
    }

    #[test]
    fn parses_finalize_policy_evaluation_instruction() {
        let request = sample_request();
        let envelope = PolicyDecisionEnvelope {
            request_commitment: request.commitment(),
            receipt: PolicyReceipt {
                action_hash: request.action_hash,
                policy_version: request.policy_version,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 5,
                expiry_slot: 680,
            },
            delay_until_slot: 640,
            reason_code: 12,
            computation_offset: 77,
            result_commitment: [6; 32],
        };
        let mut encoded = [0u8; PolicyDecisionEnvelope::ENCODED_LEN];
        assert!(envelope.encode(&mut encoded));

        let mut data = vec![2];
        data.extend_from_slice(&encoded);

        assert_eq!(
            PolicyMxeInstruction::try_from(data.as_slice()),
            Ok(PolicyMxeInstruction::FinalizePolicyEvaluation(envelope))
        );
    }

    #[test]
    fn parses_abort_policy_evaluation_instruction() {
        let mut data = vec![3];
        data.extend_from_slice(&[7; 32]);
        data.extend_from_slice(&15u16.to_le_bytes());

        assert_eq!(
            PolicyMxeInstruction::try_from(data.as_slice()),
            Ok(PolicyMxeInstruction::AbortPolicyEvaluation(
                AbortPolicyEvaluationArgs {
                    request_commitment: [7; 32],
                    reason_code: 15,
                }
            ))
        );
    }

    #[test]
    fn rejects_unknown_instruction() {
        assert_eq!(
            PolicyMxeInstruction::try_from(&[9][..]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn parses_queue_arcium_computation_instruction() {
        let mut data = vec![4];
        data.extend_from_slice(&[11; 32]); // request_commitment
        data.extend_from_slice(&42u64.to_le_bytes()); // computation_offset

        use super::QueueArciumComputationArgs;
        assert_eq!(
            PolicyMxeInstruction::try_from(data.as_slice()),
            Ok(PolicyMxeInstruction::QueueArciumComputation(
                QueueArciumComputationArgs {
                    request_commitment: [11; 32],
                    computation_offset: 42,
                }
            ))
        );
    }

    #[test]
    fn rejects_queue_arcium_computation_with_wrong_length() {
        let data = vec![4u8; 30]; // too short
        assert_eq!(
            PolicyMxeInstruction::try_from(data.as_slice()),
            Err(ProgramError::InvalidInstructionData)
        );
    }
}
