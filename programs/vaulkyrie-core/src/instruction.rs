use pinocchio::program_error::ProgramError;
use solana_winternitz::signature::WinternitzSignature;
use vaulkyrie_protocol::{
    AuthorityRotationStatement, PolicyReceipt, ThresholdRequirement, WotsAuthProof,
    AUTHORITY_PROOF_CHUNK_MAX_BYTES,
};

pub const WINTERNITZ_SIGNATURE_BYTES: usize = core::mem::size_of::<WinternitzSignature>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitVaultArgs {
    pub wallet_pubkey: [u8; 32],
    pub authority_hash: [u8; 32],
    pub policy_version: u64,
    pub bump: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitAuthorityArgs {
    pub current_authority_hash: [u8; 32],
    pub current_authority_root: [u8; 32],
    pub bump: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitQuantumVaultArgs {
    pub hash: [u8; 32],
    pub bump: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitQuantumVaultArgs {
    pub signature: [u8; WINTERNITZ_SIGNATURE_BYTES],
    pub amount: u64,
    pub bump: u8,
}

impl SplitQuantumVaultArgs {
    pub fn signature(&self) -> WinternitzSignature {
        WinternitzSignature::from(self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseQuantumVaultArgs {
    pub signature: [u8; WINTERNITZ_SIGNATURE_BYTES],
    pub bump: u8,
}

impl CloseQuantumVaultArgs {
    pub fn signature(&self) -> WinternitzSignature {
        WinternitzSignature::from(self.signature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitSpendOrchestrationArgs {
    pub action_hash: [u8; 32],
    pub session_commitment: [u8; 32],
    pub signers_commitment: [u8; 32],
    pub signing_package_hash: [u8; 32],
    pub expiry_slot: u64,
    pub threshold: u8,
    pub participant_count: u8,
    pub bump: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitSpendOrchestrationArgs {
    pub action_hash: [u8; 32],
    pub signing_package_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteSpendOrchestrationArgs {
    pub action_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailSpendOrchestrationArgs {
    pub action_hash: [u8; 32],
    pub reason_code: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateAuthorityArgs {
    pub statement: AuthorityRotationStatement,
    pub proof: WotsAuthProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitAuthorityProofArgs {
    pub statement_digest: [u8; 32],
    pub proof_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAuthorityProofChunkArgs {
    pub offset: u32,
    pub chunk_len: u16,
    pub chunk: [u8; AUTHORITY_PROOF_CHUNK_MAX_BYTES],
}

impl WriteAuthorityProofChunkArgs {
    pub fn chunk_bytes(&self) -> &[u8] {
        &self.chunk[..usize::from(self.chunk_len)]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreInstruction {
    Ping,
    InitVault(InitVaultArgs),
    InitAuthority(InitAuthorityArgs),
    InitQuantumVault(InitQuantumVaultArgs),
    StageReceipt(PolicyReceipt),
    ConsumeReceipt(PolicyReceipt),
    OpenSession(PolicyReceipt),
    ActivateSession([u8; 32]),
    ConsumeSession([u8; 32]),
    FinalizeSession(PolicyReceipt),
    SetVaultStatus(u8),
    RotateAuthority(RotateAuthorityArgs),
    InitAuthorityProof(InitAuthorityProofArgs),
    WriteAuthorityProofChunk(WriteAuthorityProofChunkArgs),
    RotateAuthorityStaged(AuthorityRotationStatement),
    SplitQuantumVault(SplitQuantumVaultArgs),
    CloseQuantumVault(CloseQuantumVaultArgs),
    InitSpendOrchestration(InitSpendOrchestrationArgs),
    CommitSpendOrchestration(CommitSpendOrchestrationArgs),
    CompleteSpendOrchestration(CompleteSpendOrchestrationArgs),
    FailSpendOrchestration(FailSpendOrchestrationArgs),
    /// Stage a policy receipt that has been cross-validated against a
    /// finalized `PolicyEvaluationState` account owned by vaulkyrie-policy-mxe.
    StageBridgedReceipt(PolicyReceipt),
}

impl TryFrom<&[u8]> for CoreInstruction {
    type Error = ProgramError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        match data {
            [0] => Ok(Self::Ping),
            [1, rest @ ..] => Ok(Self::InitVault(parse_init_vault(rest)?)),
            [2, rest @ ..] => Ok(Self::InitAuthority(parse_init_authority(rest)?)),
            [3, rest @ ..] => Ok(Self::InitQuantumVault(parse_init_quantum_vault(rest)?)),
            [4, rest @ ..] => Ok(Self::StageReceipt(parse_policy_receipt(rest)?)),
            [5, rest @ ..] => Ok(Self::ConsumeReceipt(parse_policy_receipt(rest)?)),
            [6, rest @ ..] => Ok(Self::OpenSession(parse_policy_receipt(rest)?)),
            [7, rest @ ..] => Ok(Self::ActivateSession(parse_action_hash(rest)?)),
            [8, rest @ ..] => Ok(Self::ConsumeSession(parse_action_hash(rest)?)),
            [9, rest @ ..] => Ok(Self::FinalizeSession(parse_policy_receipt(rest)?)),
            [10, rest @ ..] => Ok(Self::SetVaultStatus(parse_vault_status(rest)?)),
            [11, rest @ ..] => Ok(Self::RotateAuthority(parse_rotate_authority_args(rest)?)),
            [12, rest @ ..] => Ok(Self::InitAuthorityProof(parse_init_authority_proof(rest)?)),
            [13, rest @ ..] => Ok(Self::WriteAuthorityProofChunk(
                parse_write_authority_proof_chunk(rest)?,
            )),
            [14, rest @ ..] => Ok(Self::RotateAuthorityStaged(
                parse_authority_rotation_statement(rest)?,
            )),
            [15, rest @ ..] => Ok(Self::SplitQuantumVault(parse_split_quantum_vault(rest)?)),
            [16, rest @ ..] => Ok(Self::CloseQuantumVault(parse_close_quantum_vault(rest)?)),
            [17, rest @ ..] => Ok(Self::InitSpendOrchestration(
                parse_init_spend_orchestration(rest)?,
            )),
            [18, rest @ ..] => Ok(Self::CommitSpendOrchestration(
                parse_commit_spend_orchestration(rest)?,
            )),
            [19, rest @ ..] => Ok(Self::CompleteSpendOrchestration(
                parse_complete_spend_orchestration(rest)?,
            )),
            [20, rest @ ..] => Ok(Self::FailSpendOrchestration(
                parse_fail_spend_orchestration(rest)?,
            )),
            [21, rest @ ..] => Ok(Self::StageBridgedReceipt(parse_policy_receipt(rest)?)),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

fn parse_vault_status(data: &[u8]) -> Result<u8, ProgramError> {
    if data.len() != 1 {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(data[0])
}

fn parse_action_hash(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    if data.len() != 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(data);
    Ok(action_hash)
}

fn parse_init_vault(data: &[u8]) -> Result<InitVaultArgs, ProgramError> {
    if data.len() != 73 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut wallet_pubkey = [0; 32];
    wallet_pubkey.copy_from_slice(&data[..32]);

    let mut authority_hash = [0; 32];
    authority_hash.copy_from_slice(&data[32..64]);

    let mut policy_version = [0; 8];
    policy_version.copy_from_slice(&data[64..72]);

    Ok(InitVaultArgs {
        wallet_pubkey,
        authority_hash,
        policy_version: u64::from_le_bytes(policy_version),
        bump: data[72],
    })
}

fn parse_init_authority(data: &[u8]) -> Result<InitAuthorityArgs, ProgramError> {
    if data.len() != 65 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut current_authority_hash = [0; 32];
    current_authority_hash.copy_from_slice(&data[..32]);

    let mut current_authority_root = [0; 32];
    current_authority_root.copy_from_slice(&data[32..64]);

    Ok(InitAuthorityArgs {
        current_authority_hash,
        current_authority_root,
        bump: data[64],
    })
}

fn parse_init_quantum_vault(data: &[u8]) -> Result<InitQuantumVaultArgs, ProgramError> {
    if data.len() != 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut hash = [0; 32];
    hash.copy_from_slice(&data[..32]);

    Ok(InitQuantumVaultArgs {
        hash,
        bump: data[32],
    })
}

fn parse_policy_receipt(data: &[u8]) -> Result<PolicyReceipt, ProgramError> {
    if data.len() != 57 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(&data[..32]);

    let mut policy_version = [0; 8];
    policy_version.copy_from_slice(&data[32..40]);

    let threshold = ThresholdRequirement::try_from(data[40])
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let mut nonce = [0; 8];
    nonce.copy_from_slice(&data[41..49]);

    let mut expiry_slot = [0; 8];
    expiry_slot.copy_from_slice(&data[49..57]);

    Ok(PolicyReceipt {
        action_hash,
        policy_version: u64::from_le_bytes(policy_version),
        threshold,
        nonce: u64::from_le_bytes(nonce),
        expiry_slot: u64::from_le_bytes(expiry_slot),
    })
}

fn parse_authority_rotation_statement(
    data: &[u8],
) -> Result<AuthorityRotationStatement, ProgramError> {
    if data.len() != 80 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(&data[..32]);

    let mut next_authority_hash = [0; 32];
    next_authority_hash.copy_from_slice(&data[32..64]);

    let mut sequence = [0; 8];
    sequence.copy_from_slice(&data[64..72]);

    let mut expiry_slot = [0; 8];
    expiry_slot.copy_from_slice(&data[72..80]);

    Ok(AuthorityRotationStatement {
        action_hash,
        next_authority_hash,
        sequence: u64::from_le_bytes(sequence),
        expiry_slot: u64::from_le_bytes(expiry_slot),
    })
}

fn parse_rotate_authority_args(data: &[u8]) -> Result<RotateAuthorityArgs, ProgramError> {
    if data.len() != 80 + WotsAuthProof::ENCODED_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let statement = parse_authority_rotation_statement(&data[..80])?;
    let proof = WotsAuthProof::decode(&data[80..]).ok_or(ProgramError::InvalidInstructionData)?;

    Ok(RotateAuthorityArgs { statement, proof })
}

fn parse_init_authority_proof(data: &[u8]) -> Result<InitAuthorityProofArgs, ProgramError> {
    if data.len() != 64 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut statement_digest = [0; 32];
    statement_digest.copy_from_slice(&data[..32]);

    let mut proof_commitment = [0; 32];
    proof_commitment.copy_from_slice(&data[32..64]);

    Ok(InitAuthorityProofArgs {
        statement_digest,
        proof_commitment,
    })
}

fn parse_write_authority_proof_chunk(
    data: &[u8],
) -> Result<WriteAuthorityProofChunkArgs, ProgramError> {
    if data.len() < 6 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut offset = [0; 4];
    offset.copy_from_slice(&data[..4]);

    let mut chunk_len = [0; 2];
    chunk_len.copy_from_slice(&data[4..6]);
    let chunk_len = u16::from_le_bytes(chunk_len);
    let chunk_len_usize = usize::from(chunk_len);

    if chunk_len_usize == 0
        || chunk_len_usize > AUTHORITY_PROOF_CHUNK_MAX_BYTES
        || data.len() != 6 + chunk_len_usize
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut chunk = [0; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
    chunk[..chunk_len_usize].copy_from_slice(&data[6..]);

    Ok(WriteAuthorityProofChunkArgs {
        offset: u32::from_le_bytes(offset),
        chunk_len,
        chunk,
    })
}

fn parse_split_quantum_vault(data: &[u8]) -> Result<SplitQuantumVaultArgs, ProgramError> {
    if data.len() != WINTERNITZ_SIGNATURE_BYTES + 8 + 1 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut signature = [0; WINTERNITZ_SIGNATURE_BYTES];
    signature.copy_from_slice(&data[..WINTERNITZ_SIGNATURE_BYTES]);

    let mut amount = [0; 8];
    amount.copy_from_slice(&data[WINTERNITZ_SIGNATURE_BYTES..WINTERNITZ_SIGNATURE_BYTES + 8]);

    Ok(SplitQuantumVaultArgs {
        signature,
        amount: u64::from_le_bytes(amount),
        bump: data[WINTERNITZ_SIGNATURE_BYTES + 8],
    })
}

fn parse_close_quantum_vault(data: &[u8]) -> Result<CloseQuantumVaultArgs, ProgramError> {
    if data.len() != WINTERNITZ_SIGNATURE_BYTES + 1 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut signature = [0; WINTERNITZ_SIGNATURE_BYTES];
    signature.copy_from_slice(&data[..WINTERNITZ_SIGNATURE_BYTES]);

    Ok(CloseQuantumVaultArgs {
        signature,
        bump: data[WINTERNITZ_SIGNATURE_BYTES],
    })
}

fn parse_init_spend_orchestration(
    data: &[u8],
) -> Result<InitSpendOrchestrationArgs, ProgramError> {
    // 32 + 32 + 32 + 32 + 8 + 1 + 1 + 1 = 139
    if data.len() != 139 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(&data[..32]);

    let mut session_commitment = [0; 32];
    session_commitment.copy_from_slice(&data[32..64]);

    let mut signers_commitment = [0; 32];
    signers_commitment.copy_from_slice(&data[64..96]);

    let mut signing_package_hash = [0; 32];
    signing_package_hash.copy_from_slice(&data[96..128]);

    let mut expiry_slot = [0; 8];
    expiry_slot.copy_from_slice(&data[128..136]);

    Ok(InitSpendOrchestrationArgs {
        action_hash,
        session_commitment,
        signers_commitment,
        signing_package_hash,
        expiry_slot: u64::from_le_bytes(expiry_slot),
        threshold: data[136],
        participant_count: data[137],
        bump: data[138],
    })
}

fn parse_commit_spend_orchestration(
    data: &[u8],
) -> Result<CommitSpendOrchestrationArgs, ProgramError> {
    // 32 + 32 = 64
    if data.len() != 64 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(&data[..32]);

    let mut signing_package_hash = [0; 32];
    signing_package_hash.copy_from_slice(&data[32..64]);

    Ok(CommitSpendOrchestrationArgs {
        action_hash,
        signing_package_hash,
    })
}

fn parse_complete_spend_orchestration(
    data: &[u8],
) -> Result<CompleteSpendOrchestrationArgs, ProgramError> {
    // 32
    if data.len() != 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(data);

    Ok(CompleteSpendOrchestrationArgs { action_hash })
}

fn parse_fail_spend_orchestration(
    data: &[u8],
) -> Result<FailSpendOrchestrationArgs, ProgramError> {
    // 32 + 1 = 33
    if data.len() != 33 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut action_hash = [0; 32];
    action_hash.copy_from_slice(&data[..32]);

    Ok(FailSpendOrchestrationArgs {
        action_hash,
        reason_code: data[32],
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CloseQuantumVaultArgs, CommitSpendOrchestrationArgs, CompleteSpendOrchestrationArgs,
        CoreInstruction, FailSpendOrchestrationArgs, InitAuthorityArgs, InitAuthorityProofArgs,
        InitQuantumVaultArgs, InitSpendOrchestrationArgs, InitVaultArgs, RotateAuthorityArgs,
        SplitQuantumVaultArgs, WriteAuthorityProofChunkArgs, WINTERNITZ_SIGNATURE_BYTES,
    };
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{
        AuthorityRotationStatement, PolicyReceipt, ThresholdRequirement, WotsAuthProof,
        AUTHORITY_PROOF_CHUNK_MAX_BYTES, WOTS_KEY_BYTES, XMSS_AUTH_PATH_BYTES,
    };

    #[test]
    fn parses_ping_instruction() {
        assert_eq!(
            CoreInstruction::try_from(&[0][..]),
            Ok(CoreInstruction::Ping)
        );
    }

    #[test]
    fn rejects_unknown_instruction() {
        assert_eq!(
            CoreInstruction::try_from(&[1][..]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn parses_init_vault_instruction() {
        let mut data = vec![1];
        data.extend_from_slice(&[7; 32]);
        data.extend_from_slice(&[9; 32]);
        data.extend_from_slice(&42u64.to_le_bytes());
        data.push(3);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::InitVault(InitVaultArgs {
                wallet_pubkey: [7; 32],
                authority_hash: [9; 32],
                policy_version: 42,
                bump: 3,
            }))
        );
    }

    #[test]
    fn parses_stage_receipt_instruction() {
        let mut data = vec![4];
        data.extend_from_slice(&[4; 32]);
        data.extend_from_slice(&10u64.to_le_bytes());
        data.push(2);
        data.extend_from_slice(&11u64.to_le_bytes());
        data.extend_from_slice(&12u64.to_le_bytes());

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::StageReceipt(PolicyReceipt {
                action_hash: [4; 32],
                policy_version: 10,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 11,
                expiry_slot: 12,
            }))
        );
    }

    #[test]
    fn parses_init_authority_instruction() {
        let mut data = vec![2];
        data.extend_from_slice(&[3; 32]);
        data.extend_from_slice(&[4; 32]);
        data.push(5);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::InitAuthority(InitAuthorityArgs {
                current_authority_hash: [3; 32],
                current_authority_root: [4; 32],
                bump: 5,
            }))
        );
    }

    #[test]
    fn parses_open_session_instruction() {
        let mut data = vec![6];
        data.extend_from_slice(&[4; 32]);
        data.extend_from_slice(&10u64.to_le_bytes());
        data.push(2);
        data.extend_from_slice(&11u64.to_le_bytes());
        data.extend_from_slice(&12u64.to_le_bytes());

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::OpenSession(PolicyReceipt {
                action_hash: [4; 32],
                policy_version: 10,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 11,
                expiry_slot: 12,
            }))
        );
    }

    #[test]
    fn parses_activate_session_instruction() {
        let mut data = vec![7];
        data.extend_from_slice(&[7; 32]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::ActivateSession([7; 32]))
        );
    }

    #[test]
    fn parses_consume_session_instruction() {
        let mut data = vec![8];
        data.extend_from_slice(&[8; 32]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::ConsumeSession([8; 32]))
        );
    }

    #[test]
    fn parses_finalize_session_instruction() {
        let mut data = vec![9];
        data.extend_from_slice(&[4; 32]);
        data.extend_from_slice(&10u64.to_le_bytes());
        data.push(2);
        data.extend_from_slice(&11u64.to_le_bytes());
        data.extend_from_slice(&12u64.to_le_bytes());

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::FinalizeSession(PolicyReceipt {
                action_hash: [4; 32],
                policy_version: 10,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 11,
                expiry_slot: 12,
            }))
        );
    }

    #[test]
    fn parses_rotate_authority_instruction() {
        let mut data = vec![11];
        data.extend_from_slice(&[5; 32]);
        data.extend_from_slice(&[6; 32]);
        data.extend_from_slice(&13u64.to_le_bytes());
        data.extend_from_slice(&14u64.to_le_bytes());
        data.extend_from_slice(&[7; WOTS_KEY_BYTES]);
        data.extend_from_slice(&[8; WOTS_KEY_BYTES]);
        data.extend_from_slice(&9u32.to_le_bytes());
        data.extend_from_slice(&[10; XMSS_AUTH_PATH_BYTES]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::RotateAuthority(RotateAuthorityArgs {
                statement: AuthorityRotationStatement {
                    action_hash: [5; 32],
                    next_authority_hash: [6; 32],
                    sequence: 13,
                    expiry_slot: 14,
                },
                proof: WotsAuthProof {
                    public_key: [7; WOTS_KEY_BYTES],
                    signature: [8; WOTS_KEY_BYTES],
                    leaf_index: 9,
                    auth_path: [10; XMSS_AUTH_PATH_BYTES],
                },
            }))
        );
    }

    #[test]
    fn parses_set_vault_status_instruction() {
        let data = vec![10, 2];

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::SetVaultStatus(2))
        );
    }

    #[test]
    fn parses_init_authority_proof_instruction() {
        let mut data = vec![12];
        data.extend_from_slice(&[5; 32]);
        data.extend_from_slice(&[6; 32]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::InitAuthorityProof(
                InitAuthorityProofArgs {
                    statement_digest: [5; 32],
                    proof_commitment: [6; 32],
                }
            ))
        );
    }

    #[test]
    fn parses_write_authority_proof_chunk_instruction() {
        let mut data = vec![13];
        data.extend_from_slice(&9u32.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&[7, 8, 9]);

        let mut chunk = [0; AUTHORITY_PROOF_CHUNK_MAX_BYTES];
        chunk[..3].copy_from_slice(&[7, 8, 9]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::WriteAuthorityProofChunk(
                WriteAuthorityProofChunkArgs {
                    offset: 9,
                    chunk_len: 3,
                    chunk,
                }
            ))
        );
    }

    #[test]
    fn parses_rotate_authority_staged_instruction() {
        let mut data = vec![14];
        data.extend_from_slice(&[5; 32]);
        data.extend_from_slice(&[6; 32]);
        data.extend_from_slice(&13u64.to_le_bytes());
        data.extend_from_slice(&14u64.to_le_bytes());

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::RotateAuthorityStaged(
                AuthorityRotationStatement {
                    action_hash: [5; 32],
                    next_authority_hash: [6; 32],
                    sequence: 13,
                    expiry_slot: 14,
                }
            ))
        );
    }

    #[test]
    fn rejects_unknown_threshold_encoding() {
        let mut data = vec![4];
        data.extend_from_slice(&[4; 32]);
        data.extend_from_slice(&10u64.to_le_bytes());
        data.push(99);
        data.extend_from_slice(&11u64.to_le_bytes());
        data.extend_from_slice(&12u64.to_le_bytes());

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn rejects_oversized_authority_chunk() {
        let mut data = vec![13];
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&257u16.to_le_bytes());
        data.resize(1 + 4 + 2 + 257, 1);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn parses_init_quantum_vault_instruction() {
        let mut data = vec![3];
        data.extend_from_slice(&[7; 32]);
        data.push(4);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::InitQuantumVault(InitQuantumVaultArgs {
                hash: [7; 32],
                bump: 4,
            }))
        );
    }

    #[test]
    fn parses_split_quantum_vault_instruction() {
        let signature = [1; WINTERNITZ_SIGNATURE_BYTES];

        let mut data = vec![15];
        data.extend_from_slice(&signature);
        data.extend_from_slice(&42u64.to_le_bytes());
        data.push(5);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::SplitQuantumVault(SplitQuantumVaultArgs {
                signature,
                amount: 42,
                bump: 5,
            }))
        );
    }

    #[test]
    fn parses_close_quantum_vault_instruction() {
        let signature = [1; WINTERNITZ_SIGNATURE_BYTES];

        let mut data = vec![16];
        data.extend_from_slice(&signature);
        data.push(6);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::CloseQuantumVault(CloseQuantumVaultArgs {
                signature,
                bump: 6,
            }))
        );
    }

    #[test]
    fn parses_init_spend_orchestration_instruction() {
        let mut data = vec![17];
        data.extend_from_slice(&[1; 32]); // action_hash
        data.extend_from_slice(&[2; 32]); // session_commitment
        data.extend_from_slice(&[3; 32]); // signers_commitment
        data.extend_from_slice(&[4; 32]); // signing_package_hash
        data.extend_from_slice(&500u64.to_le_bytes());
        data.push(2); // threshold
        data.push(3); // participant_count
        data.push(7); // bump

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::InitSpendOrchestration(
                InitSpendOrchestrationArgs {
                    action_hash: [1; 32],
                    session_commitment: [2; 32],
                    signers_commitment: [3; 32],
                    signing_package_hash: [4; 32],
                    expiry_slot: 500,
                    threshold: 2,
                    participant_count: 3,
                    bump: 7,
                }
            ))
        );
    }

    #[test]
    fn parses_commit_spend_orchestration_instruction() {
        let mut data = vec![18];
        data.extend_from_slice(&[5; 32]); // action_hash
        data.extend_from_slice(&[6; 32]); // signing_package_hash

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::CommitSpendOrchestration(
                CommitSpendOrchestrationArgs {
                    action_hash: [5; 32],
                    signing_package_hash: [6; 32],
                }
            ))
        );
    }

    #[test]
    fn parses_complete_spend_orchestration_instruction() {
        let mut data = vec![19];
        data.extend_from_slice(&[7; 32]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::CompleteSpendOrchestration(
                CompleteSpendOrchestrationArgs { action_hash: [7; 32] }
            ))
        );
    }

    #[test]
    fn parses_fail_spend_orchestration_instruction() {
        let mut data = vec![20];
        data.extend_from_slice(&[8; 32]);
        data.push(42); // reason_code

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::FailSpendOrchestration(
                FailSpendOrchestrationArgs {
                    action_hash: [8; 32],
                    reason_code: 42,
                }
            ))
        );
    }

    #[test]
    fn parses_stage_bridged_receipt_instruction() {
        let mut data = vec![21];
        data.extend_from_slice(&[11; 32]); // action_hash
        data.extend_from_slice(&7u64.to_le_bytes()); // policy_version
        data.push(2); // threshold = TwoOfThree
        data.extend_from_slice(&8u64.to_le_bytes()); // nonce
        data.extend_from_slice(&900u64.to_le_bytes()); // expiry_slot

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::StageBridgedReceipt(PolicyReceipt {
                action_hash: [11; 32],
                policy_version: 7,
                threshold: ThresholdRequirement::TwoOfThree,
                nonce: 8,
                expiry_slot: 900,
            }))
        );
    }
}
