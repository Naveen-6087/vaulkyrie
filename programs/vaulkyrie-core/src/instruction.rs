use pinocchio::program_error::ProgramError;
use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt, ThresholdRequirement};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitVaultArgs {
    pub wallet_pubkey: [u8; 32],
    pub authority_hash: [u8; 32],
    pub policy_version: u64,
    pub bump: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreInstruction {
    Ping,
    InitVault(InitVaultArgs),
    StageReceipt(PolicyReceipt),
    ConsumeReceipt(PolicyReceipt),
    OpenSession(PolicyReceipt),
    ActivateSession([u8; 32]),
    RotateAuthority(AuthorityRotationStatement),
}

impl TryFrom<&[u8]> for CoreInstruction {
    type Error = ProgramError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        match data {
            [0] => Ok(Self::Ping),
            [1, rest @ ..] => Ok(Self::InitVault(parse_init_vault(rest)?)),
            [2, rest @ ..] => Ok(Self::StageReceipt(parse_policy_receipt(rest)?)),
            [3, rest @ ..] => Ok(Self::ConsumeReceipt(parse_policy_receipt(rest)?)),
            [4, rest @ ..] => Ok(Self::OpenSession(parse_policy_receipt(rest)?)),
            [5, rest @ ..] => Ok(Self::ActivateSession(parse_action_hash(rest)?)),
            [6, rest @ ..] => Ok(Self::RotateAuthority(parse_authority_rotation(rest)?)),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
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

fn parse_authority_rotation(data: &[u8]) -> Result<AuthorityRotationStatement, ProgramError> {
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

#[cfg(test)]
mod tests {
    use super::{CoreInstruction, InitVaultArgs};
    use pinocchio::program_error::ProgramError;
    use vaulkyrie_protocol::{AuthorityRotationStatement, PolicyReceipt, ThresholdRequirement};

    #[test]
    fn parses_ping_instruction() {
        assert_eq!(CoreInstruction::try_from(&[0][..]), Ok(CoreInstruction::Ping));
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
        let mut data = vec![2];
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
    fn parses_open_session_instruction() {
        let mut data = vec![4];
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
        let mut data = vec![5];
        data.extend_from_slice(&[7; 32]);

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::ActivateSession([7; 32]))
        );
    }

    #[test]
    fn parses_rotate_authority_instruction() {
        let mut data = vec![6];
        data.extend_from_slice(&[5; 32]);
        data.extend_from_slice(&[6; 32]);
        data.extend_from_slice(&13u64.to_le_bytes());
        data.extend_from_slice(&14u64.to_le_bytes());

        assert_eq!(
            CoreInstruction::try_from(data.as_slice()),
            Ok(CoreInstruction::RotateAuthority(AuthorityRotationStatement {
                action_hash: [5; 32],
                next_authority_hash: [6; 32],
                sequence: 13,
                expiry_slot: 14,
            }))
        );
    }

    #[test]
    fn rejects_unknown_threshold_encoding() {
        let mut data = vec![2];
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
}
