use pinocchio::program_error::ProgramError;
use vaulkyrie_core::instruction::CoreInstruction;

#[test]
fn parses_init_vault_instruction_without_legacy_fields() {
    let mut data = vec![1];
    data.extend_from_slice(&[7; 32]);
    data.extend_from_slice(&[8; 32]);
    data.push(9);

    let instruction = CoreInstruction::try_from(data.as_slice()).unwrap();
    match instruction {
        CoreInstruction::InitVault(args) => {
            assert_eq!(args.wallet_pubkey, [7; 32]);
            assert_eq!(args.authority_hash, [8; 32]);
            assert_eq!(args.bump, 9);
        }
        other => panic!("unexpected instruction: {other:?}"),
    }
}

#[test]
fn rejects_legacy_init_vault_payload_shape() {
    let mut data = vec![1];
    data.extend_from_slice(&[7; 32]);
    data.extend_from_slice(&[8; 32]);
    data.extend_from_slice(&42u64.to_le_bytes());
    data.push(9);
    data.extend_from_slice(&[0; 32]);

    let error = CoreInstruction::try_from(data.as_slice()).unwrap_err();
    assert_eq!(error, ProgramError::InvalidInstructionData);
}

#[test]
fn parses_recovery_instruction() {
    let mut data = vec![22];
    data.extend_from_slice(&[1; 32]);
    data.extend_from_slice(&[2; 32]);
    data.extend_from_slice(&100u64.to_le_bytes());
    data.push(2);
    data.push(3);
    data.push(4);

    let instruction = CoreInstruction::try_from(data.as_slice()).unwrap();
    match instruction {
        CoreInstruction::InitRecovery(args) => {
            assert_eq!(args.vault_pubkey, [1; 32]);
            assert_eq!(args.recovery_commitment, [2; 32]);
            assert_eq!(args.expiry_slot, 100);
            assert_eq!(args.new_threshold, 2);
            assert_eq!(args.new_participant_count, 3);
            assert_eq!(args.bump, 4);
        }
        other => panic!("unexpected instruction: {other:?}"),
    }
}
