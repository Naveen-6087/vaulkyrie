use pinocchio::program_error::ProgramError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreInstruction {
    Ping,
}

impl TryFrom<&[u8]> for CoreInstruction {
    type Error = ProgramError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        match data {
            [0] => Ok(Self::Ping),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CoreInstruction;
    use pinocchio::program_error::ProgramError;

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
}
