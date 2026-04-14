use anchor_lang::prelude::*;

use crate::transition::TransitionError;

#[error_code]
pub enum PolicyMxeError {
    #[msg("Account size does not match expected layout")]
    InvalidAccountSize,

    #[msg("Account already initialized")]
    AlreadyInitialized,

    #[msg("Account not initialized (missing discriminator)")]
    NotInitialized,

    #[msg("Policy version mismatch")]
    PolicyVersionMismatch,

    #[msg("Request nonce mismatch")]
    RequestNonceMismatch,

    #[msg("Policy request has expired")]
    RequestExpired,

    #[msg("Request already finalized")]
    RequestAlreadyFinalized,

    #[msg("Request already aborted")]
    RequestAlreadyAborted,

    #[msg("Decision envelope does not match request")]
    DecisionMismatch,

    #[msg("Delay slot exceeds receipt expiry")]
    DelayExceedsExpiry,

    #[msg("Arcium computation already queued")]
    ComputationAlreadyQueued,

    #[msg("Invalid computation status for this transition")]
    InvalidComputationStatus,

    #[msg("Invalid instruction data")]
    InvalidInstructionData,

    #[msg("Account owner mismatch")]
    AccountOwnerMismatch,

    #[msg("Arcium callback output verification failed")]
    CallbackVerificationFailed,
}

impl From<TransitionError> for PolicyMxeError {
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::PolicyVersionMismatch => PolicyMxeError::PolicyVersionMismatch,
            TransitionError::RequestNonceMismatch => PolicyMxeError::RequestNonceMismatch,
            TransitionError::RequestExpired => PolicyMxeError::RequestExpired,
            TransitionError::RequestAlreadyFinalized => PolicyMxeError::RequestAlreadyFinalized,
            TransitionError::RequestAlreadyAborted => PolicyMxeError::RequestAlreadyAborted,
            TransitionError::DecisionMismatch => PolicyMxeError::DecisionMismatch,
            TransitionError::DelayExceedsExpiry => PolicyMxeError::DelayExceedsExpiry,
            TransitionError::ComputationAlreadyQueued => PolicyMxeError::ComputationAlreadyQueued,
            TransitionError::InvalidComputationStatus => PolicyMxeError::InvalidComputationStatus,
        }
    }
}
