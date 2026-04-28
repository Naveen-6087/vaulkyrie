//! Wallet-facing policy helpers.
//!
//! These helpers keep the richer policy-engine surface in the SDK so browser or
//! mobile clients can construct the same request, signal commitment, and
//! decision envelope that the Arcium MXE circuit is expected to mirror.

pub use vaulkyrie_protocol::{
    build_policy_request as protocol_build_policy_request,
    evaluate_policy as protocol_evaluate_policy, PolicyAmountBucket, PolicyBalanceBucket,
    PolicyBoilerplate, PolicyDecision, PolicyDeviceTrustBucket, PolicyEvaluationArtifacts,
    PolicyGuardianPosture, PolicyHistoryBucket, PolicyLimitHeadroomBucket,
    PolicyProtocolRiskBucket, PolicyRecipientClass, PolicyScope, PolicySignals, PolicyTemplate,
    PolicyVelocityBucket,
};

use vaulkyrie_protocol::PolicyEvaluationRequest;

pub fn build_policy_request(
    vault_id: [u8; 32],
    action_hash: [u8; 32],
    policy_version: u64,
    request_nonce: u64,
    expiry_slot: u64,
    signals: &PolicySignals,
) -> PolicyEvaluationRequest {
    protocol_build_policy_request(
        vault_id,
        action_hash,
        policy_version,
        request_nonce,
        expiry_slot,
        signals,
    )
}

pub fn evaluate_policy(
    request: &PolicyEvaluationRequest,
    signals: &PolicySignals,
    current_slot: u64,
    computation_offset: u64,
) -> PolicyEvaluationArtifacts {
    protocol_evaluate_policy(request, signals, current_slot, computation_offset)
}

pub fn policy_signal_commitment(signals: &PolicySignals) -> [u8; 32] {
    signals.commitment()
}

pub fn packed_policy_signal_lanes(signals: &PolicySignals) -> [u128; PolicySignals::PACKED_LANES] {
    signals.pack_lanes()
}

#[cfg(test)]
mod tests {
    use super::{
        build_policy_request, evaluate_policy, packed_policy_signal_lanes,
        policy_signal_commitment, PolicyAmountBucket, PolicyBalanceBucket, PolicyDeviceTrustBucket,
        PolicyGuardianPosture, PolicyHistoryBucket, PolicyLimitHeadroomBucket,
        PolicyProtocolRiskBucket, PolicyRecipientClass, PolicyScope, PolicySignals, PolicyTemplate,
        PolicyVelocityBucket,
    };

    fn sample_signals() -> PolicySignals {
        PolicySignals {
            template: PolicyTemplate::TreasuryOps,
            scope: PolicyScope::Spend,
            amount_bucket: PolicyAmountBucket::Large,
            balance_bucket: PolicyBalanceBucket::Treasury,
            limit_headroom_bucket: PolicyLimitHeadroomBucket::Tight,
            velocity_bucket: PolicyVelocityBucket::Warm,
            recipient_class: PolicyRecipientClass::Known,
            protocol_risk: PolicyProtocolRiskBucket::Medium,
            device_trust: PolicyDeviceTrustBucket::Trusted,
            history_bucket: PolicyHistoryBucket::Warned,
            guardian_posture: PolicyGuardianPosture::Available,
            flags: 0,
        }
    }

    #[test]
    fn sdk_policy_helpers_build_request_and_envelope() {
        let signals = sample_signals();
        let request = build_policy_request([1; 32], [2; 32], 8, 9, 2_000, &signals);
        let artifacts = evaluate_policy(&request, &signals, 500, 77);

        assert_eq!(
            request.encrypted_input_commitment,
            policy_signal_commitment(&signals)
        );
        assert_eq!(artifacts.envelope.request_commitment, request.commitment());
        assert_eq!(
            artifacts.signal_commitment,
            policy_signal_commitment(&signals)
        );
    }

    #[test]
    fn sdk_exposes_packed_lanes_for_wallet_encryption() {
        let signals = sample_signals();
        let lanes = packed_policy_signal_lanes(&signals);

        assert_ne!(lanes[0], 0);
    }
}
