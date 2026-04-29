//! Wallet-facing helpers for Vaulkyrie privacy intents.
//!
//! These helpers mirror the protocol-level privacy model that the Arcium MXE
//! circuit is expected to compute over: compact encrypted signal lanes, an
//! action-bound intent commitment, and a sealed receipt commitment.

use vaulkyrie_protocol::{
    build_privacy_request, evaluate_privacy, PrivacyComputationRequest, PrivacyDecision,
    PrivacyIntent, PrivacySignals,
};

pub fn build_request_from_privacy_intent(
    intent: &PrivacyIntent,
    signals: &PrivacySignals,
    request_nonce: u64,
    expiry_slot: u64,
) -> PrivacyComputationRequest {
    build_privacy_request(intent, signals, request_nonce, expiry_slot)
}

pub fn evaluate_privacy_preview(signals: &PrivacySignals) -> PrivacyDecision {
    evaluate_privacy(signals)
}

pub fn packed_privacy_signal_lanes(signals: PrivacySignals) -> [u128; PrivacySignals::PACKED_LANES] {
    signals.pack_lanes()
}

pub fn privacy_signal_commitment(signals: &PrivacySignals) -> [u8; 32] {
    signals.commitment()
}

pub fn privacy_intent_commitment(intent: &PrivacyIntent) -> [u8; 32] {
    intent.commitment()
}
