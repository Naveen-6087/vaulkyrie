use sha2::{Digest, Sha256};

use crate::{PolicyDecisionEnvelope, PolicyEvaluationRequest, PolicyReceipt, ThresholdRequirement};

macro_rules! tiny_enum {
    ($name:ident { $($variant:ident = $value:expr),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum $name {
            $($variant = $value),+
        }

        impl $name {
            pub const fn as_byte(self) -> u8 {
                self as u8
            }
        }

        impl TryFrom<u8> for $name {
            type Error = ();

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(()),
                }
            }
        }
    };
}

tiny_enum!(PolicyTemplate {
    StandardWallet = 1,
    HighSecurityWallet = 2,
    TreasuryOps = 3,
    RecoveryEscalation = 4,
    AdminQuarantine = 5,
});

tiny_enum!(PolicyScope {
    Spend = 1,
    Admin = 2,
    Recovery = 3,
});

tiny_enum!(PolicyAmountBucket {
    Dust = 0,
    Small = 1,
    Medium = 2,
    Large = 3,
    Whale = 4,
});

tiny_enum!(PolicyBalanceBucket {
    Low = 0,
    Medium = 1,
    High = 2,
    Treasury = 3,
});

tiny_enum!(PolicyLimitHeadroomBucket {
    Wide = 0,
    Comfortable = 1,
    Tight = 2,
    NearLimit = 3,
    Exhausted = 4,
});

tiny_enum!(PolicyVelocityBucket {
    Idle = 0,
    Warm = 1,
    Elevated = 2,
    Burst = 3,
});

tiny_enum!(PolicyRecipientClass {
    SelfOwned = 0,
    Allowlisted = 1,
    Known = 2,
    New = 3,
    Sensitive = 4,
});

tiny_enum!(PolicyProtocolRiskBucket {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
});

tiny_enum!(PolicyDeviceTrustBucket {
    Attested = 0,
    Trusted = 1,
    Degraded = 2,
    Unknown = 3,
    Compromised = 4,
});

tiny_enum!(PolicyHistoryBucket {
    Clean = 0,
    Warned = 1,
    Challenged = 2,
    RecoveryLinked = 3,
});

tiny_enum!(PolicyGuardianPosture {
    None = 0,
    Optional = 1,
    Available = 2,
    VerifiedQuorum = 3,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyBoilerplate {
    pub template: PolicyTemplate,
    pub base_threshold: ThresholdRequirement,
    pub elevated_threshold: ThresholdRequirement,
    pub critical_threshold: ThresholdRequirement,
    pub low_delay_slots: u64,
    pub medium_delay_slots: u64,
    pub high_delay_slots: u64,
    pub severity_bias: u8,
    pub deny_on_compromised_spend: bool,
    pub require_pqc_for_admin: bool,
}

impl PolicyTemplate {
    pub const fn boilerplate(self) -> PolicyBoilerplate {
        match self {
            Self::StandardWallet => PolicyBoilerplate {
                template: self,
                base_threshold: ThresholdRequirement::OneOfThree,
                elevated_threshold: ThresholdRequirement::TwoOfThree,
                critical_threshold: ThresholdRequirement::ThreeOfThree,
                low_delay_slots: 0,
                medium_delay_slots: 30,
                high_delay_slots: 120,
                severity_bias: 0,
                deny_on_compromised_spend: true,
                require_pqc_for_admin: false,
            },
            Self::HighSecurityWallet => PolicyBoilerplate {
                template: self,
                base_threshold: ThresholdRequirement::TwoOfThree,
                elevated_threshold: ThresholdRequirement::ThreeOfThree,
                critical_threshold: ThresholdRequirement::RequirePqcAuth,
                low_delay_slots: 15,
                medium_delay_slots: 90,
                high_delay_slots: 240,
                severity_bias: 2,
                deny_on_compromised_spend: true,
                require_pqc_for_admin: true,
            },
            Self::TreasuryOps => PolicyBoilerplate {
                template: self,
                base_threshold: ThresholdRequirement::TwoOfThree,
                elevated_threshold: ThresholdRequirement::ThreeOfThree,
                critical_threshold: ThresholdRequirement::RequirePqcAuth,
                low_delay_slots: 30,
                medium_delay_slots: 120,
                high_delay_slots: 480,
                severity_bias: 3,
                deny_on_compromised_spend: true,
                require_pqc_for_admin: true,
            },
            Self::RecoveryEscalation => PolicyBoilerplate {
                template: self,
                base_threshold: ThresholdRequirement::TwoOfThree,
                elevated_threshold: ThresholdRequirement::ThreeOfThree,
                critical_threshold: ThresholdRequirement::RequirePqcAuth,
                low_delay_slots: 60,
                medium_delay_slots: 240,
                high_delay_slots: 960,
                severity_bias: 4,
                deny_on_compromised_spend: false,
                require_pqc_for_admin: true,
            },
            Self::AdminQuarantine => PolicyBoilerplate {
                template: self,
                base_threshold: ThresholdRequirement::TwoOfThree,
                elevated_threshold: ThresholdRequirement::RequirePqcAuth,
                critical_threshold: ThresholdRequirement::RequirePqcAuth,
                low_delay_slots: 120,
                medium_delay_slots: 600,
                high_delay_slots: 1_800,
                severity_bias: 5,
                deny_on_compromised_spend: true,
                require_pqc_for_admin: true,
            },
        }
    }
}

pub const POLICY_FLAG_NEW_DEVICE: u16 = 1 << 0;
pub const POLICY_FLAG_OFF_HOURS: u16 = 1 << 1;
pub const POLICY_FLAG_GEO_VELOCITY: u16 = 1 << 2;
pub const POLICY_FLAG_ALLOWLIST_MATCH: u16 = 1 << 3;
pub const POLICY_FLAG_PENDING_RECOVERY: u16 = 1 << 4;
pub const POLICY_FLAG_AUDITOR_VISIBLE: u16 = 1 << 5;
pub const POLICY_FLAG_TIMELOCK_BYPASS_REQUESTED: u16 = 1 << 6;
pub const POLICY_FLAG_SERVER_COSIGNER_ATTESTED: u16 = 1 << 7;
pub const POLICY_FLAG_GUARDIAN_ATTESTED: u16 = 1 << 8;
pub const POLICY_FLAG_FORCE_PQC_REVIEW: u16 = 1 << 9;

pub const DECISION_FLAG_LIMIT_ESCALATED: u16 = 1 << 0;
pub const DECISION_FLAG_RECIPIENT_ESCALATED: u16 = 1 << 1;
pub const DECISION_FLAG_PROTOCOL_ESCALATED: u16 = 1 << 2;
pub const DECISION_FLAG_DEVICE_ESCALATED: u16 = 1 << 3;
pub const DECISION_FLAG_HISTORY_ESCALATED: u16 = 1 << 4;
pub const DECISION_FLAG_GUARDIAN_ESCALATED: u16 = 1 << 5;
pub const DECISION_FLAG_DELAY_APPLIED: u16 = 1 << 6;
pub const DECISION_FLAG_PQC_REQUIRED: u16 = 1 << 7;
pub const DECISION_FLAG_DENIED: u16 = 1 << 8;
pub const DECISION_FLAG_ADMIN_SCOPE: u16 = 1 << 9;
pub const DECISION_FLAG_RECOVERY_SCOPE: u16 = 1 << 10;

tiny_enum!(PolicyReasonCode {
    Approved = 0,
    LimitPressure = 10,
    RecipientEscalation = 11,
    ProtocolRisk = 12,
    DeviceTrust = 13,
    HistoryEscalation = 14,
    GuardianEscalation = 15,
    RecoveryEscalation = 30,
    AdminPqcRequired = 40,
    DeniedCriticalCompoundRisk = 90,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySignals {
    pub template: PolicyTemplate,
    pub scope: PolicyScope,
    pub amount_bucket: PolicyAmountBucket,
    pub balance_bucket: PolicyBalanceBucket,
    pub limit_headroom_bucket: PolicyLimitHeadroomBucket,
    pub velocity_bucket: PolicyVelocityBucket,
    pub recipient_class: PolicyRecipientClass,
    pub protocol_risk: PolicyProtocolRiskBucket,
    pub device_trust: PolicyDeviceTrustBucket,
    pub history_bucket: PolicyHistoryBucket,
    pub guardian_posture: PolicyGuardianPosture,
    pub flags: u16,
}

impl PolicySignals {
    pub const PACKED_LANES: usize = 2;

    pub const fn pack_lanes(self) -> [u128; Self::PACKED_LANES] {
        let lane_0 = (self.template.as_byte() as u128)
            | ((self.scope.as_byte() as u128) << 8)
            | ((self.amount_bucket.as_byte() as u128) << 16)
            | ((self.balance_bucket.as_byte() as u128) << 24)
            | ((self.limit_headroom_bucket.as_byte() as u128) << 32)
            | ((self.velocity_bucket.as_byte() as u128) << 40)
            | ((self.recipient_class.as_byte() as u128) << 48)
            | ((self.protocol_risk.as_byte() as u128) << 56)
            | ((self.device_trust.as_byte() as u128) << 64)
            | ((self.history_bucket.as_byte() as u128) << 72)
            | ((self.guardian_posture.as_byte() as u128) << 80);
        let lane_1 = self.flags as u128;
        [lane_0, lane_1]
    }

    pub fn unpack_lanes(lanes: [u128; Self::PACKED_LANES]) -> Option<Self> {
        let lane_0 = lanes[0];
        let lane_1 = lanes[1];

        Some(Self {
            template: PolicyTemplate::try_from((lane_0 & 0xff) as u8).ok()?,
            scope: PolicyScope::try_from(((lane_0 >> 8) & 0xff) as u8).ok()?,
            amount_bucket: PolicyAmountBucket::try_from(((lane_0 >> 16) & 0xff) as u8).ok()?,
            balance_bucket: PolicyBalanceBucket::try_from(((lane_0 >> 24) & 0xff) as u8).ok()?,
            limit_headroom_bucket: PolicyLimitHeadroomBucket::try_from(
                ((lane_0 >> 32) & 0xff) as u8,
            )
            .ok()?,
            velocity_bucket: PolicyVelocityBucket::try_from(((lane_0 >> 40) & 0xff) as u8).ok()?,
            recipient_class: PolicyRecipientClass::try_from(((lane_0 >> 48) & 0xff) as u8).ok()?,
            protocol_risk: PolicyProtocolRiskBucket::try_from(((lane_0 >> 56) & 0xff) as u8)
                .ok()?,
            device_trust: PolicyDeviceTrustBucket::try_from(((lane_0 >> 64) & 0xff) as u8).ok()?,
            history_bucket: PolicyHistoryBucket::try_from(((lane_0 >> 72) & 0xff) as u8).ok()?,
            guardian_posture: PolicyGuardianPosture::try_from(((lane_0 >> 80) & 0xff) as u8)
                .ok()?,
            flags: lane_1 as u16,
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let lanes = self.pack_lanes();
        let mut hasher = Sha256::new();
        hasher.update(b"VAULKYRIE_POLICY_SIGNALS_V1");
        hasher.update(lanes[0].to_le_bytes());
        hasher.update(lanes[1].to_le_bytes());
        hasher.finalize().into()
    }

    fn severity_score(&self) -> u16 {
        self.amount_bucket.weight()
            + self.balance_bucket.weight()
            + self.limit_headroom_bucket.weight()
            + self.velocity_bucket.weight()
            + self.recipient_class.weight()
            + self.protocol_risk.weight()
            + self.device_trust.weight()
            + self.history_bucket.weight()
            + self.guardian_posture.weight()
    }
}

impl PolicyAmountBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::Dust => 0,
            Self::Small => 1,
            Self::Medium => 2,
            Self::Large => 4,
            Self::Whale => 6,
        }
    }
}

impl PolicyBalanceBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Treasury => 3,
        }
    }
}

impl PolicyLimitHeadroomBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::Wide => 0,
            Self::Comfortable => 1,
            Self::Tight => 3,
            Self::NearLimit => 5,
            Self::Exhausted => 7,
        }
    }
}

impl PolicyVelocityBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::Idle => 0,
            Self::Warm => 1,
            Self::Elevated => 3,
            Self::Burst => 5,
        }
    }
}

impl PolicyRecipientClass {
    const fn weight(self) -> u16 {
        match self {
            Self::SelfOwned => 0,
            Self::Allowlisted => 0,
            Self::Known => 1,
            Self::New => 3,
            Self::Sensitive => 5,
        }
    }
}

impl PolicyProtocolRiskBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 4,
            Self::Critical => 7,
        }
    }
}

impl PolicyDeviceTrustBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::Attested => 0,
            Self::Trusted => 1,
            Self::Degraded => 4,
            Self::Unknown => 6,
            Self::Compromised => 10,
        }
    }
}

impl PolicyHistoryBucket {
    const fn weight(self) -> u16 {
        match self {
            Self::Clean => 0,
            Self::Warned => 2,
            Self::Challenged => 4,
            Self::RecoveryLinked => 6,
        }
    }
}

impl PolicyGuardianPosture {
    const fn weight(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Optional => 1,
            Self::Available => 2,
            Self::VerifiedQuorum => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecision {
    pub approved: bool,
    pub threshold: ThresholdRequirement,
    pub delay_until_slot: u64,
    pub reason_code: u16,
    pub decision_flags: u16,
    /// Privacy-preserving risk score revealed by the policy engine.
    ///
    /// The raw private signal buckets stay encrypted.  The circuit reveals only
    /// this bounded summary so wallets and auditors can explain the decision.
    pub risk_score: u16,
    pub risk_tier: u8,
}

impl PolicyDecision {
    pub fn result_commitment(
        &self,
        request: &PolicyEvaluationRequest,
        signal_commitment: [u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VAULKYRIE_POLICY_RESULT_V1");
        hasher.update(request.commitment());
        hasher.update(signal_commitment);
        hasher.update([self.threshold.as_byte()]);
        hasher.update(self.delay_until_slot.to_le_bytes());
        hasher.update(self.reason_code.to_le_bytes());
        hasher.update(self.decision_flags.to_le_bytes());
        hasher.update(self.risk_score.to_le_bytes());
        hasher.update([self.risk_tier]);
        hasher.update([self.approved as u8]);
        hasher.finalize().into()
    }

    pub fn into_envelope(
        self,
        request: &PolicyEvaluationRequest,
        computation_offset: u64,
        signal_commitment: [u8; 32],
    ) -> PolicyDecisionEnvelope {
        PolicyDecisionEnvelope {
            request_commitment: request.commitment(),
            receipt: PolicyReceipt {
                action_hash: request.action_hash,
                policy_version: request.policy_version,
                threshold: self.threshold,
                nonce: request.request_nonce,
                expiry_slot: request.expiry_slot,
            },
            delay_until_slot: self.delay_until_slot,
            reason_code: self.reason_code,
            computation_offset,
            result_commitment: self.result_commitment(request, signal_commitment),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationArtifacts {
    pub signal_commitment: [u8; 32],
    pub decision: PolicyDecision,
    pub envelope: PolicyDecisionEnvelope,
}

pub const RISK_TIER_LOW: u8 = 0;
pub const RISK_TIER_MEDIUM: u8 = 1;
pub const RISK_TIER_HIGH: u8 = 2;
pub const RISK_TIER_CRITICAL: u8 = 3;

pub fn risk_tier_from_score(score: u16) -> u8 {
    match score {
        0..=24 => RISK_TIER_LOW,
        25..=49 => RISK_TIER_MEDIUM,
        50..=84 => RISK_TIER_HIGH,
        _ => RISK_TIER_CRITICAL,
    }
}

fn risk_score_from_severity(severity: u16, denied: bool) -> u16 {
    if denied {
        100
    } else {
        severity.saturating_mul(3).min(100)
    }
}

pub fn build_policy_request(
    vault_id: [u8; 32],
    action_hash: [u8; 32],
    policy_version: u64,
    request_nonce: u64,
    expiry_slot: u64,
    signals: &PolicySignals,
) -> PolicyEvaluationRequest {
    PolicyEvaluationRequest {
        vault_id,
        action_hash,
        policy_version,
        request_nonce,
        expiry_slot,
        encrypted_input_commitment: signals.commitment(),
    }
}

pub fn evaluate_policy(
    request: &PolicyEvaluationRequest,
    signals: &PolicySignals,
    current_slot: u64,
    computation_offset: u64,
) -> PolicyEvaluationArtifacts {
    let boilerplate = signals.template.boilerplate();
    let signal_commitment = signals.commitment();
    let mut severity = signals.severity_score() + boilerplate.severity_bias as u16;
    let mut decision_flags = 0u16;
    let mut reason = PolicyReasonCode::Approved;
    let mut approved = true;

    if signals.scope == PolicyScope::Admin {
        severity += 3;
        decision_flags |= DECISION_FLAG_ADMIN_SCOPE;
    } else if signals.scope == PolicyScope::Recovery {
        severity += 5;
        decision_flags |= DECISION_FLAG_RECOVERY_SCOPE;
        reason = PolicyReasonCode::RecoveryEscalation;
    }

    if signals.limit_headroom_bucket.weight() >= 3 {
        decision_flags |= DECISION_FLAG_LIMIT_ESCALATED;
        reason = PolicyReasonCode::LimitPressure;
    }
    if signals.recipient_class.weight() >= 3 {
        decision_flags |= DECISION_FLAG_RECIPIENT_ESCALATED;
        reason = PolicyReasonCode::RecipientEscalation;
    }
    if signals.protocol_risk.weight() >= 4 {
        decision_flags |= DECISION_FLAG_PROTOCOL_ESCALATED;
        reason = PolicyReasonCode::ProtocolRisk;
    }
    if signals.device_trust.weight() >= 4 {
        decision_flags |= DECISION_FLAG_DEVICE_ESCALATED;
        reason = PolicyReasonCode::DeviceTrust;
    }
    if signals.history_bucket.weight() >= 4 {
        decision_flags |= DECISION_FLAG_HISTORY_ESCALATED;
        reason = PolicyReasonCode::HistoryEscalation;
    }
    if signals.guardian_posture.weight() >= 2 {
        decision_flags |= DECISION_FLAG_GUARDIAN_ESCALATED;
        reason = PolicyReasonCode::GuardianEscalation;
    }

    if signals.flags & POLICY_FLAG_PENDING_RECOVERY != 0 {
        severity += 4;
        decision_flags |= DECISION_FLAG_RECOVERY_SCOPE;
        reason = PolicyReasonCode::RecoveryEscalation;
    }
    if signals.flags & POLICY_FLAG_TIMELOCK_BYPASS_REQUESTED != 0 {
        severity += 3;
    }
    if signals.flags & POLICY_FLAG_GEO_VELOCITY != 0 {
        severity += 2;
    }

    let critical_compound_risk = signals.scope == PolicyScope::Spend
        && signals.protocol_risk == PolicyProtocolRiskBucket::Critical
        && signals.recipient_class == PolicyRecipientClass::Sensitive
        && (signals.flags & POLICY_FLAG_OFF_HOURS != 0
            || signals.flags & POLICY_FLAG_TIMELOCK_BYPASS_REQUESTED != 0
            || signals.device_trust == PolicyDeviceTrustBucket::Compromised);

    if critical_compound_risk
        || (signals.scope == PolicyScope::Spend
            && signals.device_trust == PolicyDeviceTrustBucket::Compromised
            && boilerplate.deny_on_compromised_spend)
    {
        approved = false;
        decision_flags |= DECISION_FLAG_DENIED
            | DECISION_FLAG_PROTOCOL_ESCALATED
            | DECISION_FLAG_RECIPIENT_ESCALATED
            | DECISION_FLAG_DEVICE_ESCALATED;
        reason = PolicyReasonCode::DeniedCriticalCompoundRisk;
    }

    let require_pqc = signals.flags & POLICY_FLAG_FORCE_PQC_REVIEW != 0
        || (signals.scope != PolicyScope::Spend && boilerplate.require_pqc_for_admin)
        || (signals.scope == PolicyScope::Recovery
            && signals.guardian_posture != PolicyGuardianPosture::VerifiedQuorum);

    let threshold = if !approved {
        if signals.scope == PolicyScope::Spend {
            boilerplate.critical_threshold
        } else {
            ThresholdRequirement::RequirePqcAuth
        }
    } else if require_pqc {
        decision_flags |= DECISION_FLAG_PQC_REQUIRED;
        reason = PolicyReasonCode::AdminPqcRequired;
        ThresholdRequirement::RequirePqcAuth
    } else if severity >= 18 {
        if boilerplate.critical_threshold == ThresholdRequirement::RequirePqcAuth {
            decision_flags |= DECISION_FLAG_PQC_REQUIRED;
            reason = PolicyReasonCode::AdminPqcRequired;
        }
        boilerplate.critical_threshold
    } else if severity >= 10 {
        boilerplate.elevated_threshold
    } else {
        boilerplate.base_threshold
    };

    let delay_slots = if !approved {
        boilerplate.high_delay_slots
    } else if threshold == ThresholdRequirement::RequirePqcAuth || severity >= 18 {
        boilerplate.high_delay_slots
    } else if severity >= 10 {
        boilerplate.medium_delay_slots
    } else {
        boilerplate.low_delay_slots
    };
    let mut delay_until_slot = current_slot.saturating_add(delay_slots);
    if delay_until_slot > request.expiry_slot {
        delay_until_slot = request.expiry_slot;
    }
    if delay_until_slot > current_slot {
        decision_flags |= DECISION_FLAG_DELAY_APPLIED;
    }
    let risk_score = risk_score_from_severity(severity, !approved);
    let risk_tier = risk_tier_from_score(risk_score);

    let decision = PolicyDecision {
        approved,
        threshold,
        delay_until_slot,
        reason_code: reason.as_byte() as u16,
        decision_flags,
        risk_score,
        risk_tier,
    };
    let envelope = decision.into_envelope(request, computation_offset, signal_commitment);

    PolicyEvaluationArtifacts {
        signal_commitment,
        decision,
        envelope,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_policy_request, evaluate_policy, PolicyAmountBucket, PolicyBalanceBucket,
        PolicyDeviceTrustBucket, PolicyGuardianPosture, PolicyHistoryBucket,
        PolicyLimitHeadroomBucket, PolicyProtocolRiskBucket, PolicyRecipientClass, PolicyScope,
        PolicySignals, PolicyTemplate, PolicyVelocityBucket, DECISION_FLAG_DENIED,
        DECISION_FLAG_PQC_REQUIRED, POLICY_FLAG_PENDING_RECOVERY,
    };
    use crate::ThresholdRequirement;

    fn sample_signals() -> PolicySignals {
        PolicySignals {
            template: PolicyTemplate::StandardWallet,
            scope: PolicyScope::Spend,
            amount_bucket: PolicyAmountBucket::Small,
            balance_bucket: PolicyBalanceBucket::Medium,
            limit_headroom_bucket: PolicyLimitHeadroomBucket::Comfortable,
            velocity_bucket: PolicyVelocityBucket::Idle,
            recipient_class: PolicyRecipientClass::Allowlisted,
            protocol_risk: PolicyProtocolRiskBucket::Low,
            device_trust: PolicyDeviceTrustBucket::Trusted,
            history_bucket: PolicyHistoryBucket::Clean,
            guardian_posture: PolicyGuardianPosture::Optional,
            flags: 0,
        }
    }

    #[test]
    fn signals_roundtrip_through_packed_lanes() {
        let signals = sample_signals();
        let packed = signals.pack_lanes();

        assert_eq!(PolicySignals::unpack_lanes(packed), Some(signals));
    }

    #[test]
    fn signal_commitment_changes_when_bucket_changes() {
        let signals = sample_signals();
        let mut changed = sample_signals();
        changed.protocol_risk = PolicyProtocolRiskBucket::High;

        assert_ne!(signals.commitment(), changed.commitment());
    }

    #[test]
    fn low_risk_standard_wallet_spend_uses_base_threshold() {
        let signals = sample_signals();
        let request = build_policy_request([1; 32], [2; 32], 7, 9, 1_000, &signals);
        let artifacts = evaluate_policy(&request, &signals, 500, 77);

        assert!(artifacts.decision.approved);
        assert_eq!(
            artifacts.decision.threshold,
            ThresholdRequirement::OneOfThree
        );
        assert_eq!(artifacts.decision.delay_until_slot, 500);
        assert!(artifacts.decision.risk_score < 25);
        assert_eq!(artifacts.decision.risk_tier, super::RISK_TIER_LOW);
    }

    #[test]
    fn risky_spend_escalates_threshold_and_delay() {
        let mut signals = sample_signals();
        signals.amount_bucket = PolicyAmountBucket::Whale;
        signals.limit_headroom_bucket = PolicyLimitHeadroomBucket::NearLimit;
        signals.velocity_bucket = PolicyVelocityBucket::Burst;
        signals.recipient_class = PolicyRecipientClass::New;
        signals.protocol_risk = PolicyProtocolRiskBucket::High;

        let request = build_policy_request([1; 32], [3; 32], 7, 9, 1_500, &signals);
        let artifacts = evaluate_policy(&request, &signals, 500, 77);

        assert!(artifacts.decision.approved);
        assert_eq!(
            artifacts.decision.threshold,
            ThresholdRequirement::ThreeOfThree
        );
        assert!(artifacts.decision.delay_until_slot > 500);
        assert!(artifacts.decision.risk_score >= 50);
        assert_eq!(artifacts.decision.risk_tier, super::RISK_TIER_HIGH);
    }

    #[test]
    fn compromised_standard_spend_is_denied() {
        let mut signals = sample_signals();
        signals.recipient_class = PolicyRecipientClass::Sensitive;
        signals.protocol_risk = PolicyProtocolRiskBucket::Critical;
        signals.device_trust = PolicyDeviceTrustBucket::Compromised;

        let request = build_policy_request([1; 32], [4; 32], 7, 9, 2_000, &signals);
        let artifacts = evaluate_policy(&request, &signals, 500, 77);

        assert!(!artifacts.decision.approved);
        assert_ne!(artifacts.decision.decision_flags & DECISION_FLAG_DENIED, 0);
        assert_eq!(artifacts.decision.risk_score, 100);
        assert_eq!(artifacts.decision.risk_tier, super::RISK_TIER_CRITICAL);
    }

    #[test]
    fn recovery_template_requires_pqc_when_guardians_not_ready() {
        let signals = PolicySignals {
            template: PolicyTemplate::RecoveryEscalation,
            scope: PolicyScope::Recovery,
            amount_bucket: PolicyAmountBucket::Medium,
            balance_bucket: PolicyBalanceBucket::High,
            limit_headroom_bucket: PolicyLimitHeadroomBucket::Tight,
            velocity_bucket: PolicyVelocityBucket::Warm,
            recipient_class: PolicyRecipientClass::Known,
            protocol_risk: PolicyProtocolRiskBucket::Medium,
            device_trust: PolicyDeviceTrustBucket::Degraded,
            history_bucket: PolicyHistoryBucket::RecoveryLinked,
            guardian_posture: PolicyGuardianPosture::Available,
            flags: POLICY_FLAG_PENDING_RECOVERY,
        };

        let request = build_policy_request([9; 32], [8; 32], 3, 4, 5_000, &signals);
        let artifacts = evaluate_policy(&request, &signals, 800, 12);

        assert!(artifacts.decision.approved);
        assert_eq!(
            artifacts.decision.threshold,
            ThresholdRequirement::RequirePqcAuth
        );
        assert_ne!(
            artifacts.decision.decision_flags & DECISION_FLAG_PQC_REQUIRED,
            0
        );
    }
}
