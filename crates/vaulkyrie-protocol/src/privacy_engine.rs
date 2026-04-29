use sha2::{Digest, Sha256};

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

tiny_enum!(PrivacyAction {
    Deposit = 1,
    Transfer = 2,
    Withdraw = 3,
    SwapIntent = 4,
    SealReceipt = 5,
});

tiny_enum!(PrivacyAsset {
    Sol = 1,
    Usdc = 2,
});

tiny_enum!(PrivacyExecutionModel {
    ShieldedState = 1,
    ExternalPrivateSwap = 2,
    ConfidentialIntent = 3,
    OneTimeWallet = 4,
});

tiny_enum!(PrivacyAmountBucket {
    Dust = 0,
    Small = 1,
    Medium = 2,
    Large = 3,
    Whale = 4,
});

tiny_enum!(PrivacyPoolBucket {
    Thin = 0,
    Building = 1,
    Healthy = 2,
    Deep = 3,
});

tiny_enum!(PrivacyRouteRisk {
    Low = 0,
    Medium = 1,
    High = 2,
    Blocked = 3,
});

tiny_enum!(PrivacyDisclosureMode {
    None = 0,
    UserReceipt = 1,
    SelectiveAudit = 2,
    BusinessAudit = 3,
});

pub const PRIVACY_FLAG_STEALTH_RECIPIENT: u16 = 1 << 0;
pub const PRIVACY_FLAG_ONE_TIME_ADDRESS: u16 = 1 << 1;
pub const PRIVACY_FLAG_SELECTIVE_DISCLOSURE: u16 = 1 << 2;
pub const PRIVACY_FLAG_PROVIDER_ROUTE: u16 = 1 << 3;
pub const PRIVACY_FLAG_NATIVE_SHIELDED: u16 = 1 << 4;
pub const PRIVACY_FLAG_SWAP_INTENT: u16 = 1 << 5;
pub const PRIVACY_FLAG_WITHDRAW_LINKABLE: u16 = 1 << 6;
pub const PRIVACY_FLAG_SPONSORED_FEES: u16 = 1 << 7;

pub const PRIVACY_DECISION_READY: u16 = 1 << 0;
pub const PRIVACY_DECISION_NEEDS_SHIELDING: u16 = 1 << 1;
pub const PRIVACY_DECISION_LINKABILITY_WARNING: u16 = 1 << 2;
pub const PRIVACY_DECISION_ROUTE_PROVIDER: u16 = 1 << 3;
pub const PRIVACY_DECISION_ROUTE_NATIVE: u16 = 1 << 4;
pub const PRIVACY_DECISION_DISCLOSURE_AVAILABLE: u16 = 1 << 5;
pub const PRIVACY_DECISION_BLOCKED: u16 = 1 << 6;

pub const PRIVACY_DOMAIN_INTENT: &[u8] = b"VAULKYRIE_PRIVACY_INTENT_V1";
pub const PRIVACY_DOMAIN_SIGNALS: &[u8] = b"VAULKYRIE_PRIVACY_SIGNALS_V1";
pub const PRIVACY_DOMAIN_RECEIPT: &[u8] = b"VAULKYRIE_PRIVACY_RECEIPT_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyIntent {
    pub privacy_account: [u8; 32],
    pub action: PrivacyAction,
    pub asset: PrivacyAsset,
    pub amount_atoms: u64,
    pub counterparty_commitment: [u8; 32],
    pub execution_model: PrivacyExecutionModel,
    pub nonce: u64,
    pub expiry_slot: u64,
    pub flags: u16,
}

impl PrivacyIntent {
    pub const ENCODED_LEN: usize = 93;

    pub fn encode(&self, dst: &mut [u8]) -> bool {
        if dst.len() != Self::ENCODED_LEN {
            return false;
        }

        dst[..32].copy_from_slice(&self.privacy_account);
        dst[32] = self.action.as_byte();
        dst[33] = self.asset.as_byte();
        dst[34..42].copy_from_slice(&self.amount_atoms.to_le_bytes());
        dst[42..74].copy_from_slice(&self.counterparty_commitment);
        dst[74] = self.execution_model.as_byte();
        dst[75..83].copy_from_slice(&self.nonce.to_le_bytes());
        dst[83..91].copy_from_slice(&self.expiry_slot.to_le_bytes());
        dst[91..93].copy_from_slice(&self.flags.to_le_bytes());

        true
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != Self::ENCODED_LEN {
            return None;
        }

        let mut privacy_account = [0; 32];
        privacy_account.copy_from_slice(&src[..32]);

        let mut amount_atoms = [0; 8];
        amount_atoms.copy_from_slice(&src[34..42]);

        let mut counterparty_commitment = [0; 32];
        counterparty_commitment.copy_from_slice(&src[42..74]);

        let mut nonce = [0; 8];
        nonce.copy_from_slice(&src[75..83]);

        let mut expiry_slot = [0; 8];
        expiry_slot.copy_from_slice(&src[83..91]);

        let mut flags = [0; 2];
        flags.copy_from_slice(&src[91..93]);

        Some(Self {
            privacy_account,
            action: PrivacyAction::try_from(src[32]).ok()?,
            asset: PrivacyAsset::try_from(src[33]).ok()?,
            amount_atoms: u64::from_le_bytes(amount_atoms),
            counterparty_commitment,
            execution_model: PrivacyExecutionModel::try_from(src[74]).ok()?,
            nonce: u64::from_le_bytes(nonce),
            expiry_slot: u64::from_le_bytes(expiry_slot),
            flags: u16::from_le_bytes(flags),
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut encoded = [0u8; Self::ENCODED_LEN];
        let _ = self.encode(&mut encoded);

        let mut hasher = Sha256::new();
        hasher.update(PRIVACY_DOMAIN_INTENT);
        hasher.update(encoded);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacySignals {
    pub action: PrivacyAction,
    pub asset: PrivacyAsset,
    pub amount_bucket: PrivacyAmountBucket,
    pub pool_bucket: PrivacyPoolBucket,
    pub route_risk: PrivacyRouteRisk,
    pub disclosure_mode: PrivacyDisclosureMode,
    pub execution_model: PrivacyExecutionModel,
    pub flags: u16,
}

impl PrivacySignals {
    pub const PACKED_LANES: usize = 2;

    pub const fn pack_lanes(self) -> [u128; Self::PACKED_LANES] {
        let lane_0 = (self.action.as_byte() as u128)
            | ((self.asset.as_byte() as u128) << 8)
            | ((self.amount_bucket.as_byte() as u128) << 16)
            | ((self.pool_bucket.as_byte() as u128) << 24)
            | ((self.route_risk.as_byte() as u128) << 32)
            | ((self.disclosure_mode.as_byte() as u128) << 40)
            | ((self.execution_model.as_byte() as u128) << 48)
            | ((self.flags as u128) << 56);

        [lane_0, 0]
    }

    pub fn unpack_lanes(lanes: [u128; Self::PACKED_LANES]) -> Option<Self> {
        let lane_0 = lanes[0];
        let code = |shift: u32| -> u8 { ((lane_0 >> shift) & 0xff) as u8 };

        Some(Self {
            action: PrivacyAction::try_from(code(0)).ok()?,
            asset: PrivacyAsset::try_from(code(8)).ok()?,
            amount_bucket: PrivacyAmountBucket::try_from(code(16)).ok()?,
            pool_bucket: PrivacyPoolBucket::try_from(code(24)).ok()?,
            route_risk: PrivacyRouteRisk::try_from(code(32)).ok()?,
            disclosure_mode: PrivacyDisclosureMode::try_from(code(40)).ok()?,
            execution_model: PrivacyExecutionModel::try_from(code(48)).ok()?,
            flags: ((lane_0 >> 56) & 0xffff) as u16,
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let lanes = self.pack_lanes();
        let mut hasher = Sha256::new();
        hasher.update(PRIVACY_DOMAIN_SIGNALS);
        hasher.update(lanes[0].to_le_bytes());
        hasher.update(lanes[1].to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyComputationRequest {
    pub intent_commitment: [u8; 32],
    pub signal_commitment: [u8; 32],
    pub request_nonce: u64,
    pub expiry_slot: u64,
}

impl PrivacyComputationRequest {
    pub const ENCODED_LEN: usize = 80;

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.intent_commitment);
        hasher.update(self.signal_commitment);
        hasher.update(self.request_nonce.to_le_bytes());
        hasher.update(self.expiry_slot.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyDecision {
    pub approved: bool,
    pub execution_model: PrivacyExecutionModel,
    pub decision_flags: u16,
    pub privacy_score: u8,
    pub min_confirmations: u8,
}

impl PrivacyDecision {
    pub fn receipt_commitment(
        &self,
        request: &PrivacyComputationRequest,
        computation_offset: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PRIVACY_DOMAIN_RECEIPT);
        hasher.update(request.commitment());
        hasher.update([self.approved as u8]);
        hasher.update([self.execution_model.as_byte()]);
        hasher.update(self.decision_flags.to_le_bytes());
        hasher.update([self.privacy_score]);
        hasher.update([self.min_confirmations]);
        hasher.update(computation_offset.to_le_bytes());
        hasher.finalize().into()
    }
}

pub fn build_privacy_request(
    intent: &PrivacyIntent,
    signals: &PrivacySignals,
    request_nonce: u64,
    expiry_slot: u64,
) -> PrivacyComputationRequest {
    PrivacyComputationRequest {
        intent_commitment: intent.commitment(),
        signal_commitment: signals.commitment(),
        request_nonce,
        expiry_slot,
    }
}

pub fn evaluate_privacy(signals: &PrivacySignals) -> PrivacyDecision {
    let mut score: u8 = 35;
    let mut flags = 0u16;

    score = score.saturating_add(match signals.amount_bucket {
        PrivacyAmountBucket::Dust => 6,
        PrivacyAmountBucket::Small => 10,
        PrivacyAmountBucket::Medium => 14,
        PrivacyAmountBucket::Large => 18,
        PrivacyAmountBucket::Whale => 22,
    });

    score = score.saturating_add(match signals.pool_bucket {
        PrivacyPoolBucket::Thin => {
            flags |= PRIVACY_DECISION_LINKABILITY_WARNING;
            2
        }
        PrivacyPoolBucket::Building => 9,
        PrivacyPoolBucket::Healthy => 17,
        PrivacyPoolBucket::Deep => 24,
    });

    match signals.route_risk {
        PrivacyRouteRisk::Low => score = score.saturating_add(12),
        PrivacyRouteRisk::Medium => score = score.saturating_add(4),
        PrivacyRouteRisk::High => {
            score = score.saturating_sub(10);
            flags |= PRIVACY_DECISION_LINKABILITY_WARNING;
        }
        PrivacyRouteRisk::Blocked => {
            flags |= PRIVACY_DECISION_BLOCKED;
        }
    }

    if signals.route_risk != PrivacyRouteRisk::Blocked {
        if signals.flags & PRIVACY_FLAG_STEALTH_RECIPIENT != 0 {
            score = score.saturating_add(8);
        }
        if signals.flags & PRIVACY_FLAG_ONE_TIME_ADDRESS != 0 {
            score = score.saturating_add(8);
        }
        if signals.flags & PRIVACY_FLAG_WITHDRAW_LINKABLE != 0 {
            score = score.saturating_sub(20);
            flags |= PRIVACY_DECISION_LINKABILITY_WARNING;
        }
    }
    if signals.disclosure_mode != PrivacyDisclosureMode::None {
        flags |= PRIVACY_DECISION_DISCLOSURE_AVAILABLE;
    }

    if signals.execution_model == PrivacyExecutionModel::ShieldedState {
        flags |= PRIVACY_DECISION_ROUTE_NATIVE;
    } else {
        flags |= PRIVACY_DECISION_ROUTE_PROVIDER;
    }

    if signals.action == PrivacyAction::Transfer || signals.action == PrivacyAction::SwapIntent {
        flags |= PRIVACY_DECISION_NEEDS_SHIELDING;
    }

    let approved = signals.route_risk != PrivacyRouteRisk::Blocked;
    if approved {
        flags |= PRIVACY_DECISION_READY;
    }

    PrivacyDecision {
        approved,
        execution_model: signals.execution_model,
        decision_flags: flags,
        privacy_score: if !approved {
            0
        } else if score > 100 {
            100
        } else {
            score
        },
        min_confirmations: match signals.pool_bucket {
            PrivacyPoolBucket::Thin => 8,
            PrivacyPoolBucket::Building => 4,
            PrivacyPoolBucket::Healthy => 2,
            PrivacyPoolBucket::Deep => 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_privacy_request, evaluate_privacy, PrivacyAction, PrivacyAmountBucket, PrivacyAsset,
        PrivacyDisclosureMode, PrivacyExecutionModel, PrivacyIntent, PrivacyPoolBucket,
        PrivacyRouteRisk, PrivacySignals, PRIVACY_DECISION_BLOCKED,
        PRIVACY_DECISION_DISCLOSURE_AVAILABLE, PRIVACY_DECISION_LINKABILITY_WARNING,
        PRIVACY_FLAG_ONE_TIME_ADDRESS, PRIVACY_FLAG_SELECTIVE_DISCLOSURE,
        PRIVACY_FLAG_STEALTH_RECIPIENT, PRIVACY_FLAG_WITHDRAW_LINKABLE,
    };

    fn sample_intent() -> PrivacyIntent {
        PrivacyIntent {
            privacy_account: [1; 32],
            action: PrivacyAction::Transfer,
            asset: PrivacyAsset::Usdc,
            amount_atoms: 25_000_000,
            counterparty_commitment: [2; 32],
            execution_model: PrivacyExecutionModel::ShieldedState,
            nonce: 9,
            expiry_slot: 1_000,
            flags: PRIVACY_FLAG_STEALTH_RECIPIENT | PRIVACY_FLAG_ONE_TIME_ADDRESS,
        }
    }

    fn sample_signals() -> PrivacySignals {
        PrivacySignals {
            action: PrivacyAction::Transfer,
            asset: PrivacyAsset::Usdc,
            amount_bucket: PrivacyAmountBucket::Medium,
            pool_bucket: PrivacyPoolBucket::Healthy,
            route_risk: PrivacyRouteRisk::Low,
            disclosure_mode: PrivacyDisclosureMode::SelectiveAudit,
            execution_model: PrivacyExecutionModel::ShieldedState,
            flags: PRIVACY_FLAG_STEALTH_RECIPIENT
                | PRIVACY_FLAG_ONE_TIME_ADDRESS
                | PRIVACY_FLAG_SELECTIVE_DISCLOSURE,
        }
    }

    #[test]
    fn privacy_intent_roundtrips() {
        let intent = sample_intent();
        let mut encoded = [0u8; PrivacyIntent::ENCODED_LEN];

        assert!(intent.encode(&mut encoded));
        assert_eq!(PrivacyIntent::decode(&encoded), Some(intent));
    }

    #[test]
    fn privacy_signals_roundtrip_through_lanes() {
        let signals = sample_signals();
        assert_eq!(
            PrivacySignals::unpack_lanes(signals.pack_lanes()),
            Some(signals)
        );
    }

    #[test]
    fn request_commitment_binds_intent_and_signals() {
        let intent = sample_intent();
        let signals = sample_signals();
        let first = build_privacy_request(&intent, &signals, 1, 500);

        let mut changed = intent;
        changed.amount_atoms += 1;
        let second = build_privacy_request(&changed, &signals, 1, 500);

        assert_ne!(first.commitment(), second.commitment());
    }

    #[test]
    fn healthy_native_transfer_gets_high_privacy_score() {
        let decision = evaluate_privacy(&sample_signals());

        assert!(decision.approved);
        assert!(decision.privacy_score >= 80);
        assert_ne!(
            decision.decision_flags & PRIVACY_DECISION_DISCLOSURE_AVAILABLE,
            0
        );
    }

    #[test]
    fn linkable_withdraw_gets_warning() {
        let mut signals = sample_signals();
        signals.action = PrivacyAction::Withdraw;
        signals.route_risk = PrivacyRouteRisk::High;
        signals.flags |= PRIVACY_FLAG_WITHDRAW_LINKABLE;

        let decision = evaluate_privacy(&signals);

        assert!(decision.approved);
        assert_ne!(
            decision.decision_flags & PRIVACY_DECISION_LINKABILITY_WARNING,
            0
        );
    }

    #[test]
    fn blocked_route_is_not_approved() {
        let mut signals = sample_signals();
        signals.route_risk = PrivacyRouteRisk::Blocked;

        let decision = evaluate_privacy(&signals);

        assert!(!decision.approved);
        assert_eq!(decision.privacy_score, 0);
        assert_ne!(decision.decision_flags & PRIVACY_DECISION_BLOCKED, 0);
    }
}
