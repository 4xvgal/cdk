use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use cdk_common::payment;
use cdk_lnd::lnrpc;
use serde_json::{json, Value};

/// NUT-XX hold state of a quote
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    /// No HTLCs, or HTLCs not summing to the amount, have been accepted
    Unpaid,
    /// HTLCs summing to the amount are accepted and not resolved
    Held,
    /// The HTLCs were settled with the preimage
    Settled,
    /// The held HTLCs were cancelled
    Cancelled,
}

impl HoldState {
    /// NUT-XX string form
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unpaid => "UNPAID",
            Self::Held => "HELD",
            Self::Settled => "SETTLED",
            Self::Cancelled => "CANCELLED",
        }
    }

    fn from_invoice_state(state: lnrpc::invoice::InvoiceState) -> Self {
        match state {
            lnrpc::invoice::InvoiceState::Open => Self::Unpaid,
            lnrpc::invoice::InvoiceState::Accepted => Self::Held,
            lnrpc::invoice::InvoiceState::Settled => Self::Settled,
            lnrpc::invoice::InvoiceState::Canceled => Self::Cancelled,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Unpaid => 0,
            Self::Held => 1,
            Self::Settled | Self::Cancelled => 2,
        }
    }

    fn is_terminal(self) -> bool {
        self.rank() == Self::Settled.rank()
    }
}

/// Hold state and timing of an LND hold invoice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldStatus {
    /// NUT-XX hold state
    pub state: HoldState,
    /// Lowest `expiry_height` over accepted HTLCs
    pub min_htlc_expiry_height: Option<i32>,
}

impl HoldStatus {
    /// Map an LND invoice to a hold status
    pub fn from_invoice(invoice: &lnrpc::Invoice) -> Self {
        Self {
            state: HoldState::from_invoice_state(invoice.state()),
            min_htlc_expiry_height: invoice
                .htlcs
                .iter()
                .filter(|htlc| htlc.state() == lnrpc::InvoiceHtlcState::Accepted)
                .map(|htlc| htlc.expiry_height)
                .min(),
        }
    }

    /// Status of an invoice LND does not know
    pub fn unpaid() -> Self {
        Self {
            state: HoldState::Unpaid,
            min_htlc_expiry_height: None,
        }
    }

    /// `true` once LND has settled the invoice
    pub fn is_settled(self) -> bool {
        self.state == HoldState::Settled
    }
}

/// Last block height at which the mint accepts the preimage, `None` while it is
/// unknown
pub fn settle_deadline(
    min_htlc_expiry_height: Option<i32>,
    settle_margin_blocks: u32,
) -> Option<u32> {
    let height = u32::try_from(min_htlc_expiry_height?).ok()?;
    Some(height.saturating_sub(settle_margin_blocks))
}

/// Hold state, timing and settle deadline of one tracked hold invoice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldRecord {
    /// NUT-XX hold state
    pub state: HoldState,
    /// Lowest `expiry_height` over accepted HTLCs
    pub min_htlc_expiry_height: Option<i32>,
    /// Last block height at which the mint accepts the preimage
    pub settle_deadline: Option<u32>,
}

impl HoldRecord {
    /// Build a record from a freshly observed status
    pub fn from_status(status: HoldStatus, settle_margin_blocks: u32) -> Self {
        let settle_deadline = (status.state == HoldState::Held)
            .then(|| settle_deadline(status.min_htlc_expiry_height, settle_margin_blocks))
            .flatten();

        Self {
            state: status.state,
            min_htlc_expiry_height: status.min_htlc_expiry_height,
            settle_deadline,
        }
    }

    /// `true` when the held HTLCs must be cancelled at `block_height`
    pub fn should_cancel(self, block_height: u32) -> bool {
        self.state == HoldState::Held
            && self
                .settle_deadline
                .is_some_and(|deadline| block_height > deadline)
    }

    /// Extra JSON fields reported to the mint
    pub fn extra_json(self) -> Value {
        json!({
            "hold_state": self.state.as_str(),
            "min_htlc_expiry_height": self.min_htlc_expiry_height,
            "settle_deadline": self.settle_deadline,
        })
    }
}

/// Effect of a tracked record on the subscription of its invoice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowAction {
    /// Keep following the invoice
    Continue,
    /// Stop following; the invoice is resolved without a payment
    Stop,
    /// Stop following and report the payment to the mint
    Settle,
}

/// `true` when the held HTLCs must be cancelled
///
/// A persisted preimage means the settlement is pending, and NUT-XX forbids
/// cancelling such HTLCs.
pub fn should_cancel(record: HoldRecord, preimage_persisted: bool, block_height: u32) -> bool {
    !preimage_persisted && record.should_cancel(block_height)
}

/// Outcome of a settle request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleDecision {
    /// Settle the held HTLCs with the preimage
    Settle,
    /// The HTLCs are already settled, so the request is a no-op
    AlreadySettled,
}

/// Decide a settle request, accepting it up to the settle deadline height
///
/// A preimage that is already persisted was accepted within the deadline, so
/// the deadline no longer applies and the HTLCs must be settled.
pub fn settle_decision(
    record: HoldRecord,
    preimage_persisted: bool,
    block_height: Option<u32>,
) -> Result<SettleDecision, payment::Error> {
    match record.state {
        HoldState::Settled => Ok(SettleDecision::AlreadySettled),
        HoldState::Cancelled => Err(payment::Error::HoldCancelled),
        HoldState::Unpaid => Err(payment::Error::HoldNotHeld),
        HoldState::Held if preimage_persisted => Ok(SettleDecision::Settle),
        HoldState::Held => match (record.settle_deadline, block_height) {
            (Some(deadline), Some(height)) if height > deadline => {
                Err(payment::Error::SettleDeadlinePassed)
            }
            (Some(_), None) => Err(payment::Error::UnknownPaymentState),
            _ => Ok(SettleDecision::Settle),
        },
    }
}

/// Action for a tracked record, reporting a payment only once it is settled
pub fn follow_action(record: HoldRecord) -> FollowAction {
    match record.state {
        HoldState::Unpaid | HoldState::Held => FollowAction::Continue,
        HoldState::Settled => FollowAction::Settle,
        HoldState::Cancelled => FollowAction::Stop,
    }
}

/// In-memory hold records keyed by payment hash
#[derive(Debug)]
pub struct HoldTracker {
    settle_margin_blocks: u32,
    records: Mutex<HashMap<[u8; 32], HoldRecord>>,
}

impl HoldTracker {
    /// Tracker deriving settle deadlines with `settle_margin_blocks`
    pub fn new(settle_margin_blocks: u32) -> Self {
        Self {
            settle_margin_blocks,
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Current record of `payment_hash`
    pub fn get(&self, payment_hash: &[u8; 32]) -> Option<HoldRecord> {
        self.lock().get(payment_hash).copied()
    }

    /// Fold an observed status into the record of `payment_hash`
    ///
    /// States only move forward, and the settle deadline never rises, so a
    /// stale observation cannot reopen a resolved quote.
    pub fn observe(&self, payment_hash: &[u8; 32], status: HoldStatus) -> HoldRecord {
        let mut records = self.lock();
        let mut next = HoldRecord::from_status(status, self.settle_margin_blocks);

        if let Some(previous) = records.get(payment_hash).copied() {
            if previous.state.is_terminal() || next.state.rank() < previous.state.rank() {
                next.state = previous.state;
            }

            next.settle_deadline = if previous.state.is_terminal() {
                previous.settle_deadline
            } else {
                match (previous.settle_deadline, next.settle_deadline) {
                    (Some(previous), Some(next)) => Some(previous.min(next)),
                    (previous, next) => previous.or(next),
                }
            };
        }

        records.insert(*payment_hash, next);
        next
    }

    /// Mark a held record as cancelled, returning whether it changed
    pub fn mark_cancelled(&self, payment_hash: &[u8; 32]) -> bool {
        let mut records = self.lock();
        let Some(record) = records.get_mut(payment_hash) else {
            return false;
        };

        if record.state != HoldState::Held {
            return false;
        }

        record.state = HoldState::Cancelled;
        true
    }

    /// Mark a held record as settled, returning whether it changed
    pub fn mark_settled(&self, payment_hash: &[u8; 32]) -> bool {
        let mut records = self.lock();
        let Some(record) = records.get_mut(payment_hash) else {
            return false;
        };

        if record.state != HoldState::Held {
            return false;
        }

        record.state = HoldState::Settled;
        true
    }

    /// Held records, the candidates for cancellation
    pub fn held(&self) -> Vec<([u8; 32], HoldRecord)> {
        self.lock()
            .iter()
            .filter(|(_, record)| record.state == HoldState::Held)
            .map(|(payment_hash, record)| (*payment_hash, *record))
            .collect()
    }

    /// `true` when `payment_hash` already has a record
    pub fn is_tracked(&self, payment_hash: &[u8; 32]) -> bool {
        self.lock().contains_key(payment_hash)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], HoldRecord>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> [u8; 32] {
        [7u8; 32]
    }

    fn invoice(
        state: lnrpc::invoice::InvoiceState,
        htlcs: Vec<lnrpc::InvoiceHtlc>,
    ) -> lnrpc::Invoice {
        lnrpc::Invoice {
            state: state as i32,
            htlcs,
            ..Default::default()
        }
    }

    fn htlc(state: lnrpc::InvoiceHtlcState, expiry_height: i32) -> lnrpc::InvoiceHtlc {
        lnrpc::InvoiceHtlc {
            state: state as i32,
            expiry_height,
            ..Default::default()
        }
    }

    fn status(state: HoldState, min_htlc_expiry_height: Option<i32>) -> HoldStatus {
        HoldStatus {
            state,
            min_htlc_expiry_height,
        }
    }

    #[test]
    fn open_invoice_is_unpaid() {
        let status =
            HoldStatus::from_invoice(&invoice(lnrpc::invoice::InvoiceState::Open, Vec::new()));

        assert_eq!(status.state, HoldState::Unpaid);
        assert_eq!(status.state.as_str(), "UNPAID");
        assert_eq!(status.min_htlc_expiry_height, None);
        assert!(!status.is_settled());
    }

    #[test]
    fn accepted_invoice_is_held_with_lowest_accepted_expiry() {
        let status = HoldStatus::from_invoice(&invoice(
            lnrpc::invoice::InvoiceState::Accepted,
            vec![
                htlc(lnrpc::InvoiceHtlcState::Accepted, 120),
                htlc(lnrpc::InvoiceHtlcState::Accepted, 100),
                htlc(lnrpc::InvoiceHtlcState::Settled, 50),
            ],
        ));

        assert_eq!(status.state, HoldState::Held);
        assert_eq!(status.state.as_str(), "HELD");
        assert_eq!(status.min_htlc_expiry_height, Some(100));
        assert!(!status.is_settled());
    }

    #[test]
    fn accepted_invoice_without_accepted_htlcs_has_no_expiry() {
        let status = HoldStatus::from_invoice(&invoice(
            lnrpc::invoice::InvoiceState::Accepted,
            vec![htlc(lnrpc::InvoiceHtlcState::Canceled, 100)],
        ));

        assert_eq!(status.state, HoldState::Held);
        assert_eq!(status.min_htlc_expiry_height, None);
    }

    #[test]
    fn settled_invoice_is_settled() {
        let status = HoldStatus::from_invoice(&invoice(
            lnrpc::invoice::InvoiceState::Settled,
            vec![htlc(lnrpc::InvoiceHtlcState::Settled, 100)],
        ));

        assert_eq!(status.state, HoldState::Settled);
        assert_eq!(status.state.as_str(), "SETTLED");
        assert!(status.is_settled());
    }

    #[test]
    fn canceled_invoice_is_cancelled() {
        let status =
            HoldStatus::from_invoice(&invoice(lnrpc::invoice::InvoiceState::Canceled, Vec::new()));

        assert_eq!(status.state, HoldState::Cancelled);
        assert_eq!(status.state.as_str(), "CANCELLED");
        assert!(!status.is_settled());
    }

    #[test]
    fn deadline_subtracts_margin_from_lowest_expiry() {
        assert_eq!(settle_deadline(Some(870_420), 12), Some(870_408));
        assert_eq!(settle_deadline(Some(870_420), 0), Some(870_420));
        assert_eq!(settle_deadline(Some(5), 12), Some(0));
        assert_eq!(settle_deadline(None, 12), None);
        assert_eq!(settle_deadline(Some(-1), 12), None);
    }

    #[test]
    fn deadline_requires_held_state() {
        let unpaid = HoldRecord::from_status(status(HoldState::Unpaid, Some(1_000)), 12);
        assert_eq!(unpaid.settle_deadline, None);

        let held = HoldRecord::from_status(status(HoldState::Held, Some(1_000)), 12);
        assert_eq!(held.settle_deadline, Some(988));

        let settled = HoldRecord::from_status(status(HoldState::Settled, Some(1_000)), 12);
        assert_eq!(settled.settle_deadline, None);

        let without_htlcs = HoldRecord::from_status(status(HoldState::Held, None), 12);
        assert_eq!(without_htlcs.settle_deadline, None);
    }

    #[test]
    fn cancel_only_after_deadline_of_held_invoice() {
        let held = HoldRecord::from_status(status(HoldState::Held, Some(1_000)), 12);

        assert!(!held.should_cancel(0));
        assert!(!held.should_cancel(987));
        assert!(!held.should_cancel(988));
        assert!(held.should_cancel(989));
        assert!(held.should_cancel(1_000));
    }

    #[test]
    fn cancel_ignores_other_states_and_unknown_deadline() {
        for state in [HoldState::Unpaid, HoldState::Settled, HoldState::Cancelled] {
            assert!(
                !HoldRecord::from_status(status(state, Some(1_000)), 12).should_cancel(u32::MAX)
            );
        }

        assert!(!HoldRecord::from_status(status(HoldState::Held, None), 12).should_cancel(u32::MAX));
    }

    #[test]
    fn observation_moves_unpaid_to_held_with_deadline() {
        let tracker = HoldTracker::new(12);

        let record = tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        assert_eq!(record.state, HoldState::Held);
        assert_eq!(record.settle_deadline, Some(988));
        assert_eq!(tracker.get(&hash()), Some(record));
        assert!(tracker.is_tracked(&hash()));
        assert_eq!(tracker.held(), vec![(hash(), record)]);
    }

    #[test]
    fn observation_keeps_deadline_once_held() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        let record = tracker.observe(&hash(), status(HoldState::Held, Some(1_060)));

        assert_eq!(record.settle_deadline, Some(988));
    }

    #[test]
    fn observation_lowers_deadline_on_earlier_expiry() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        let record = tracker.observe(&hash(), status(HoldState::Held, Some(900)));

        assert_eq!(record.settle_deadline, Some(888));
    }

    #[test]
    fn observation_of_settled_keeps_state_and_deadline() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        let record = tracker.observe(&hash(), status(HoldState::Settled, Some(1_000)));

        assert_eq!(record.state, HoldState::Settled);
        assert_eq!(record.settle_deadline, Some(988));
        assert!(tracker.held().is_empty());
    }

    #[test]
    fn stale_unpaid_observation_does_not_reopen_held_or_settled() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        assert_eq!(
            tracker.observe(&hash(), HoldStatus::unpaid()).state,
            HoldState::Held
        );

        tracker.observe(&hash(), status(HoldState::Settled, Some(1_000)));

        let record = tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));
        assert_eq!(record.state, HoldState::Settled);
        assert_eq!(record.settle_deadline, Some(988));
    }

    #[test]
    fn cancelled_record_is_terminal() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        assert!(tracker.mark_cancelled(&hash()));
        assert!(!tracker.mark_cancelled(&hash()));

        let record = tracker.observe(&hash(), status(HoldState::Settled, Some(1_000)));
        assert_eq!(record.state, HoldState::Cancelled);
        assert_eq!(record.settle_deadline, Some(988));
        assert!(tracker.held().is_empty());
    }

    #[test]
    fn cancel_requires_a_held_record() {
        let tracker = HoldTracker::new(12);

        assert!(!tracker.mark_cancelled(&hash()));

        tracker.observe(&hash(), HoldStatus::unpaid());
        assert!(!tracker.mark_cancelled(&hash()));

        tracker.observe(&hash(), status(HoldState::Settled, Some(1_000)));
        assert!(!tracker.mark_cancelled(&hash()));
    }

    #[test]
    fn only_settled_records_report_a_payment() {
        for (state, expected) in [
            (HoldState::Unpaid, FollowAction::Continue),
            (HoldState::Held, FollowAction::Continue),
            (HoldState::Settled, FollowAction::Settle),
            (HoldState::Cancelled, FollowAction::Stop),
        ] {
            let record = HoldRecord::from_status(status(state, Some(1_000)), 12);
            assert_eq!(follow_action(record), expected, "{state:?}");
        }
    }

    #[test]
    fn cancelled_invoice_never_reports_a_payment() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));
        assert!(tracker.mark_cancelled(&hash()));

        for status in [
            HoldStatus::unpaid(),
            status(HoldState::Held, Some(1_000)),
            status(HoldState::Settled, Some(1_000)),
        ] {
            let record = tracker.observe(&hash(), status);
            assert_eq!(follow_action(record), FollowAction::Stop);
        }
    }

    #[test]
    fn terminal_record_freezes_settle_deadline() {
        for terminal in [HoldState::Settled, HoldState::Cancelled] {
            let tracker = HoldTracker::new(12);
            tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

            if terminal == HoldState::Settled {
                tracker.observe(&hash(), status(HoldState::Settled, Some(1_000)));
            } else {
                assert!(tracker.mark_cancelled(&hash()));
            }

            let record = tracker.observe(&hash(), status(HoldState::Held, Some(900)));

            assert_eq!(record.state, terminal);
            assert_eq!(record.settle_deadline, Some(988));
        }
    }

    #[test]
    fn settle_requires_a_held_record() {
        let tracker = HoldTracker::new(12);

        assert!(!tracker.mark_settled(&hash()));

        tracker.observe(&hash(), HoldStatus::unpaid());
        assert!(!tracker.mark_settled(&hash()));

        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));
        assert!(tracker.mark_settled(&hash()));
    }

    #[test]
    fn settled_record_keeps_its_deadline_and_stops_cancelling() {
        let tracker = HoldTracker::new(12);
        tracker.observe(&hash(), status(HoldState::Held, Some(1_000)));

        assert!(tracker.mark_settled(&hash()));
        assert!(!tracker.mark_settled(&hash()));

        let record = tracker.get(&hash()).expect("tracked record");
        assert_eq!(record.state, HoldState::Settled);
        assert_eq!(record.settle_deadline, Some(988));
        assert!(tracker.held().is_empty());
        assert_eq!(follow_action(record), FollowAction::Settle);
    }

    #[test]
    fn settle_decision_accepts_at_the_deadline_height() {
        let held = HoldRecord::from_status(status(HoldState::Held, Some(1_012)), 12);

        assert_eq!(held.settle_deadline, Some(1_000));
        assert_eq!(
            settle_decision(held, false, Some(1_000)).ok(),
            Some(SettleDecision::Settle)
        );
        assert_eq!(
            settle_decision(held, false, Some(0)).ok(),
            Some(SettleDecision::Settle)
        );
        assert!(matches!(
            settle_decision(held, false, Some(1_001)),
            Err(payment::Error::SettleDeadlinePassed)
        ));
    }

    #[test]
    fn persisted_preimage_is_accepted_past_the_deadline() {
        let held = HoldRecord::from_status(status(HoldState::Held, Some(1_012)), 12);

        assert_eq!(
            settle_decision(held, true, Some(u32::MAX)).ok(),
            Some(SettleDecision::Settle)
        );
        assert_eq!(
            settle_decision(held, true, None).ok(),
            Some(SettleDecision::Settle)
        );
    }

    #[test]
    fn settle_decision_accepts_a_held_record_without_deadline() {
        let held = HoldRecord::from_status(status(HoldState::Held, None), 12);

        assert_eq!(
            settle_decision(held, false, Some(u32::MAX)).ok(),
            Some(SettleDecision::Settle)
        );
    }

    #[test]
    fn settle_decision_needs_a_height_for_a_held_deadline() {
        let held = HoldRecord::from_status(status(HoldState::Held, Some(1_012)), 12);

        assert!(matches!(
            settle_decision(held, false, None),
            Err(payment::Error::UnknownPaymentState)
        ));
    }

    #[test]
    fn settle_decision_rejects_unpaid_and_cancelled_records() {
        for (state, expected) in [
            (HoldState::Unpaid, "not held"),
            (HoldState::Cancelled, "cancelled"),
        ] {
            let record = HoldRecord::from_status(status(state, Some(1_000)), 12);
            let error = settle_decision(record, false, Some(0)).expect_err(expected);

            assert_eq!(
                matches!(error, payment::Error::HoldNotHeld),
                state == HoldState::Unpaid,
                "{state:?}"
            );
            assert_eq!(
                matches!(error, payment::Error::HoldCancelled),
                state == HoldState::Cancelled,
                "{state:?}"
            );
        }
    }

    #[test]
    fn cancelled_record_is_not_settled_by_a_persisted_preimage() {
        let cancelled = HoldRecord::from_status(status(HoldState::Cancelled, Some(1_000)), 12);

        assert!(matches!(
            settle_decision(cancelled, true, Some(0)),
            Err(payment::Error::HoldCancelled)
        ));
    }

    #[test]
    fn settled_record_is_idempotent_past_the_deadline() {
        let settled = HoldRecord::from_status(status(HoldState::Settled, Some(1_000)), 12);

        assert_eq!(
            settle_decision(settled, true, Some(u32::MAX)).ok(),
            Some(SettleDecision::AlreadySettled)
        );
    }

    #[test]
    fn cancel_is_skipped_once_the_preimage_is_persisted() {
        let held = HoldRecord::from_status(status(HoldState::Held, Some(1_000)), 12);

        assert!(should_cancel(held, false, 989));
        assert!(!should_cancel(held, true, 989));
        assert!(!should_cancel(held, true, u32::MAX));
        assert!(!should_cancel(held, false, 988));
    }

    #[test]
    fn extra_json_reports_state_and_deadline() {
        let held = HoldRecord::from_status(status(HoldState::Held, Some(870_420)), 12);
        assert_eq!(
            held.extra_json(),
            json!({
                "hold_state": "HELD",
                "min_htlc_expiry_height": 870_420,
                "settle_deadline": 870_408,
            })
        );

        let unpaid = HoldRecord::from_status(HoldStatus::unpaid(), 12);
        assert_eq!(
            unpaid.extra_json(),
            json!({
                "hold_state": "UNPAID",
                "min_htlc_expiry_height": null,
                "settle_deadline": null,
            })
        );
    }
}
