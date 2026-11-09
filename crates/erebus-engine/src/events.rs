//! Bounded structured security-event journal.
//!
//! Events intentionally contain metadata only. Packet payloads, credentials,
//! DNS query contents, and other secrets must not be added to this type.

use erebus_types::{FlowId, Verdict};
use std::collections::VecDeque;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityEventKind {
    PolicyDecision {
        verdict: Verdict,
        rule_id: Option<String>,
    },
    PolicyReloaded {
        generation: u64,
    },
    ConnectionCreated,
    ConnectionStateChanged {
        state: String,
    },
    ConnectionExpired,
    RateLimitExceeded {
        scope: String,
    },
    EnforcementFailure {
        adapter: String,
        error_code: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityEvent {
    pub sequence: u64,
    /// Monotonic milliseconds from the caller's clock, not wall-clock time.
    pub timestamp_ms: u64,
    pub flow_id: Option<FlowId>,
    pub kind: SecurityEventKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordOutcome {
    pub sequence: u64,
    /// When the journal is full, the oldest event is evicted and its sequence
    /// is returned so callers can detect that the in-memory history rolled over.
    pub evicted_sequence: Option<u64>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EventJournalError {
    #[error("event journal capacity must be greater than zero")]
    ZeroCapacity,
    #[error("event timestamp moved backwards: previous {previous_ms} ms, received {received_ms} ms")]
    ClockWentBackwards {
        previous_ms: u64,
        received_ms: u64,
    },
    #[error("event sequence space is exhausted")]
    SequenceExhausted,
}

/// A bounded FIFO journal. On capacity pressure it retains the newest events
/// and explicitly reports the sequence number of the event it evicted.
pub struct EventJournal {
    capacity: usize,
    next_sequence: u64,
    last_timestamp_ms: Option<u64>,
    events: VecDeque<SecurityEvent>,
}

impl EventJournal {
    pub fn new(capacity: usize) -> Result<Self, EventJournalError> {
        if capacity == 0 {
            return Err(EventJournalError::ZeroCapacity);
        }

        Ok(Self {
            capacity,
            next_sequence: 1,
            last_timestamp_ms: None,
            events: VecDeque::with_capacity(capacity.min(4096)),
        })
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn record(
        &mut self,
        timestamp_ms: u64,
        flow_id: Option<FlowId>,
        kind: SecurityEventKind,
    ) -> Result<RecordOutcome, EventJournalError> {
        if let Some(previous_ms) = self.last_timestamp_ms {
            if timestamp_ms < previous_ms {
                return Err(EventJournalError::ClockWentBackwards {
                    previous_ms,
                    received_ms: timestamp_ms,
                });
            }
        }

        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(EventJournalError::SequenceExhausted)?;
        let sequence = self.next_sequence;
        self.next_sequence = next_sequence;
        self.last_timestamp_ms = Some(timestamp_ms);

        let evicted_sequence = if self.events.len() == self.capacity {
            self.events.pop_front().map(|event| event.sequence)
        } else {
            None
        };

        self.events.push_back(SecurityEvent {
            sequence,
            timestamp_ms,
            flow_id,
            kind,
        });

        Ok(RecordOutcome {
            sequence,
            evicted_sequence,
        })
    }

    /// Return a stable copy of retained events in sequence order.
    pub fn snapshot(&self) -> Vec<SecurityEvent> {
        self.events.iter().cloned().collect()
    }

    /// Remove retained events older than the supplied monotonic timestamp.
    pub fn prune_before(&mut self, timestamp_ms: u64) -> usize {
        let mut removed = 0;
        while self
            .events
            .front()
            .is_some_and(|event| event.timestamp_ms < timestamp_ms)
        {
            self.events.pop_front();
            removed += 1;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_records_ordered_structured_events() {
        let mut journal = EventJournal::new(4).unwrap();
        let first = journal
            .record(
                10,
                None,
                SecurityEventKind::PolicyDecision {
                    verdict: Verdict::Deny,
                    rule_id: Some("deny-ssh".into()),
                },
            )
            .unwrap();
        let second = journal
            .record(
                11,
                Some(FlowId(9)),
                SecurityEventKind::ConnectionCreated,
            )
            .unwrap();

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        let events = journal.snapshot();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].flow_id, Some(FlowId(9)));
    }

    #[test]
    fn full_journal_evicts_oldest_and_reports_sequence() {
        let mut journal = EventJournal::new(2).unwrap();
        journal
            .record(1, None, SecurityEventKind::ConnectionCreated)
            .unwrap();
        journal
            .record(2, None, SecurityEventKind::ConnectionExpired)
            .unwrap();

        let outcome = journal
            .record(3, None, SecurityEventKind::RateLimitExceeded {
                scope: "host".into(),
            })
            .unwrap();

        assert_eq!(outcome.sequence, 3);
        assert_eq!(outcome.evicted_sequence, Some(1));
        let events = journal.snapshot();
        assert_eq!(events.iter().map(|event| event.sequence).collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn journal_rejects_timestamp_regression() {
        let mut journal = EventJournal::new(2).unwrap();
        journal
            .record(10, None, SecurityEventKind::ConnectionCreated)
            .unwrap();

        assert_eq!(
            journal.record(9, None, SecurityEventKind::ConnectionExpired),
            Err(EventJournalError::ClockWentBackwards {
                previous_ms: 10,
                received_ms: 9
            })
        );
        assert_eq!(journal.len(), 1);
    }

    #[test]
    fn prune_removes_events_older_than_boundary() {
        let mut journal = EventJournal::new(4).unwrap();
        for time in 1..=3 {
            journal
                .record(time, None, SecurityEventKind::ConnectionCreated)
                .unwrap();
        }

        assert_eq!(journal.prune_before(3), 2);
        assert_eq!(journal.snapshot()[0].timestamp_ms, 3);
    }

    #[test]
    fn zero_capacity_is_rejected() {
        assert_eq!(EventJournal::new(0).unwrap_err(), EventJournalError::ZeroCapacity);
    }
}
