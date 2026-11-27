use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cdk_common::payment;
use rusqlite::{params, Connection, OptionalExtension};

use crate::hold::HoldState;

/// Preimage persisted for one hold invoice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettleRecord {
    /// Payment hash of the hold invoice
    pub payment_hash: [u8; 32],
    /// Preimage revealed for the payment hash
    pub preimage: [u8; 32],
}

/// SQLite store of the preimages and hold states owned by the processor
///
/// A persisted preimage is the promise to settle: it survives restarts and
/// keeps the deadline poller from cancelling the held HTLCs.
#[derive(Debug)]
pub struct SettleStore {
    connection: Mutex<Connection>,
}

impl SettleStore {
    /// Open the store at `path`, creating the schema if needed
    pub fn open(path: &Path) -> Result<Self, payment::Error> {
        Self::from_connection(Connection::open(path).map_err(store_error)?)
    }

    #[cfg(test)]
    /// Open an empty in-memory store
    pub fn in_memory() -> Result<Self, payment::Error> {
        Self::from_connection(Connection::open_in_memory().map_err(store_error)?)
    }

    fn from_connection(connection: Connection) -> Result<Self, payment::Error> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS hold_settle (
                    payment_hash BLOB PRIMARY KEY,
                    preimage BLOB NOT NULL,
                    hold_state TEXT NOT NULL
                )",
            )
            .map_err(store_error)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Persist `preimage` for `payment_hash` with `state`
    pub fn persist_preimage(
        &self,
        payment_hash: &[u8; 32],
        preimage: &[u8; 32],
        state: HoldState,
    ) -> Result<(), payment::Error> {
        self.connection()
            .execute(
                "INSERT INTO hold_settle (payment_hash, preimage, hold_state) VALUES (?1, ?2, ?3)
                 ON CONFLICT(payment_hash) DO UPDATE SET hold_state = excluded.hold_state
                 WHERE hold_state = 'HELD'",
                params![payment_hash.as_slice(), preimage.as_slice(), state.as_str()],
            )
            .map_err(store_error)?;

        Ok(())
    }

    /// Move a persisted record to `state`
    pub fn set_state(
        &self,
        payment_hash: &[u8; 32],
        state: HoldState,
    ) -> Result<(), payment::Error> {
        self.connection()
            .execute(
                "UPDATE hold_settle SET hold_state = ?2 WHERE payment_hash = ?1",
                params![payment_hash.as_slice(), state.as_str()],
            )
            .map_err(store_error)?;

        Ok(())
    }

    /// Preimage persisted for `payment_hash`, if any
    pub fn preimage(&self, payment_hash: &[u8; 32]) -> Result<Option<[u8; 32]>, payment::Error> {
        let preimage: Option<Vec<u8>> = self
            .connection()
            .query_row(
                "SELECT preimage FROM hold_settle WHERE payment_hash = ?1",
                params![payment_hash.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(store_error)?;

        preimage
            .map(|preimage| hash_from_bytes(&preimage))
            .transpose()
    }

    /// Records with a persisted preimage that are neither settled nor cancelled
    pub fn pending_settles(&self) -> Result<Vec<SettleRecord>, payment::Error> {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT payment_hash, preimage FROM hold_settle WHERE hold_state = ?1")
            .map_err(store_error)?;

        let rows = statement
            .query_map(params![HoldState::Held.as_str()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(store_error)?;

        let mut records = Vec::new();
        for row in rows {
            let (payment_hash, preimage) = row.map_err(store_error)?;
            records.push(SettleRecord {
                payment_hash: hash_from_bytes(&payment_hash)?,
                preimage: hash_from_bytes(&preimage)?,
            });
        }

        Ok(records)
    }

    fn connection(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

fn hash_from_bytes(bytes: &[u8]) -> Result<[u8; 32], payment::Error> {
    bytes.try_into().map_err(|_| payment::Error::InvalidHash)
}

fn store_error(error: rusqlite::Error) -> payment::Error {
    payment::Error::Backend(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn preimage_round_trip() {
        let store = SettleStore::in_memory().expect("in-memory store");

        assert_eq!(store.preimage(&hash(7)).expect("read"), None);

        store
            .persist_preimage(&hash(7), &hash(1), HoldState::Held)
            .expect("persist");

        assert_eq!(store.preimage(&hash(7)).expect("read"), Some(hash(1)));
        assert_eq!(store.preimage(&hash(8)).expect("read"), None);
    }

    #[test]
    fn persisting_twice_keeps_the_first_preimage() {
        let store = SettleStore::in_memory().expect("in-memory store");

        store
            .persist_preimage(&hash(7), &hash(1), HoldState::Held)
            .expect("persist");
        store
            .persist_preimage(&hash(7), &hash(2), HoldState::Settled)
            .expect("persist");

        assert_eq!(store.preimage(&hash(7)).expect("read"), Some(hash(1)));
        assert!(store.pending_settles().expect("pending").is_empty());
    }

    #[test]
    fn persisting_never_downgrades_a_resolved_state() {
        let store = SettleStore::in_memory().expect("in-memory store");

        for resolved in [HoldState::Settled, HoldState::Cancelled] {
            store
                .persist_preimage(&hash(7), &hash(1), HoldState::Held)
                .expect("persist");
            store.set_state(&hash(7), resolved).expect("set state");

            store
                .persist_preimage(&hash(7), &hash(1), HoldState::Held)
                .expect("persist");

            assert!(
                store.pending_settles().expect("pending").is_empty(),
                "{resolved:?}"
            );
        }
    }

    #[test]
    fn pending_settles_holds_unsettled_preimages() {
        let store = SettleStore::in_memory().expect("in-memory store");

        store
            .persist_preimage(&hash(7), &hash(1), HoldState::Held)
            .expect("persist");
        assert_eq!(
            store.pending_settles().expect("pending"),
            vec![SettleRecord {
                payment_hash: hash(7),
                preimage: hash(1),
            }]
        );

        store
            .set_state(&hash(7), HoldState::Settled)
            .expect("set state");
        assert!(store.pending_settles().expect("pending").is_empty());
        assert_eq!(store.preimage(&hash(7)).expect("read"), Some(hash(1)));
    }

    #[test]
    fn cancelled_records_are_not_pending() {
        let store = SettleStore::in_memory().expect("in-memory store");

        store
            .persist_preimage(&hash(7), &hash(1), HoldState::Held)
            .expect("persist");
        store
            .set_state(&hash(7), HoldState::Cancelled)
            .expect("set state");

        assert!(store.pending_settles().expect("pending").is_empty());
    }

    #[test]
    fn state_of_an_unknown_record_is_ignored() {
        let store = SettleStore::in_memory().expect("in-memory store");

        store
            .set_state(&hash(7), HoldState::Settled)
            .expect("set state");

        assert_eq!(store.preimage(&hash(7)).expect("read"), None);
        assert!(store.pending_settles().expect("pending").is_empty());
    }

    #[test]
    fn unopenable_path_is_a_backend_error() {
        let error =
            SettleStore::open(Path::new("/nonexistent/hold.sqlite")).expect_err("unopenable path");

        assert!(matches!(error, payment::Error::Backend(_)));
    }
}
