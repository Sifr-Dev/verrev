use alloc::vec::Vec;
use crate::*;

pub enum SyncMessage {
    StateAnnounce {
        hash: [u8; HASH_SIZE],
        version: u64,
    },
    StateRequest {
        remote_hash: [u8; HASH_SIZE],
        known_hashes: Vec<[u8; HASH_SIZE]>,
    },
    StateDelta {
        base_hash: [u8; HASH_SIZE],
        ops: Vec<u8>,
    },
    Ack {
        hash: [u8; HASH_SIZE],
    },
}

pub struct SyncSession {
    state_hash: [u8; HASH_SIZE],
    remote_hash: [u8; HASH_SIZE],
    version: u64,
}

impl SyncSession {
    pub fn new(local_hash: [u8; HASH_SIZE]) -> Self {
        SyncSession {
            state_hash: local_hash,
            remote_hash: [0u8; HASH_SIZE],
            version: 0,
        }
    }

    pub fn reconcile(&mut self, remote: &SyncMessage) -> Result<Option<SyncMessage>> {
        Ok(None)
    }
}
