#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_identity::Identity;
use verrev_transport::connection::Connection;

pub struct RelaySession {
    session_id: [u8; 32],
    source: Identity,
    destination: Identity,
    hop_count: u8,
}

pub struct StoreAndForward {
    pending: Vec<StoredMessage>,
}

struct StoredMessage {
    recipient: Identity,
    data: Vec<u8>,
    expiry: u64,
}

impl StoreAndForward {
    pub fn new() -> Self {
        StoreAndForward { pending: Vec::new() }
    }

    pub fn store(&mut self, recipient: Identity, data: Vec<u8>, ttl_secs: u64) -> bool {
        self.prune();
        if self.pending.iter().any(|m| m.recipient == recipient && m.data == data) {
            return false;
        }
        let now = verrev_syscall::linux::now_nanos().unwrap_or(0) / 1_000_000_000;
        self.pending.push(StoredMessage { recipient, data, expiry: now + ttl_secs });
        true
    }

    pub fn retrieve(&mut self, recipient: &Identity) -> Option<Vec<u8>> {
        self.prune();
        let pos = self.pending.iter().position(|m| m.recipient == *recipient)?;
        let msg = self.pending.remove(pos);
        Some(msg.data)
    }
    
    fn prune(&mut self) {
        let now = verrev_syscall::linux::now_nanos().unwrap_or(0) / 1_000_000_000;
        self.pending.retain(|m| m.expiry > now);
    }
}
