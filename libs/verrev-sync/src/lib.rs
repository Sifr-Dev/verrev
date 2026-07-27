#![no_std]

extern crate alloc;



pub mod crdt;
pub mod merkle;
pub mod protocol;

pub const HASH_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    Conflict,
    InvalidState,
    HashMismatch,
    Diverged,
}

pub type Result<T> = core::result::Result<T, SyncError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncState {
    pub hash: [u8; HASH_SIZE],
    pub version: u64,
}
