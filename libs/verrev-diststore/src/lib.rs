#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_store::BlockRef;

pub mod erasure;
pub mod repair;
pub mod policy;

pub const DEFAULT_DATA_SHARDS: usize = 8;
pub const DEFAULT_PARITY_SHARDS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistStoreError {
    NotEnoughPeers,
    RepairFailed,
    PolicyViolation,
    BlockNotFound,
}

pub type Result<T> = core::result::Result<T, DistStoreError>;

pub struct DistributedStore;

impl DistributedStore {
    pub fn new() -> Self {
        DistributedStore
    }

    pub fn put(&mut self, _data: &[u8], _policy: &policy::StoragePolicy) -> Result<BlockRef> {
        Err(DistStoreError::NotEnoughPeers)
    }

    pub fn get(&self, _ref: &BlockRef) -> Result<Vec<u8>> {
        Err(DistStoreError::BlockNotFound)
    }

    pub fn repair(&mut self, _ref: &BlockRef) -> Result<()> {
        Err(DistStoreError::RepairFailed)
    }
}

impl Default for DistributedStore {
    fn default() -> Self {
        Self::new()
    }
}
