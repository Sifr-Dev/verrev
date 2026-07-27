#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use verrev_hash::sha3;

pub const BLOCK_SIZE: usize = 4096;
pub const HASH_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    HashMismatch,
    Corruption,
    IoError,
}

pub type Result<T> = core::result::Result<T, StoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    pub hash: [u8; HASH_SIZE],
    pub size: u32,
}

pub struct ContentStore {
    blocks: BTreeMap<[u8; HASH_SIZE], Vec<u8>>,
}

impl ContentStore {
    pub fn new() -> Self {
        ContentStore { blocks: BTreeMap::new() }
    }

    pub fn put(&mut self, data: &[u8]) -> BlockRef {
        let hash = sha3::sha3_256(data);
        self.blocks.insert(hash, data.to_vec());
        BlockRef { hash, size: data.len() as u32 }
    }

    pub fn get(&self, r#ref: &BlockRef) -> Option<Vec<u8>> {
        self.blocks.get(&r#ref.hash).cloned()
    }

    pub fn verify(&self, r#ref: &BlockRef) -> bool {
        self.blocks.get(&r#ref.hash)
            .map_or(false, |data| sha3::sha3_256(data) == r#ref.hash)
    }
}
