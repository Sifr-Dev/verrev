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
    SizeMismatch,
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

#[derive(Default)]
pub struct ContentStore {
    blocks: BTreeMap<[u8; HASH_SIZE], Vec<u8>>,
}

impl ContentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, data: &[u8]) -> BlockRef {
        let hash = sha3::sha3_256(data);
        self.blocks.insert(hash, data.to_vec());
        BlockRef {
            hash,
            size: data.len() as u32,
        }
    }

    pub fn get(&self, r#ref: &BlockRef) -> Result<Vec<u8>> {
        self.validate(r#ref)?;
        match self.blocks.get(&r#ref.hash) {
            Some(data) => Ok(data.clone()),
            None => Err(StoreError::NotFound),
        }
    }

    pub fn verify(&self, r#ref: &BlockRef) -> Result<()> {
        self.validate(r#ref).map(|_| ())
    }

    fn validate(&self, r#ref: &BlockRef) -> Result<&[u8]> {
        let Some(data) = self.blocks.get(&r#ref.hash) else {
            return Err(StoreError::NotFound);
        };
        if data.len() != r#ref.size as usize {
            return Err(StoreError::SizeMismatch);
        }
        if sha3::sha3_256(data) != r#ref.hash {
            return Err(StoreError::HashMismatch);
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_only_an_intact_block_with_the_declared_size() {
        let mut store = ContentStore::new();
        let data = b"content addressed and length checked";
        let block = store.put(data);

        assert_eq!(block.size, data.len() as u32);
        assert_eq!(store.get(&block), Ok(data.to_vec()));
        assert_eq!(store.verify(&block), Ok(()));
    }

    #[test]
    fn get_rejects_incorrect_declared_sizes_before_returning_data() {
        let mut store = ContentStore::new();
        let block = store.put(b"12345678");

        for size in [0, 7, 9, u32::MAX] {
            let invalid = BlockRef { size, ..block };
            assert_eq!(store.get(&invalid), Err(StoreError::SizeMismatch));
            assert_eq!(store.verify(&invalid), Err(StoreError::SizeMismatch));
        }
    }

    #[test]
    fn get_distinguishes_a_missing_block_from_corruption() {
        let mut store = ContentStore::new();
        let block = store.put(b"present");
        let missing = BlockRef {
            hash: [0xA5; HASH_SIZE],
            size: block.size,
        };

        assert_eq!(store.get(&missing), Err(StoreError::NotFound));
        assert_eq!(store.verify(&missing), Err(StoreError::NotFound));
    }

    #[test]
    fn get_detects_content_corruption() {
        let mut store = ContentStore::new();
        let block = store.put(b"original bytes");
        if let Some(data) = store.blocks.get_mut(&block.hash) {
            data[0] ^= 1;
        }

        assert_eq!(store.get(&block), Err(StoreError::HashMismatch));
        assert_eq!(store.verify(&block), Err(StoreError::HashMismatch));
    }

    #[test]
    fn get_detects_stored_length_corruption() {
        let mut store = ContentStore::new();
        let block = store.put(b"original bytes");
        if let Some(data) = store.blocks.get_mut(&block.hash) {
            data.pop();
        }

        assert_eq!(store.get(&block), Err(StoreError::SizeMismatch));
        assert_eq!(store.verify(&block), Err(StoreError::SizeMismatch));
    }
}
