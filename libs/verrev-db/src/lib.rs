#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub mod kv;
pub mod queue;
pub mod doc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbError {
    NotFound,
    Conflict,
    CollectionExists,
    SerializationError,
}

pub type Result<T> = core::result::Result<T, DbError>;

pub struct Database {
    collections: BTreeMap<String, Vec<u8>>,
}

impl Database {
    pub fn new() -> Self {
        Database { collections: BTreeMap::new() }
    }

    pub fn create_collection(&mut self, name: &str) -> Result<()> {
        if self.collections.contains_key(name) {
            return Err(DbError::CollectionExists);
        }
        self.collections.insert(name.into(), Vec::new());
        Ok(())
    }
}
