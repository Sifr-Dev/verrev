use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use verrev_hash::sha3;

pub struct DocumentStore {
    collections: BTreeMap<String, BTreeMap<[u8; 32], Vec<u8>>>,
}

impl DocumentStore {
    pub fn new() -> Self {
        DocumentStore { collections: BTreeMap::new() }
    }

    pub fn insert(&mut self, collection: &str, doc: &[u8]) -> super::Result<[u8; 32]> {
        let id = sha3::sha3_256(doc);
        let col = self.collections.entry(collection.into()).or_default();
        if col.contains_key(&id) {
            return Err(super::DbError::Conflict);
        }
        col.insert(id, doc.to_vec());
        Ok(id)
    }

    pub fn find(&self, collection: &str, id: &[u8; 32]) -> super::Result<Vec<u8>> {
        self.collections.get(collection)
            .and_then(|col| col.get(id))
            .cloned()
            .ok_or(super::DbError::NotFound)
    }
}

impl Default for DocumentStore {
    fn default() -> Self {
        Self::new()
    }
}
