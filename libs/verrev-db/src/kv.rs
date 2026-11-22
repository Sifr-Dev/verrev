use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct KvStore {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl KvStore {
    pub fn new() -> Self {
        KvStore { data: BTreeMap::new() }
    }

    pub fn get(&self, key: &[u8]) -> super::Result<Vec<u8>> {
        self.data.get(key).cloned().ok_or(super::DbError::NotFound)
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> super::Result<()> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> super::Result<()> {
        self.data.remove(key).ok_or(super::DbError::NotFound).map(|_| ())?;
        Ok(())
    }
}

impl Default for KvStore {
    fn default() -> Self {
        Self::new()
    }
}
