use super::*;

pub struct StoragePolicy {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub replication_factor: usize,
    pub encryption: bool,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        StoragePolicy {
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
            replication_factor: 3,
            encryption: true,
        }
    }
}
