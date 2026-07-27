use alloc::vec::Vec;
use verrev_identity::Identity;
use crate::*;

pub fn needs_repair(_ref: &BlockRef) -> bool {
    false
}

pub fn find_replacements(_missing: &[Identity]) -> Result<Vec<Identity>> {
    Err(DistStoreError::NotEnoughPeers)
}
