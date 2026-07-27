use alloc::vec::Vec;
use crate::*;

pub fn find_workers(_function_hash: [u8; 32], _count: usize) -> Result<Vec<Identity>> {
    Err(ComputeError::NoAvailableWorker)
}
