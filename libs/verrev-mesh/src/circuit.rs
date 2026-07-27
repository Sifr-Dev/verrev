use alloc::vec::Vec;
use verrev_identity::Identity;

pub struct Circuit {
    pub circuit_id: [u8; 32],
    pub hops: Vec<Identity>,
    pub session_key: [u8; 32],
    pub created_at: u64,
}
