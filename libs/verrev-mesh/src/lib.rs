#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_crypto::aead::XChaCha20Poly1305;
use verrev_identity::Identity;

pub mod routing;
pub mod onion;
pub mod circuit;

pub const MAX_HOPS: u8 = 8;
pub const ONION_LAYER_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshError {
    NoRoute,
    HopLimitExceeded,
    CircuitBroken,
    DecryptionFailed,
    RelayUnavailable,
}

pub type Result<T> = core::result::Result<T, MeshError>;

pub struct MeshNode {
    identity: Identity,
    routing_table: routing::RoutingTable,
    circuits: Vec<circuit::Circuit>,
}

impl MeshNode {
    pub fn new(identity: Identity) -> Self {
        MeshNode {
            identity,
            routing_table: routing::RoutingTable::new(),
            circuits: Vec::new(),
        }
    }

    pub fn route_message(&self, target: &Identity, data: &[u8]) -> Result<Vec<u8>> {
        // Find a circuit or create one. For Phase 0, we assume a direct route or stub route.
        // We will just build an onion packet with a single hop (the target) for simplicity,
        // or a simulated 3-hop route if we had one.
        // Since we don't have key exchange for the circuit yet, we use a zero key for the stub.
        let route = alloc::vec![*target];
        let keys = alloc::vec![[0u8; 32]];
        
        let packet = onion::OnionPacket::build(data, &route, &keys);
        Ok(packet.data)
    }
}
