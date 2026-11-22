#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_identity::Identity;
use verrev_transport::PeerAddr;

pub mod dht;
pub mod discovery;
pub mod nat;
pub mod rpc;

pub const K: usize = 20; // Kademlia bucket size
pub const ALPHA: usize = 3; // Parallel lookups

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2PError {
    PeerNotFound,
    RoutingFailed,
    NATTraversalFailed,
    TransportError,
}

pub type Result<T> = core::result::Result<T, P2PError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerInfo {
    pub identity: Identity,
    pub addrs: Vec<PeerAddr>,
    pub distance: [u8; 32],
}

use verrev_transport::endpoint::Endpoint;
use verrev_identity::IdentityBundle;

pub struct P2PNode {
    identity_bundle: IdentityBundle,
    endpoint: Endpoint,
    routing_table: dht::RoutingTable,
}

impl P2PNode {
    pub fn new(identity_bundle: IdentityBundle, port: u16) -> Result<Self> {
        let endpoint = Endpoint::new(port, identity_bundle.clone())
            .map_err(|_| P2PError::TransportError)?;
        
        Ok(P2PNode {
            routing_table: dht::RoutingTable::new(identity_bundle.identity),
            identity_bundle,
            endpoint,
        })
    }

    pub fn identity(&self) -> Identity {
        self.identity_bundle.identity
    }

    pub fn bootstrap(&mut self, seeds: &[PeerAddr]) -> Result<()> {
        for seed in seeds {
            if let Ok(_conn_id) = self.endpoint.connect(seed.ip, seed.port) {
                // Connection initiated. We must poll to complete the handshake.
            }
        }
        Ok(())
    }

    pub fn find_peer(&mut self, target: &Identity) -> Result<PeerInfo> {
        // Local lookup
        let mut closest = self.routing_table.find_closest(target, 1);
        if closest.first().map(|p| &p.identity) == Some(target) {
            return Ok(closest.remove(0));
        }
        
        // P2P DHT Lookup (stubbed block for Kademlia logic)
        let alpha = self.routing_table.find_closest(target, ALPHA);
        if alpha.is_empty() {
            return Err(P2PError::PeerNotFound);
        }

        // We would connect and send FindNode RPCs to alpha nodes here.
        Err(P2PError::PeerNotFound)
    }

    pub fn connect(&mut self, target: &Identity) -> Result<u64> {
        let peer = self.find_peer(target)?;
        if let Some(addr) = peer.addrs.first() {
            let conn_id = self.endpoint.connect(addr.ip, addr.port)
                .map_err(|_| P2PError::TransportError)?;
            return Ok(conn_id);
        }
        Err(P2PError::PeerNotFound)
    }

    pub fn poll(&mut self) -> Result<()> {
        let _ = self.endpoint.poll();
        
        // Read incoming RPC messages from established connections
        // Note: iter_mut is not trivial on BTreeMap, so we collect IDs first.
        let conn_ids: Vec<u64> = self.endpoint.connections.keys().copied().collect();
        for id in conn_ids {
            if let Some(conn) = self.endpoint.connections.get_mut(&id)
                && conn.state == verrev_transport::connection::ConnectionState::Established {
                    let msgs = conn.receive_messages();
                    for msg in msgs {
                        if let Some(rpc) = rpc::RpcMessage::decode(&msg) {
                            self.handle_rpc(id, rpc);
                        }
                    }
                }
        }
        Ok(())
    }
    
    fn handle_rpc(&mut self, conn_id: u64, msg: rpc::RpcMessage) {
        match msg {
            rpc::RpcMessage::Ping => {
                if let Some(conn) = self.endpoint.connections.get_mut(&conn_id) {
                    let _ = conn.send_message(&rpc::RpcMessage::Pong.encode());
                }
            }
            rpc::RpcMessage::Pong => {
                // Handled in routing layer (mark peer active)
            }
            rpc::RpcMessage::FindNode { target } => {
                let closest = self.routing_table.find_closest(&target, K);
                if let Some(conn) = self.endpoint.connections.get_mut(&conn_id) {
                    let reply = rpc::RpcMessage::FindNodeReply { nodes: closest };
                    let _ = conn.send_message(&reply.encode());
                }
            }
            rpc::RpcMessage::FindNodeReply { nodes } => {
                for node in nodes {
                    self.routing_table.insert(node);
                }
            }
        }
    }
}
