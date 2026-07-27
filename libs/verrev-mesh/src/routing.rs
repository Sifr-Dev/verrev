use alloc::vec::Vec;
use verrev_identity::Identity;

pub struct RoutingTable {
    entries: Vec<RouteEntry>,
}

struct RouteEntry {
    target: Identity,
    next_hop: Identity,
    latency_ms: u32,
    hop_count: u8,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable { entries: Vec::new() }
    }

    pub fn add_route(&mut self, target: Identity, next_hop: Identity, latency_ms: u32, hop_count: u8) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.target == target) {
            existing.next_hop = next_hop;
            existing.latency_ms = latency_ms;
            existing.hop_count = hop_count;
        } else {
            self.entries.push(RouteEntry { target, next_hop, latency_ms, hop_count });
        }
    }

    pub fn next_hop(&self, target: &Identity) -> Option<Identity> {
        self.entries.iter().find(|e| e.target == *target).map(|e| e.next_hop)
    }
}
