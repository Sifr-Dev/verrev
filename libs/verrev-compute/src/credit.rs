use alloc::collections::BTreeSet;
use verrev_identity::Identity;

pub struct CreditCapability {
    pub issuer: Identity,
    pub holder: Identity,
    pub amount: u64,
    pub resource_type: ResourceType,
    pub serial: [u8; 32],
    pub expiration: u64,
}

pub enum ResourceType {
    Compute,
    Storage,
    Bandwidth,
    Relay,
}

pub struct CreditLedger {
    spent: BTreeSet<[u8; 32]>,
}

impl CreditLedger {
    pub fn new() -> Self {
        CreditLedger { spent: BTreeSet::new() }
    }

    pub fn is_spent(&self, serial: &[u8; 32]) -> bool {
        self.spent.contains(serial)
    }

    pub fn mark_spent(&mut self, serial: [u8; 32]) {
        self.spent.insert(serial);
    }
}

impl Default for CreditLedger {
    fn default() -> Self {
        Self::new()
    }
}
