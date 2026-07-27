#![no_std]

use verrev_hash::sha3;
use verrev_identity::Identity;

pub const CAPABILITY_HASH_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityType {
    Read,
    Write,
    Execute,
    Admin,
    Custom(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub target: Identity,
    pub cap_type: CapabilityType,
    pub resource_hash: [u8; CAPABILITY_HASH_SIZE],
    pub rights_mask: u64,
    pub issuer: Identity,
}

impl Capability {
    pub fn new(target: Identity, cap_type: CapabilityType, resource: &[u8], issuer: Identity) -> Self {
        let hash = sha3::sha3_256(resource);
        Capability {
            target,
            cap_type,
            resource_hash: hash,
            rights_mask: 0xFFFF_FFFF_FFFF_FFFF,
            issuer,
        }
    }

    pub fn check_access(&self, requested: CapabilityType) -> bool {
        let requested_bit = match requested {
            CapabilityType::Read => 1u64 << 0,
            CapabilityType::Write => 1u64 << 1,
            CapabilityType::Execute => 1u64 << 2,
            CapabilityType::Admin => 1u64 << 3,
            CapabilityType::Custom(c) => 1u64.checked_shl(4 + c.min(59)).unwrap_or(0),
        };
        (self.rights_mask & requested_bit) != 0
    }

    pub fn delegate(&self, new_target: Identity, rights_mask: u64) -> Option<Capability> {
        let attenuated = self.rights_mask & rights_mask;
        Some(Capability {
            target: new_target,
            cap_type: self.cap_type,
            resource_hash: self.resource_hash,
            rights_mask: attenuated,
            issuer: self.issuer,
        })
    }

    pub fn revoke(&self) -> Capability {
        Capability {
            target: self.target,
            cap_type: self.cap_type,
            resource_hash: self.resource_hash,
            rights_mask: 0,
            issuer: self.issuer,
        }
    }
}
