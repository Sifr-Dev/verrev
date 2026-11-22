#![no_std]

use verrev_hash::sha3;
use verrev_identity::Identity;

pub const CAPABILITY_HASH_SIZE: usize = 32;
pub const CUSTOM_RIGHTS_COUNT: u32 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityType {
    Read,
    Write,
    Execute,
    Admin,
    Custom(u32),
}

impl CapabilityType {
    fn right_bit(self) -> Option<u64> {
        match self {
            Self::Read => Some(1 << 0),
            Self::Write => Some(1 << 1),
            Self::Execute => Some(1 << 2),
            Self::Admin => Some(1 << 3),
            Self::Custom(index) if index < CUSTOM_RIGHTS_COUNT => Some(1 << (index + 4)),
            Self::Custom(_) => None,
        }
    }
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
    pub fn new(
        target: Identity,
        cap_type: CapabilityType,
        resource: &[u8],
        issuer: Identity,
    ) -> Self {
        let hash = sha3::sha3_256(resource);
        Capability {
            target,
            cap_type,
            resource_hash: hash,
            rights_mask: u64::MAX,
            issuer,
        }
    }

    pub fn check_access(&self, requested: CapabilityType) -> bool {
        requested
            .right_bit()
            .is_some_and(|bit| self.rights_mask & bit != 0)
    }

    pub fn delegate(&self, new_target: Identity, rights_mask: u64) -> Option<Capability> {
        let attenuated = self.rights_mask & rights_mask;
        if attenuated == 0 {
            return None;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(rights_mask: u64) -> Capability {
        let target = Identity::from_bytes([1; 32]);
        let issuer = Identity::from_bytes([2; 32]);
        Capability {
            rights_mask,
            ..Capability::new(target, CapabilityType::Read, b"resource", issuer)
        }
    }

    #[test]
    fn every_supported_custom_right_has_a_distinct_bit() {
        let cap = capability(u64::MAX);
        let mut represented = 0u64;

        for index in 0..CUSTOM_RIGHTS_COUNT {
            let bit = CapabilityType::Custom(index).right_bit();
            assert!(bit.is_some());
            let bit = bit.unwrap_or(0);
            assert_eq!(bit.count_ones(), 1);
            assert_eq!(represented & bit, 0, "custom right {index} aliases");
            assert!(cap.check_access(CapabilityType::Custom(index)));
            represented |= bit;
        }
        assert_eq!(represented, u64::MAX << 4);
    }

    #[test]
    fn out_of_range_custom_rights_never_alias_the_highest_bit() {
        let cap = capability(1 << 63);

        assert!(cap.check_access(CapabilityType::Custom(59)));
        for index in [60, 61, u32::MAX] {
            assert!(!cap.check_access(CapabilityType::Custom(index)));
        }
    }

    #[test]
    fn delegation_intersects_rights_and_cannot_escalate() {
        let cap = capability((1 << 0) | (1 << 63));
        let delegated = cap.delegate(Identity::from_bytes([3; 32]), u64::MAX);

        assert!(delegated.is_some());
        let delegated = delegated.unwrap_or(cap.revoke());
        assert_eq!(delegated.rights_mask, cap.rights_mask);
        assert!(delegated.check_access(CapabilityType::Read));
        assert!(!delegated.check_access(CapabilityType::Write));
        assert!(delegated.check_access(CapabilityType::Custom(59)));
        assert!(!delegated.check_access(CapabilityType::Custom(60)));
    }

    #[test]
    fn delegation_rejects_empty_or_non_overlapping_rights() {
        let cap = capability(1 << 0);
        let new_target = Identity::from_bytes([3; 32]);

        assert!(cap.delegate(new_target, 0).is_none());
        assert!(cap.delegate(new_target, 1 << 1).is_none());
        assert!(cap.revoke().delegate(new_target, u64::MAX).is_none());
    }
}
