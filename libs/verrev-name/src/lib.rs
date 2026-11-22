#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_identity::Identity;

pub const MAX_NAME_LENGTH: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    NameTooLong,
    NameAlreadyRegistered,
    ResolutionFailed,
    SignatureInvalid,
}

pub type Result<T> = core::result::Result<T, NameError>;

#[derive(Debug, Clone)]
pub struct NameRecord {
    pub name: Vec<u8>,
    pub target: Identity,
    pub registrar: Identity,
    pub signature: [u8; verrev_crypto::dilithium::SIGNATURE_BYTES],
    pub expires_at: u64,
}

pub struct NameResolver {
    records: alloc::collections::BTreeMap<alloc::string::String, NameRecord>,
}

impl NameResolver {
    pub fn new() -> Self {
        NameResolver {
            records: alloc::collections::BTreeMap::new(),
        }
    }

    pub fn resolve(&self, name: &str) -> Result<Identity> {
        if let Some(record) = self.records.get(name) {
            let now = verrev_syscall::linux::now_nanos().unwrap_or(0) / 1_000_000_000;
            if record.expires_at > now {
                return Ok(record.target);
            }
        }
        Err(NameError::ResolutionFailed)
    }

    pub fn register(&mut self, name: &str, target: &Identity, registrar: &Identity) -> Result<NameRecord> {
        if name.len() > MAX_NAME_LENGTH {
            return Err(NameError::NameTooLong);
        }
        
        let now = verrev_syscall::linux::now_nanos().unwrap_or(0) / 1_000_000_000;
        let expires_at = now + 86400; // 1 day validity
        
        // For Phase 0, we don't actually sign, we just create a dummy signature
        let record = NameRecord {
            name: name.as_bytes().to_vec(),
            target: *target,
            registrar: *registrar,
            signature: [0u8; verrev_crypto::dilithium::SIGNATURE_BYTES],
            expires_at,
        };
        
        self.records.insert(alloc::string::String::from(name), record.clone());
        
        Ok(record)
    }
}

impl Default for NameResolver {
    fn default() -> Self {
        Self::new()
    }
}
