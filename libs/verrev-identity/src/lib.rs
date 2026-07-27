#![no_std]

use verrev_crypto::dilithium;
use verrev_hash::sha3;

pub const IDENTITY_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Identity {
    id: [u8; IDENTITY_BYTES],
}

impl Identity {
    pub fn as_bytes(&self) -> &[u8; IDENTITY_BYTES] {
        &self.id
    }

    pub const fn from_bytes(id: [u8; IDENTITY_BYTES]) -> Self {
        Identity { id }
    }

    pub fn from_public_key(pk: &[u8; dilithium::PUBLIC_KEY_BYTES]) -> Self {
        let hash = sha3::sha3_256(pk);
        Identity { id: hash }
    }

    pub fn verify_identity(&self, pk: &[u8; dilithium::PUBLIC_KEY_BYTES]) -> bool {
        let computed = Self::from_public_key(pk);
        *self == computed
    }
}

#[derive(Debug, Clone)]
pub struct IdentityBundle {
    pub identity: Identity,
    pub public_key: [u8; dilithium::PUBLIC_KEY_BYTES],
    pub secret_key: [u8; dilithium::SECRET_KEY_BYTES],
}

impl IdentityBundle {
    pub fn generate() -> Self {
        let kp = dilithium::generate_keypair(None);
        let identity = Identity::from_public_key(&kp.public_key);
        IdentityBundle {
            identity,
            public_key: kp.public_key,
            secret_key: kp.secret_key,
        }
    }

    pub fn sign(&self, data: &[u8]) -> [u8; dilithium::SIGNATURE_BYTES] {
        dilithium::sign(&self.secret_key, data)
    }

    pub fn verify(&self, data: &[u8], sig: &[u8; dilithium::SIGNATURE_BYTES]) -> bool {
        dilithium::verify(&self.public_key, data, sig)
    }
}
