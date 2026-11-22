#![no_std]

extern crate alloc;

pub mod kyber;
pub mod dilithium;
pub mod aead;
pub mod util;

#[cfg(test)]
mod gcm_vectors;
