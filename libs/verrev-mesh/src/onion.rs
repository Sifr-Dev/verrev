use alloc::vec::Vec;
use verrev_crypto::aead::XChaCha20Poly1305;
use verrev_identity::Identity;
use crate::{MeshError, Result};

pub struct OnionPacket {
    pub data: Vec<u8>,
}

impl OnionPacket {
    /// Builds an onion packet from the inside out.
    /// `route` is ordered from first hop to last hop (destination).
    /// `keys` must correspond 1:1 with `route`.
    pub fn build(payload: &[u8], route: &[Identity], keys: &[[u8; 32]]) -> Result<Self> {
        let mut current_payload = payload.to_vec();
        
        // Traverse backwards: from destination to first hop
        for (i, _hop) in route.iter().rev().enumerate() {
            let key = &keys[keys.len() - 1 - i];
            let cipher = XChaCha20Poly1305::new(key);
            
            // For the destination (i=0 in rev), next_hop is all zeros.
            // For intermediate hops, next_hop is the previous one we processed.
            let next_hop = if i == 0 {
                [0u8; 32] // Zero indicates final destination
            } else {
                let prev_hop = &route[route.len() - i];
                *prev_hop.as_bytes()
            };
            
            let mut plaintext = Vec::with_capacity(32 + current_payload.len());
            plaintext.extend_from_slice(&next_hop);
            plaintext.extend_from_slice(&current_payload);
            
            // Encrypt
            let nonce = verrev_crypto::util::random_u64()
                .map_err(|_| MeshError::EncryptionFailed)?
                .to_le_bytes(); // Use 8 bytes random, pad to 24
            let mut full_nonce = [0u8; 24];
            full_nonce[0..8].copy_from_slice(&nonce);
            
            let mut ciphertext = alloc::vec![0u8; plaintext.len()];
            let tag = cipher.encrypt(&full_nonce, &[], &plaintext, &mut ciphertext);
            
            // Layer format: [Nonce (24)] || [Tag (16)] || [Ciphertext]
            let mut layer = Vec::with_capacity(24 + 16 + ciphertext.len());
            layer.extend_from_slice(&full_nonce);
            layer.extend_from_slice(&tag);
            layer.extend_from_slice(&ciphertext);
            
            current_payload = layer;
        }
        
        Ok(OnionPacket { data: current_payload })
    }

    /// Peels one layer of the onion.
    /// Returns (Next Hop, Inner Data). If next hop is all zeros, this node is the final destination.
    pub fn peel(&self, key: &[u8; 32]) -> Result<(Identity, Vec<u8>)> {
        if self.data.len() < 24 + 32 + 16 {
            return Err(MeshError::DecryptionFailed);
        }
        
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&self.data[0..24]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&self.data[24..40]);
        let ciphertext = &self.data[40..];
        
        let cipher = XChaCha20Poly1305::new(key);
        let mut plaintext = alloc::vec![0u8; ciphertext.len()];
        if !cipher.decrypt(&nonce, &[], ciphertext, &tag, &mut plaintext) {
            return Err(MeshError::DecryptionFailed);
        }
        
        if plaintext.len() < 32 {
            return Err(MeshError::DecryptionFailed);
        }
        
        let mut next_hop_bytes = [0u8; 32];
        next_hop_bytes.copy_from_slice(&plaintext[0..32]);
        let next_hop = Identity::from_bytes(next_hop_bytes);
        
        let inner_data = plaintext[32..].to_vec();
        
        Ok((next_hop, inner_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(seed: u8) -> Identity {
        let mut b = [0u8; 32];
        b[0] = seed;
        Identity::from_bytes(b)
    }

    #[test]
    fn test_onion_build_and_peel() {
        let payload = b"Hello, world!";
        let r1 = make_identity(1);
        let r2 = make_identity(2);
        let r3 = make_identity(3); // destination
        
        let route = alloc::vec![r1, r2, r3];
        
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let key3 = [3u8; 32];
        let keys = alloc::vec![key1, key2, key3];
        
        let onion = OnionPacket::build(payload, &route, &keys).unwrap();
        
        // Node 1 peels
        let (next_hop1, inner1) = onion.peel(&key1).unwrap();
        assert_eq!(next_hop1, r2);
        
        // Node 2 peels
        let onion2 = OnionPacket { data: inner1 };
        let (next_hop2, inner2) = onion2.peel(&key2).unwrap();
        assert_eq!(next_hop2, r3);
        
        // Node 3 (dest) peels
        let onion3 = OnionPacket { data: inner2 };
        let (next_hop3, inner3) = onion3.peel(&key3).unwrap();
        assert_eq!(next_hop3, Identity::from_bytes([0u8; 32]));
        assert_eq!(inner3, payload);
    }
}
