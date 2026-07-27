use crate::Result;
use crate::TransportError;

pub struct EncryptedChannel {
    key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
}

impl EncryptedChannel {
    pub fn new(session_key: [u8; 32]) -> Self {
        EncryptedChannel {
            key: session_key,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&self.send_nonce.to_le_bytes());
        let aead = verrev_crypto::aead::XChaCha20Poly1305::new(&self.key);
        
        let tag = aead.encrypt(&nonce, &[], plaintext, &mut out[24..]);
        out[..24].copy_from_slice(&nonce);
        out[24 + plaintext.len()..24 + plaintext.len() + 16].copy_from_slice(&tag);
        
        self.send_nonce += 1;
        Ok(24 + plaintext.len() + 16)
    }

    pub fn decrypt(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        if packet.len() < 40 {
            return Err(TransportError::InvalidMessage);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&packet[..24]);
        
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&packet[packet.len() - 16..]);
        
        let ct = &packet[24..packet.len() - 16];
        let aead = verrev_crypto::aead::XChaCha20Poly1305::new(&self.key);
        
        if !aead.decrypt(&nonce, &[], ct, &tag, out) {
            return Err(TransportError::DecryptionFailed);
        }
        
        self.recv_nonce += 1;
        Ok(ct.len())
    }
}
