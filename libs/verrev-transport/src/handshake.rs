use alloc::vec::Vec;
use crate::{Result, TransportError};
use verrev_identity::{Identity, IdentityBundle};
use verrev_crypto::{kyber, dilithium};
use verrev_hash::sha3::sha3_256;

const MESSAGE_SIZE: usize = kyber::PUBLIC_KEY_BYTES + dilithium::PUBLIC_KEY_BYTES + dilithium::SIGNATURE_BYTES;

pub struct Handshake {
    state: HandshakeState,
    local_identity: IdentityBundle,
    remote_identity: Option<Identity>,
    session_key: Option<[u8; 32]>,
}

struct ClientWait {
    kyber_sk: [u8; kyber::SECRET_KEY_BYTES],
    kyber_pk: [u8; kyber::PUBLIC_KEY_BYTES],
}

enum HandshakeState {
    /// Client: send Kyber PK + Dilithium PK + Sig
    ClientHello,
    /// Server: Wait for ClientHello, then respond with Kyber CT + Dilithium PK + Sig
    ServerWait,
    /// Client: Wait for ServerResponse
    ClientWait(alloc::boxed::Box<ClientWait>),
    /// Both: Established
    Established,
}

impl Handshake {
    pub fn new_initiator(identity: IdentityBundle) -> Self {
        Handshake {
            state: HandshakeState::ClientHello,
            local_identity: identity,
            remote_identity: None,
            session_key: None,
        }
    }

    pub fn new_responder(identity: IdentityBundle) -> Self {
        Handshake {
            state: HandshakeState::ServerWait,
            local_identity: identity,
            remote_identity: None,
            session_key: None,
        }
    }

    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        match &self.state {
            HandshakeState::ClientHello => {
                let (kyber_sk, kyber_pk) = kyber::ccakem_keygen(None);
                let sig = self.local_identity.sign(&kyber_pk);
                
                let mut msg = Vec::with_capacity(MESSAGE_SIZE);
                msg.extend_from_slice(&kyber_pk);
                msg.extend_from_slice(&self.local_identity.public_key);
                msg.extend_from_slice(&sig);

                self.state = HandshakeState::ClientWait(alloc::boxed::Box::new(ClientWait {
                    kyber_sk,
                    kyber_pk,
                }));
                Some(msg)
            }
            _ => None,
        }
    }

    pub fn receive_message(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>> {
        if msg.len() != MESSAGE_SIZE {
            return Err(TransportError::InvalidMessage);
        }

        match &self.state {
            HandshakeState::ServerWait => {
                let mut kyber_pk = [0u8; kyber::PUBLIC_KEY_BYTES];
                kyber_pk.copy_from_slice(&msg[..kyber::PUBLIC_KEY_BYTES]);
                
                let pk_offset = kyber::PUBLIC_KEY_BYTES;
                let mut remote_dilithium_pk = [0u8; dilithium::PUBLIC_KEY_BYTES];
                remote_dilithium_pk.copy_from_slice(&msg[pk_offset..pk_offset + dilithium::PUBLIC_KEY_BYTES]);
                
                let sig_offset = pk_offset + dilithium::PUBLIC_KEY_BYTES;
                let mut sig = [0u8; dilithium::SIGNATURE_BYTES];
                sig.copy_from_slice(&msg[sig_offset..]);

                if !dilithium::verify(&remote_dilithium_pk, &kyber_pk, &sig) {
                    return Err(TransportError::InvalidSignature);
                }

                let remote_id = Identity::from_public_key(&remote_dilithium_pk);
                self.remote_identity = Some(remote_id);

                let (ct, ss) = kyber::ccakem_encaps(&kyber_pk);
                
                let mut to_sign = Vec::with_capacity(kyber::CIPHERTEXT_BYTES + kyber::PUBLIC_KEY_BYTES);
                to_sign.extend_from_slice(&ct);
                to_sign.extend_from_slice(&kyber_pk);
                let my_sig = self.local_identity.sign(&to_sign);

                let mut out_msg = Vec::with_capacity(MESSAGE_SIZE);
                out_msg.extend_from_slice(&ct);
                out_msg.extend_from_slice(&self.local_identity.public_key);
                out_msg.extend_from_slice(&my_sig);

                let mut kdf_input = [0u8; 64];
                kdf_input[..32].copy_from_slice(&ss);
                kdf_input[32..].copy_from_slice(b"verrev-session-v1-00000000000000"); // Pad to 32
                self.session_key = Some(sha3_256(&kdf_input));

                self.state = HandshakeState::Established;
                Ok(Some(out_msg))
            }
            HandshakeState::ClientWait(wait) => {
                let ClientWait { kyber_sk, kyber_pk } = wait.as_ref();
                let mut ct = [0u8; kyber::CIPHERTEXT_BYTES];
                ct.copy_from_slice(&msg[..kyber::CIPHERTEXT_BYTES]);

                let pk_offset = kyber::CIPHERTEXT_BYTES;
                let mut remote_dilithium_pk = [0u8; dilithium::PUBLIC_KEY_BYTES];
                remote_dilithium_pk.copy_from_slice(&msg[pk_offset..pk_offset + dilithium::PUBLIC_KEY_BYTES]);

                let sig_offset = pk_offset + dilithium::PUBLIC_KEY_BYTES;
                let mut sig = [0u8; dilithium::SIGNATURE_BYTES];
                sig.copy_from_slice(&msg[sig_offset..]);

                let mut to_verify = Vec::with_capacity(kyber::CIPHERTEXT_BYTES + kyber::PUBLIC_KEY_BYTES);
                to_verify.extend_from_slice(&ct);
                to_verify.extend_from_slice(kyber_pk);

                if !dilithium::verify(&remote_dilithium_pk, &to_verify, &sig) {
                    return Err(TransportError::InvalidSignature);
                }

                let remote_id = Identity::from_public_key(&remote_dilithium_pk);
                self.remote_identity = Some(remote_id);

                let ss = kyber::ccakem_decaps(kyber_sk, &ct);

                let mut kdf_input = [0u8; 64];
                kdf_input[..32].copy_from_slice(&ss);
                kdf_input[32..].copy_from_slice(b"verrev-session-v1-00000000000000"); // Pad to 32
                self.session_key = Some(sha3_256(&kdf_input));

                self.state = HandshakeState::Established;
                Ok(None)
            }
            _ => Err(TransportError::InvalidState),
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Established)
    }

    pub fn session_key(&self) -> Result<[u8; 32]> {
        self.session_key.ok_or(TransportError::InvalidState)
    }

    pub fn remote_identity(&self) -> Option<Identity> {
        self.remote_identity
    }
}
