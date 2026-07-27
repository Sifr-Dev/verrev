#![no_std]

extern crate alloc;

pub mod channel;
pub mod connection;
pub mod crypto_stream;
pub mod endpoint;
pub mod handshake;
pub mod packet;
pub mod stream;
pub mod udp;

pub const MAX_PACKET_SIZE: usize = 1500;
pub const MAX_STREAMS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    HandshakeFailed,
    DecryptionFailed,
    StreamClosed,
    ConnectionLost,
    PacketTooLarge,
    InvalidState,
    InvalidSignature,
    InvalidMessage,
    WouldBlock,
}

pub type Result<T> = core::result::Result<T, TransportError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerAddr {
    pub ip: [u8; 16],
    pub port: u16,
}
