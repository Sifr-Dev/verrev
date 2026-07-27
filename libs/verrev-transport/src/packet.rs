use alloc::vec::Vec;
use crate::Result;
use crate::TransportError;

pub const PACKET_HEADER_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub connection_id: u64,
    pub packet_number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    Ack {
        largest_acked: u64,
        ack_delay: u64,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    Stream {
        id: u32,
        offset: u64,
        data: Vec<u8>,
    },
}

impl PacketHeader {
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < PACKET_HEADER_SIZE {
            return Err(TransportError::PacketTooLarge); // using this to mean buffer too small for now
        }
        out[0..8].copy_from_slice(&self.connection_id.to_be_bytes());
        out[8..16].copy_from_slice(&self.packet_number.to_be_bytes());
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < PACKET_HEADER_SIZE {
            return Err(TransportError::InvalidMessage);
        }
        let connection_id = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        let packet_number = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        Ok((PacketHeader { connection_id, packet_number }, PACKET_HEADER_SIZE))
    }
}

pub fn decode_frames(mut buf: &[u8]) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    while !buf.is_empty() {
        let frame_type = buf[0];
        match frame_type {
            0x00 => {
                let mut pad_len = 1;
                while pad_len < buf.len() && buf[pad_len] == 0x00 {
                    pad_len += 1;
                }
                frames.push(Frame::Padding(pad_len));
                buf = &buf[pad_len..];
            }
            0x02 => {
                if buf.len() < 17 {
                    return Err(TransportError::InvalidMessage);
                }
                let largest_acked = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                let ack_delay = u64::from_be_bytes(buf[9..17].try_into().unwrap());
                frames.push(Frame::Ack { largest_acked, ack_delay });
                buf = &buf[17..];
            }
            0x06 => {
                if buf.len() < 11 {
                    return Err(TransportError::InvalidMessage);
                }
                let offset = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                let length = u16::from_be_bytes(buf[9..11].try_into().unwrap()) as usize;
                if buf.len() < 11 + length {
                    return Err(TransportError::InvalidMessage);
                }
                let mut data = Vec::with_capacity(length);
                data.extend_from_slice(&buf[11..11 + length]);
                frames.push(Frame::Crypto { offset, data });
                buf = &buf[11 + length..];
            }
            0x08 => {
                if buf.len() < 15 {
                    return Err(TransportError::InvalidMessage);
                }
                let id = u32::from_be_bytes(buf[1..5].try_into().unwrap());
                let offset = u64::from_be_bytes(buf[5..13].try_into().unwrap());
                let length = u16::from_be_bytes(buf[13..15].try_into().unwrap()) as usize;
                if buf.len() < 15 + length {
                    return Err(TransportError::InvalidMessage);
                }
                let mut data = Vec::with_capacity(length);
                data.extend_from_slice(&buf[15..15 + length]);
                frames.push(Frame::Stream { id, offset, data });
                buf = &buf[15 + length..];
            }
            _ => return Err(TransportError::InvalidMessage),
        }
    }
    Ok(frames)
}

pub fn encode_frame(frame: &Frame, out: &mut Vec<u8>) {
    match frame {
        Frame::Padding(len) => {
            out.resize(out.len() + len, 0x00);
        }
        Frame::Ack { largest_acked, ack_delay } => {
            out.push(0x02);
            out.extend_from_slice(&largest_acked.to_be_bytes());
            out.extend_from_slice(&ack_delay.to_be_bytes());
        }
        Frame::Crypto { offset, data } => {
            out.push(0x06);
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        Frame::Stream { id, offset, data } => {
            out.push(0x08);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
    }
}
