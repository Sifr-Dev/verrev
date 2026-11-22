use alloc::vec::Vec;
use verrev_identity::IdentityBundle;
use crate::Result;
use crate::TransportError;
use crate::handshake::Handshake;
use crate::channel::EncryptedChannel;
use crate::crypto_stream::CryptoStream;
use crate::packet::{PacketHeader, Frame, decode_frames, encode_frame};

#[derive(Debug, PartialEq)]
pub enum ConnectionState {
    Initial,
    Handshaking,
    Established,
    Closed,
}

pub struct Connection {
    pub id: u64,
    pub state: ConnectionState,
    pub local_identity: IdentityBundle,
    pub remote_identity: Option<verrev_identity::Identity>,
    handshake: Handshake,
    crypto_stream: CryptoStream,
    channel: Option<EncryptedChannel>,
    next_packet_number: u64,
    highest_recv_packet: u64,
    handshake_buf: alloc::vec::Vec<u8>,
    is_initiator: bool,
    send_queue: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    recv_queue: alloc::vec::Vec<alloc::vec::Vec<u8>>,
}

impl Connection {
    pub fn new_initiator(id: u64, local_identity: IdentityBundle) -> Self {
        let mut handshake = Handshake::new_initiator(local_identity.clone());
        let mut crypto_stream = CryptoStream::new();
        
        // Initiator writes the first message immediately
        if let Some(msg) = handshake.next_message() {
            crypto_stream.write(&msg);
        }

        Connection {
            id,
            state: ConnectionState::Handshaking,
            local_identity,
            remote_identity: None,
            handshake,
            crypto_stream,
            next_packet_number: 1,
            highest_recv_packet: 0,
            channel: None,
            handshake_buf: alloc::vec::Vec::new(),
            is_initiator: true,
            send_queue: alloc::vec::Vec::new(),
            recv_queue: alloc::vec::Vec::new(),
        }
    }

    pub fn new_responder(id: u64, local_identity: IdentityBundle) -> Self {
        Connection {
            id,
            state: ConnectionState::Initial,
            local_identity: local_identity.clone(),
            remote_identity: None,
            handshake: Handshake::new_responder(local_identity),
            crypto_stream: CryptoStream::new(),
            next_packet_number: 1,
            highest_recv_packet: 0,
            channel: None,
            handshake_buf: alloc::vec::Vec::new(),
            is_initiator: false,
            send_queue: alloc::vec::Vec::new(),
            recv_queue: alloc::vec::Vec::new(),
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub fn send_message(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != ConnectionState::Established {
            return Err(TransportError::InvalidState);
        }
        self.send_queue.push(msg.to_vec());
        Ok(())
    }

    pub fn receive_messages(&mut self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut msgs = alloc::vec::Vec::new();
        core::mem::swap(&mut msgs, &mut self.recv_queue);
        msgs
    }

    pub fn handle_packet(&mut self, payload: &[u8]) -> Result<()> {
        let (header, header_len) = PacketHeader::decode(payload)?;
        if header.packet_number > self.highest_recv_packet {
            self.highest_recv_packet = header.packet_number;
        }
        
        let frames_data = &payload[header_len..];

        match self.state {
            ConnectionState::Initial | ConnectionState::Handshaking => {
                // Parse frames unencrypted
                let frames = decode_frames(frames_data)?;
                self.process_frames(frames)?;
            }
            ConnectionState::Established => {
                // Parse frames encrypted
                if let Some(channel) = &mut self.channel {
                    let mut plaintext = alloc::vec![0u8; frames_data.len()];
                    let len = channel.decrypt(frames_data, &mut plaintext)?;
                    let frames = decode_frames(&plaintext[..len])?;
                    self.process_frames(frames)?;
                }
            }
            ConnectionState::Closed => return Err(TransportError::ConnectionLost),
        }

        Ok(())
    }

    fn process_frames(&mut self, frames: Vec<Frame>) -> Result<()> {
        for frame in frames {
            match frame {
                Frame::Ack { .. } => {
                    // Very basic ACK handling for Phase 1. 
                    // In a real implementation we track offsets tied to packet numbers.
                    // Here we'll just optimistically advance the send buffer if handshake finishes.
                }
                Frame::Crypto { offset, data } => {
                    self.crypto_stream.receive(offset, data);
                    
                    if let Some(msg) = self.crypto_stream.extract_continuous() {
                        self.handshake_buf.extend(msg);
                        
                        let expected_len = 8787;
                        
                        if self.handshake_buf.len() >= expected_len {
                            let msg_to_process = self.handshake_buf.drain(..expected_len).collect::<Vec<u8>>();
                            
                            if self.state == ConnectionState::Initial {
                                self.state = ConnectionState::Handshaking;
                            }
                            
                            // Feed message to handshake
                            let res = self.handshake.receive_message(&msg_to_process);
                            if let Ok(Some(reply)) = res {
                                self.crypto_stream.write(&reply);
                            } else if let Err(e) = res {
                                panic!("Handshake error: {:?}", e);
                            }
                            
                            // Check if handshake is complete
                            if self.handshake.is_complete() {
                                self.state = ConnectionState::Established;
                                self.remote_identity = self.handshake.remote_identity();
                                if let Ok(key) = self.handshake.session_key() {
                                    self.channel = Some(EncryptedChannel::new(key));
                                }
                            }
                        }
                    }
                }
                Frame::Stream { id: _, offset: _, data } => {
                    if let Some(channel) = &mut self.channel {
                        let mut out = alloc::vec![0u8; data.len()];
                        if let Ok(len) = channel.decrypt(&data, &mut out) {
                            out.truncate(len);
                            self.recv_queue.push(out);
                        }
                    }
                }
                Frame::Padding(_) => {}
            }
        }
        Ok(())
    }

    pub fn generate_packets(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        
        // Always try to send pending handshake/crypto data first
        while let Some((offset, data)) = self.crypto_stream.read_for_send(1200) {
            let mut packet = alloc::vec![0u8; crate::packet::PACKET_HEADER_SIZE];
            let header = PacketHeader {
                connection_id: self.id,
                packet_number: self.next_packet_number,
            };
            header.encode(&mut packet)?;
            self.next_packet_number += 1;
            
            let frame = Frame::Crypto { offset, data: data.clone() };
            encode_frame(&frame, &mut packet);
            packets.push(packet);
            
            // For now, immediately mark as acked (optimistic)
            self.crypto_stream.mark_acked(offset + data.len() as u64);
        }
        
        match self.state {
            ConnectionState::Initial | ConnectionState::Handshaking => {
                // Crypto packets are already generated above.
            }
            ConnectionState::Established => {
                if let Some(channel) = &mut self.channel {
                    let mut msgs = alloc::vec::Vec::new();
                    core::mem::swap(&mut msgs, &mut self.send_queue);
                    
                    for msg in msgs {
                        // Max encrypted size is msg.len() + 16 (Poly1305 tag)
                        let mut out = alloc::vec![0u8; msg.len() + 16];
                        if let Ok(len) = channel.encrypt(&msg, &mut out) {
                            out.truncate(len);
                            
                            // Fragment into 1200 byte frames if needed (stubbed for simple cases)
                            // For RPC messages, they are tiny (Ping/Pong/FindNode are < 100 bytes).
                            // Only FindNodeReply with many peers can be large.
                            // We will assume they fit in one frame for Phase 0.
                            
                            let frame = Frame::Stream {
                                id: 1, // Single stream for RPC
                                offset: 0, // No proper offset tracking yet
                                data: out,
                            };
                            
                            let mut packet = alloc::vec![0u8; crate::packet::PACKET_HEADER_SIZE];
                            let header = PacketHeader {
                                connection_id: self.id,
                                packet_number: self.next_packet_number,
                            };
                            header.encode(&mut packet)?;
                            self.next_packet_number += 1;
                            
                            encode_frame(&frame, &mut packet);
                            packets.push(packet);
                        }
                    }
                }
            }
            ConnectionState::Closed => {}
        }
        
        Ok(packets)
    }
}
