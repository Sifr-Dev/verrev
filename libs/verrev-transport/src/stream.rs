use crate::*;
use crate::channel::EncryptedChannel;

pub struct Stream {
    id: u32,
    channel: EncryptedChannel,
    closed: bool,
}

impl Stream {
    pub fn new(channel: EncryptedChannel, id: u32) -> Self {
        Stream { id, channel, closed: false }
    }

    pub fn send(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.closed {
            return Err(TransportError::StreamClosed);
        }
        self.channel.encrypt(data, out)
    }

    pub fn recv(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.closed {
            return Err(TransportError::StreamClosed);
        }
        self.channel.decrypt(packet, out)
    }

    pub fn close(&mut self) -> Result<()> {
        self.closed = true;
        Ok(())
    }
    
    pub fn id(&self) -> u32 {
        self.id
    }
}
