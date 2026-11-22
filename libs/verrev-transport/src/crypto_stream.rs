use alloc::vec::Vec;
use alloc::collections::BTreeMap;


pub struct CryptoStream {
    send_buffer: Vec<u8>,
    send_offset: u64,
    recv_fragments: BTreeMap<u64, Vec<u8>>,
    recv_next_offset: u64,
}

impl CryptoStream {
    pub fn new() -> Self {
        CryptoStream {
            send_buffer: Vec::new(),
            send_offset: 0,
            recv_fragments: BTreeMap::new(),
            recv_next_offset: 0,
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.send_buffer.extend_from_slice(data);
    }

    /// Read data to send, starting from the given offset, up to max_len bytes.
    /// Returns the actual offset and data read.
    pub fn read_for_send(&self, max_len: usize) -> Option<(u64, Vec<u8>)> {
        let current_offset = self.send_offset as usize;
        if current_offset >= self.send_buffer.len() {
            return None; // Nothing more to send
        }
        let end = core::cmp::min(current_offset + max_len, self.send_buffer.len());
        let data = self.send_buffer[current_offset..end].to_vec();
        Some((current_offset as u64, data))
    }

    /// Mark data up to `offset` as successfully sent (acknowledged).
    pub fn mark_acked(&mut self, offset: u64) {
        if offset > self.send_offset {
            self.send_offset = offset;
        }
    }

    /// Receive incoming fragment
    pub fn receive(&mut self, offset: u64, data: Vec<u8>) {
        if offset >= self.recv_next_offset {
            self.recv_fragments.insert(offset, data);
        }
    }

    /// Extract continuous available data from the stream.
    pub fn extract_continuous(&mut self) -> Option<Vec<u8>> {
        let mut continuous_data = Vec::new();
        
        while let Some(data) = self.recv_fragments.remove(&self.recv_next_offset) {
            let len = data.len() as u64;
            continuous_data.extend(data);
            self.recv_next_offset += len;
        }
        
        if continuous_data.is_empty() {
            None
        } else {
            Some(continuous_data)
        }
    }
}

impl Default for CryptoStream {
    fn default() -> Self {
        Self::new()
    }
}
