use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub struct MessageQueue {
    messages: VecDeque<Vec<u8>>,
}

impl MessageQueue {
    pub fn new() -> Self {
        MessageQueue { messages: VecDeque::new() }
    }

    pub fn push(&mut self, data: &[u8]) -> super::Result<()> {
        self.messages.push_back(data.to_vec());
        Ok(())
    }

    pub fn pop(&mut self) -> super::Result<Vec<u8>> {
        self.messages.pop_front().ok_or(super::DbError::NotFound)
    }
}
