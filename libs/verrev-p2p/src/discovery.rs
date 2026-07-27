use alloc::vec::Vec;
use crate::*;

pub struct Discovery {
    port: u16,
}

impl Discovery {
    pub fn new(port: u16) -> Self {
        Discovery { port }
    }

    pub fn start(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn discover_peers(&mut self) -> Result<Vec<PeerAddr>> {
        Ok(Vec::new())
    }

    pub fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}
