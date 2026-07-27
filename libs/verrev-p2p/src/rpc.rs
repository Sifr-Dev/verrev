use alloc::vec::Vec;
use verrev_identity::Identity;
use crate::PeerInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcMessage {
    Ping,
    Pong,
    FindNode { target: Identity },
    FindNodeReply { nodes: Vec<PeerInfo> },
}

impl RpcMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            RpcMessage::Ping => {
                buf.push(0);
            }
            RpcMessage::Pong => {
                buf.push(1);
            }
            RpcMessage::FindNode { target } => {
                buf.push(2);
                buf.extend_from_slice(target.as_bytes());
            }
            RpcMessage::FindNodeReply { nodes } => {
                buf.push(3);
                buf.push(nodes.len() as u8);
                for node in nodes {
                    buf.extend_from_slice(node.identity.as_bytes());
                    buf.push(node.addrs.len() as u8);
                    for addr in &node.addrs {
                        buf.extend_from_slice(&addr.ip);
                        buf.extend_from_slice(&addr.port.to_be_bytes());
                    }
                }
            }
        }
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() { return None; }
        match buf[0] {
            0 => Some(RpcMessage::Ping),
            1 => Some(RpcMessage::Pong),
            2 => {
                if buf.len() < 33 { return None; }
                let mut target = [0u8; 32];
                target.copy_from_slice(&buf[1..33]);
                Some(RpcMessage::FindNode { target: Identity::from_bytes(target) })
            }
            3 => {
                if buf.len() < 2 { return None; }
                let count = buf[1] as usize;
                let mut nodes = Vec::with_capacity(count);
                let mut offset = 2;
                for _ in 0..count {
                    if offset + 32 + 1 > buf.len() { return None; }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&buf[offset..offset+32]);
                    offset += 32;
                    let addrs_len = buf[offset] as usize;
                    offset += 1;
                    
                    let mut addrs = Vec::with_capacity(addrs_len);
                    for _ in 0..addrs_len {
                        if offset + 18 > buf.len() { return None; }
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(&buf[offset..offset+16]);
                        offset += 16;
                        let port = u16::from_be_bytes([buf[offset], buf[offset+1]]);
                        offset += 2;
                        addrs.push(verrev_transport::PeerAddr { ip, port });
                    }
                    
                    nodes.push(PeerInfo {
                        identity: Identity::from_bytes(id),
                        addrs,
                        distance: [0u8; 32],
                    });
                }
                Some(RpcMessage::FindNodeReply { nodes })
            }
            _ => None,
        }
    }
}
