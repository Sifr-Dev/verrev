
use alloc::collections::BTreeMap;
use crate::Result;
use crate::connection::Connection;
use crate::udp::UdpSocket;
use verrev_identity::IdentityBundle;

pub struct Endpoint {
    socket: UdpSocket,
    local_identity: IdentityBundle,
    pub connections: BTreeMap<u64, Connection>,
    next_connection_id: u64,
}

impl Endpoint {
    pub fn new(port: u16, local_identity: IdentityBundle) -> Result<Self> {
        let socket = UdpSocket::bind(port)?;
        Ok(Endpoint {
            socket,
            local_identity,
            connections: BTreeMap::new(),
            next_connection_id: 1,
        })
    }

    pub fn connect(&mut self, peer_ip: [u8; 16], peer_port: u16) -> Result<u64> {
        let conn_id = self.next_connection_id;
        self.next_connection_id += 1;
        
        let conn = Connection::new_initiator(conn_id, self.local_identity.clone());
        self.connections.insert(conn_id, conn);
        
        // Immediately trigger generation of packets for the new connection
        self.flush_connection(conn_id, &peer_ip, peer_port)?;
        
        Ok(conn_id)
    }

    pub fn poll(&mut self) -> Result<()> {
        let mut buf = alloc::vec![0u8; 65535];
        
        while let Ok((size, peer_ip, peer_port)) = self.socket.recv_from(&mut buf) {
            let data = &buf[..size];
            // alloc::println!("Endpoint on port {} received {} bytes from port {}", self.socket.local_port(), size, peer_port);
            
            // Peak at header to get connection ID
            if let Ok((header, _)) = crate::packet::PacketHeader::decode(data) {
                let conn_id = header.connection_id;
                
                if !self.connections.contains_key(&conn_id) {
                    // Incoming new connection (Responder)
                    let new_conn = Connection::new_responder(conn_id, self.local_identity.clone());
                    self.connections.insert(conn_id, new_conn);
                }
                
                if let Some(conn) = self.connections.get_mut(&conn_id)
                    && conn.handle_packet(data).is_ok() {
                        // After handling, it might have new packets to send back
                    }
                
                self.flush_connection(conn_id, &peer_ip, peer_port)?;
            }
        }
        
        Ok(())
    }

    fn flush_connection(&mut self, conn_id: u64, peer_ip: &[u8; 16], peer_port: u16) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&conn_id) {
            let packets = conn.generate_packets()?;
            for packet in packets {
                let _ = self.socket.send_to(&packet, peer_ip, peer_port);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_handshake_over_udp() {
        let id_a = IdentityBundle::generate();
        let id_b = IdentityBundle::generate();
        
        let _endpoint_a = Endpoint::new(0, id_a).unwrap(); // Port 0 for random ephemeral port
        let _endpoint_b = Endpoint::new(0, id_b).unwrap();
        
        // Actually since we can't easily get the ephemeral port from verrev_syscall right now,
        // we'll hardcode high ports for the test.
        let port_a = 51000;
        let port_b = 51001;
        
        // Let's create new endpoints with fixed ports
        let mut endpoint_a = Endpoint::new(port_a, IdentityBundle::generate()).unwrap();
        let mut endpoint_b = Endpoint::new(port_b, IdentityBundle::generate()).unwrap();
        
        let loopback_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
        
        // A connects to B
        let conn_id = endpoint_a.connect(loopback_ip, port_b).unwrap();
        
        // We simulate a network event loop
        for _ in 0..10 {
            endpoint_b.poll().unwrap();
            endpoint_a.poll().unwrap();
        }
        
        // Verify connection state
        let conn_a = endpoint_a.connections.get(&conn_id).unwrap();
        assert_eq!(conn_a.state, crate::connection::ConnectionState::Established);
        
        // The responder (B) will have a connection mapped to conn_id as well
        let conn_b = endpoint_b.connections.get(&conn_id).unwrap();
        assert_eq!(conn_b.state, crate::connection::ConnectionState::Established);
    }
}
