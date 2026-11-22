use crate::Result;
use crate::TransportError;
use verrev_syscall::Fd;

const AF_INET6: i32 = 10;
const SOCK_DGRAM: i32 = 2;
const IPPROTO_UDP: i32 = 17;


#[repr(C)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

pub struct UdpSocket {
    fd: Fd,
}

impl UdpSocket {
    pub fn bind(port: u16) -> Result<Self> {
        let fd = verrev_syscall::linux::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
            .map_err(|_| TransportError::InvalidState)?; // Map to generic error for now

        // Optional: Disable IPV6_V6ONLY to accept IPv4 via IPv4-mapped IPv6 addresses
        // Not strictly necessary if we only bind to IPv6 any [::]
        
        let addr = SockaddrIn6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: [0; 16], // :: (in6addr_any)
            sin6_scope_id: 0,
        };

        let addr_bytes = unsafe {
            core::slice::from_raw_parts(&addr as *const _ as *const u8, core::mem::size_of::<SockaddrIn6>())
        };

        verrev_syscall::linux::bind(fd, addr_bytes)
            .map_err(|_| TransportError::InvalidState)?;

        Ok(UdpSocket { fd })
    }

    pub fn send_to(&self, buf: &[u8], ip: &[u8; 16], port: u16) -> Result<usize> {
        let addr = SockaddrIn6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: *ip,
            sin6_scope_id: 0,
        };

        let dest = Some((&addr as *const _ as *const u8, core::mem::size_of::<SockaddrIn6>() as u32));
        
        unsafe {
            verrev_syscall::linux::sendto(self.fd, buf, 64, dest)
                .map_err(|_| TransportError::ConnectionLost)
        }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, [u8; 16], u16)> {
        let (size, src) = match verrev_syscall::linux::recvfrom(self.fd, buf, 64) {
            Ok(res) => res,
            Err(verrev_syscall::SyscallError(11)) => return Err(TransportError::WouldBlock),
            Err(_) => return Err(TransportError::ConnectionLost),
        };

        if let Some((addr_buf, len)) = src
            && len as usize == core::mem::size_of::<SockaddrIn6>() {
                let addr = unsafe { &*(addr_buf.as_ptr() as *const SockaddrIn6) };
                return Ok((size, addr.sin6_addr, u16::from_be(addr.sin6_port)));
            }
        
        // If we get here, it wasn't a valid IPv6 sockaddr, maybe it was IPv4.
        // For Phase 1 we only parse IPv6.
        Err(TransportError::InvalidMessage)
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _ = verrev_syscall::linux::close(self.fd);
    }
}
