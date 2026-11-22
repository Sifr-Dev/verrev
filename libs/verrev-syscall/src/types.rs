pub type Fd = i32;
pub type Pid = i32;
pub type Uid = u32;
pub type Gid = u32;
pub type Size = usize;
pub type Offset = i64;
pub type Result<T> = core::result::Result<T, SyscallError>;
pub type Sockaddr = [u8; 28];
pub type RecvFrom = (usize, Option<(Sockaddr, u32)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallError(pub i32);

const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const ECONNREFUSED: i32 = 111;
const ECONNRESET: i32 = 104;

impl SyscallError {
    pub fn from_errno(errno: i32) -> Self {
        SyscallError(errno)
    }

    pub fn kind(&self) -> ErrnoKind {
        match self.0 {
            EAGAIN => ErrnoKind::Again,
            EINTR => ErrnoKind::Interrupted,
            EINVAL => ErrnoKind::InvalidArgument,
            ENOMEM => ErrnoKind::OutOfMemory,
            EACCES => ErrnoKind::PermissionDenied,
            ECONNREFUSED => ErrnoKind::ConnectionRefused,
            ECONNRESET => ErrnoKind::ConnectionReset,
            _ => ErrnoKind::Other(self.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrnoKind {
    Again,
    Interrupted,
    InvalidArgument,
    OutOfMemory,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    Other(i32),
}

pub struct IoVec<'a> {
    pub base: &'a [u8],
    pub len: usize,
}
