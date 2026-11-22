use core::arch::asm;

use crate::types::*;

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_SOCKET: usize = 41;
const SYS_SENDTO: usize = 44;
const SYS_RECVFROM: usize = 45;
const SYS_BIND: usize = 49;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_EXIT: usize = 60;
const SYS_GETRANDOM: usize = 318;

const SOCKADDR_MAX: usize = 28;

pub fn syscall0(n: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("syscall", in("rax") n, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    }
    ret
}

pub fn syscall1(n: usize, a1: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    }
    ret
}

pub fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, in("rsi") a2, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    }
    ret
}

pub fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, in("rsi") a2, in("rdx") a3, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    }
    ret
}

pub fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    }
    ret
}

pub fn syscall6(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    }
    ret
}

pub fn socket(domain: i32, ty: i32, protocol: i32) -> Result<Fd> {
    let ret = syscall3(SYS_SOCKET, domain as usize, ty as usize, protocol as usize) as i64;
    if ret >= 0 {
        Ok(ret as Fd)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

/// # Safety
/// If `dest` is `Some((addr, _))`, `addr` must point to a valid, properly aligned
/// sockaddr buffer of the specified length. The kernel reads this buffer; undefined
/// behavior results if the pointer is invalid.
pub unsafe fn sendto(fd: Fd, buf: &[u8], flags: i32, dest: Option<(*const u8, u32)>) -> Result<usize> {
    let (addr, addrlen) = match dest {
        Some((a, l)) => (a as usize, l as usize),
        None => (0, 0),
    };
    let ret = syscall6(
        SYS_SENDTO,
        fd as usize,
        buf.as_ptr() as usize,
        buf.len(),
        flags as usize,
        addr,
        addrlen,
    ) as i64;
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

pub fn recvfrom(fd: Fd, buf: &mut [u8], flags: i32) -> Result<RecvFrom> {
    let mut addr: Sockaddr = [0u8; SOCKADDR_MAX];
    let mut addrlen: u32 = SOCKADDR_MAX as u32;
    let ret = syscall6(
        SYS_RECVFROM,
        fd as usize,
        buf.as_mut_ptr() as usize,
        buf.len(),
        flags as usize,
        addr.as_mut_ptr() as usize,
        &mut addrlen as *mut u32 as usize,
    ) as i64;
    if ret >= 0 {
        let addr_out = if addrlen > 0 { Some((addr, addrlen)) } else { None };
        Ok((ret as usize, addr_out))
    } else {
        Err(SyscallError(-ret as i32))
    }
}

pub fn bind(fd: Fd, addr: &[u8]) -> Result<()> {
    let ret = syscall3(SYS_BIND, fd as usize, addr.as_ptr() as usize, addr.len()) as i64;
    if ret >= 0 {
        Ok(())
    } else {
        Err(SyscallError(-ret as i32))
    }
}

pub fn close(fd: Fd) -> Result<()> {
    let ret = syscall1(SYS_CLOSE, fd as usize) as i64;
    if ret >= 0 {
        Ok(())
    } else {
        Err(SyscallError(-ret as i32))
    }
}

pub fn getrandom(buf: &mut [u8]) -> Result<usize> {
    let ret = syscall3(SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), 0) as i64;
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

pub fn exit(code: i32) -> ! {
    syscall1(SYS_EXIT, code as usize);
    loop {
        core::hint::spin_loop();
    }
}

/// Read from a file descriptor.
pub fn read(fd: Fd, buf: &mut [u8]) -> Result<usize> {
    let ret = syscall3(SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) as i64;
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

/// Write to a file descriptor.
pub fn write(fd: Fd, buf: &[u8]) -> Result<usize> {
    let ret = syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) as i64;
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

/// Open a file. `path` must be a null-terminated C string.
pub fn open(path: *const u8, flags: i32, mode: u32) -> Result<Fd> {
    let ret = syscall3(SYS_OPEN, path as usize, flags as usize, mode as usize) as i64;
    if ret >= 0 {
        Ok(ret as Fd)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

/// # Safety
/// `addr` must be a valid mapped region (or null for system-chosen address).
/// The caller must ensure no aliasing violations.
pub unsafe fn mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> Result<*mut u8> {
    let ret = syscall6(
        SYS_MMAP,
        addr as usize,
        length,
        prot as usize,
        flags as usize,
        fd as usize,
        offset as usize,
    ) as i64;
    if ret >= 0 && !(ret as *mut u8).is_null() {
        Ok(ret as *mut u8)
    } else {
        Err(SyscallError(-ret as i32))
    }
}

/// # Safety
/// `addr` must be a pointer previously returned by `mmap` and not yet unmapped.
pub unsafe fn munmap(addr: *mut u8, length: usize) -> Result<()> {
    let ret = syscall2(SYS_MUNMAP, addr as usize, length) as i64;
    if ret >= 0 {
        Ok(())
    } else {
        Err(SyscallError(-ret as i32))
    }
}

pub fn now_nanos() -> Result<u64> {
    let mut ts: [i64; 2] = [0, 0];
    let ret = syscall2(
        SYS_CLOCK_GETTIME,
        1, // CLOCK_MONOTONIC
        ts.as_mut_ptr() as usize,
    ) as i64;
    if ret < 0 {
        return Err(SyscallError(-ret as i32));
    }
    Ok((ts[0] as u64) * 1_000_000_000 + (ts[1] as u64))
}
