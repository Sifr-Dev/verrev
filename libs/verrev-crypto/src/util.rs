pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn ct_select(bit: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    let mask: u8 = 0u8.wrapping_sub(bit & 1);
    for i in 0..out.len().min(a.len()).min(b.len()) {
        out[i] = a[i] & mask | b[i] & !mask;
    }
}

pub fn ct_swap(bit: u8, a: &mut [u8], b: &mut [u8]) {
    let mask: u8 = 0u8.wrapping_sub(bit & 1);
    for i in 0..a.len().min(b.len()) {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub fn fill_random(buf: &mut [u8]) {
    let _ = verrev_syscall::linux::getrandom(buf);
}

pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    u64::from_le_bytes(buf)
}
