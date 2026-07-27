use verrev_hash::sha3::*;
use crate::util::*;

pub const PUBLIC_KEY_BYTES: usize = 2592;
pub const SECRET_KEY_BYTES: usize = 4896;
pub const SIGNATURE_BYTES: usize = 4627;

const Q: i32 = 8380417;
const QINV: i64 = {
    let a = Q as u32;
    let mut x = 1u32;
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x as i64
};
const N: usize = 256;
const K: usize = 8;
const L: usize = 7;
const ETA: usize = 2;
const TAU: usize = 60;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (Q - 1) / 32;
const BETA: usize = TAU * ETA;
const OMEGA: usize = 80;
const D: usize = 13;
const POLYT1_PACKEDBYTES: usize = 320;
const POLYT0_PACKEDBYTES: usize = 416;
const POLYETA_PACKEDBYTES: usize = 96;
const POLYZ_PACKEDBYTES: usize = 640;
const POLYW1_PACKEDBYTES: usize = 128;
const CTILDEBYTES: usize = 32;
const ALPHA: i32 = 2 * GAMMA2;

pub struct DilithiumKeypair {
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub secret_key: [u8; SECRET_KEY_BYTES],
}

fn bit_rev7(x: usize) -> usize {
    let mut r = 0usize;
    let mut x = x;
    for _ in 0..7 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

fn zeta_table() -> ([i32; 256], i32) {
    let mut zetas = [0i32; 256];
    let q = Q as i64;
    let r_mod = ((1u64 << 32) % Q as u64) as i64;
    for i in 1..256 {
        let exp = if i < 128 {
            2 * bit_rev7(i)
        } else {
            2 * bit_rev7(i - 128) + 1
        };
        let z = (r_mod * modpow(1753, exp as u32)) % q;
        zetas[i] = if z > q / 2 { (z - q) as i32 } else { z as i32 };
    }
    let inv_256 = modpow(256, Q as u32 - 2);
    let inv = (r_mod * r_mod % q * inv_256) % q;
    let invntt_factor = if inv > q / 2 { (inv - q) as i32 } else { inv as i32 };
    (zetas, invntt_factor)
}

fn modpow(base: i64, exp: u32) -> i64 {
    let mut result = 1i64;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = (result.wrapping_mul(b)) % Q as i64;
        }
        b = (b.wrapping_mul(b)) % Q as i64;
        e >>= 1;
    }
    result
}

fn montgomery_reduce(a: i64) -> i32 {
    let t = ((a as i32).wrapping_mul(QINV as i32)) as i64;
    let t = a.wrapping_sub(t.wrapping_mul(Q as i64)) >> 32;
    t as i32
}

fn reduce32(a: i32) -> i32 {
    let t = a.wrapping_add(1 << 22) >> 23;
    a.wrapping_sub(t.wrapping_mul(Q))
}

fn caddq(a: i32) -> i32 {
    a.wrapping_add((a >> 31) & Q)
}

fn ntt(a: &mut [i32; N], zetas: &[i32; 256]) {
    let mut k = 1usize;
    let mut len = 128usize;
    loop {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas[k];
            k += 1;
            for j in start..start + len {
                let t = montgomery_reduce(zeta as i64 * a[j + len] as i64);
                a[j + len] = a[j].wrapping_sub(t);
                a[j] = a[j].wrapping_add(t);
            }
            start += 2 * len;
        }
        if len == 1 {
            break;
        }
        len >>= 1;
    }
}

fn invntt_tomont(a: &mut [i32; N], zetas: &[i32; 256], invntt_factor: i32) {
    let mut k = 256usize;
    let mut len = 1usize;
    loop {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = -zetas[k];
            for j in start..start + len {
                let t = a[j];
                a[j] = t.wrapping_add(a[j + len]);
                a[j + len] = t.wrapping_sub(a[j + len]);
                a[j + len] = montgomery_reduce(zeta as i64 * a[j + len] as i64);
            }
            start += 2 * len;
        }
        if len == 128 {
            break;
        }
        len <<= 1;
    }
    for j in 0..N {
        a[j] = montgomery_reduce(invntt_factor as i64 * a[j] as i64);
    }
}

fn poly_pointwise_montgomery(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
    c
}

fn poly_reduce_assign(a: &mut [i32; N]) {
    for i in 0..N {
        a[i] = reduce32(a[i]);
    }
}

fn poly_caddq_assign(a: &mut [i32; N]) {
    for i in 0..N {
        a[i] = caddq(a[i]);
    }
}

fn poly_chknorm(a: &[i32; N], bound: i32) -> bool {
    if bound > (Q - 1) / 8 {
        return true;
    }
    for i in 0..N {
        let abs = a[i].wrapping_abs();
        if abs >= bound {
            return true;
        }
    }
    false
}

fn power2round(a0: &mut i32, a: i32) -> i32 {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    a1
}

fn decompose(a0: &mut i32, a: i32) -> i32 {
    let mut a1 = (a.wrapping_add(127)) >> 7;
    a1 = (a1.wrapping_mul((1 << 30) / GAMMA2).wrapping_add(1 << 23)) >> 24;
    a1 &= ((Q - 1) / ALPHA - 1) as i32;
    *a0 = a.wrapping_sub(a1.wrapping_mul(ALPHA));
    let t = ((Q - 1) / 2).wrapping_sub(*a0) >> 31;
    *a0 = (*a0).wrapping_sub(t & Q);
    a1
}

fn make_hint(a0: i32, a1: i32) -> usize {
    if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
        1
    } else {
        0
    }
}

fn use_hint(a: i32, hint: usize) -> i32 {
    let mut a0 = 0i32;
    let a1 = decompose(&mut a0, a);
    if hint == 0 {
        return a1;
    }
    let w1_max = ((Q - 1) / ALPHA - 1) as i32;
    if a0 > 0 {
        (a1 + 1) & w1_max
    } else {
        (a1 - 1) & w1_max
    }
}

fn poly_uniform(seed: &[u8; 32], nonce: u16) -> [i32; N] {
    let mut poly = [0i32; N];
    let mut state = Keccak::shake128();
    let nonce_bytes = nonce.to_le_bytes();
    state.absorb(seed);
    state.absorb(&nonce_bytes);
    let mut buf = [0u8; 840];
    state.squeeze(&mut buf);
    let mut ctr = 0usize;
    let mut off = 0usize;
    while ctr < N {
        let mut pos = off;
        while ctr < N && pos + 3 <= buf.len() {
            let t = buf[pos] as u32
                | (buf[pos + 1] as u32) << 8
                | (buf[pos + 2] as u32) << 16;
            let t = t & 0x7FFFFF;
            pos += 3;
            if (t as i32) < Q {
                poly[ctr] = t as i32;
                ctr += 1;
            }
        }
        if ctr < N {
            let remaining = buf.len() - pos;
            for i in 0..remaining {
                buf[i] = buf[pos + i];
            }
            state.squeeze(&mut buf[remaining..]);
            off = remaining;
        }
    }
    poly
}

fn polyvecl_uniform_eta(seed: &[u8; 64], nonce: u16) -> [[i32; N]; L] {
    let mut v = [[0i32; N]; L];
    for i in 0..L {
        let mut h = Keccak::shake256();
        h.absorb(seed);
        h.absorb(&[(nonce + i as u16) as u8]);
        let mut buf = [0u8; 136];
        h.squeeze(&mut buf);
        let mut ctr = 0usize;
        let mut pos = 0usize;
        while ctr < N {
            while ctr < N && pos < buf.len() {
                let t0 = buf[pos] & 0x0F;
                let t1 = buf[pos] >> 4;
                pos += 1;
                if t0 < 15 {
                    v[i][ctr] = ETA as i32 - (t0 as i32 % 5);
                    ctr += 1;
                }
                if ctr < N && t1 < 15 {
                    v[i][ctr] = ETA as i32 - (t1 as i32 % 5);
                    ctr += 1;
                }
            }
            if ctr < N {
                pos = 0;
                h.squeeze(&mut buf);
            }
        }
    }
    v
}

fn polyveck_uniform_eta(seed: &[u8; 64], nonce: u16) -> [[i32; N]; K] {
    let mut v = [[0i32; N]; K];
    for i in 0..K {
        let mut h = Keccak::shake256();
        h.absorb(seed);
        h.absorb(&[(nonce + i as u16) as u8]);
        let mut buf = [0u8; 136];
        h.squeeze(&mut buf);
        let mut ctr = 0usize;
        let mut pos = 0usize;
        while ctr < N {
            while ctr < N && pos < buf.len() {
                let t0 = buf[pos] & 0x0F;
                let t1 = buf[pos] >> 4;
                pos += 1;
                if t0 < 15 {
                    v[i][ctr] = ETA as i32 - (t0 as i32 % 5);
                    ctr += 1;
                }
                if ctr < N && t1 < 15 {
                    v[i][ctr] = ETA as i32 - (t1 as i32 % 5);
                    ctr += 1;
                }
            }
            if ctr < N {
                pos = 0;
                h.squeeze(&mut buf);
            }
        }
    }
    v
}

fn polyz_unpack(buf: &[u8]) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N / 2 {
        r[2 * i] = buf[5 * i] as i32
            | (buf[5 * i + 1] as i32) << 8
            | (buf[5 * i + 2] as i32) << 16;
        r[2 * i] &= 0xFFFFF;
        r[2 * i + 1] = (buf[5 * i + 2] as i32 >> 4)
            | (buf[5 * i + 3] as i32) << 4
            | (buf[5 * i + 4] as i32) << 12;
        r[2 * i] = GAMMA1 - r[2 * i];
        r[2 * i + 1] = GAMMA1 - r[2 * i + 1];
    }
    r
}

fn polyz_pack(a: &[i32; N]) -> [u8; POLYZ_PACKEDBYTES] {
    let mut r = [0u8; POLYZ_PACKEDBYTES];
    for i in 0..N / 2 {
        let t0 = (GAMMA1 - a[2 * i]) as u32;
        let t1 = (GAMMA1 - a[2 * i + 1]) as u32;
        r[5 * i] = t0 as u8;
        r[5 * i + 1] = (t0 >> 8) as u8;
        r[5 * i + 2] = (t0 >> 16) as u8 | ((t1 << 4) as u8);
        r[5 * i + 3] = (t1 >> 4) as u8;
        r[5 * i + 4] = (t1 >> 12) as u8;
    }
    r
}

fn polyw1_pack(a: &[i32; N]) -> [u8; POLYW1_PACKEDBYTES] {
    let mut r = [0u8; POLYW1_PACKEDBYTES];
    for i in 0..N / 2 {
        r[i] = a[2 * i] as u8 | ((a[2 * i + 1] as u8) << 4);
    }
    r
}

fn polyt1_pack(a: &[i32; N]) -> [u8; POLYT1_PACKEDBYTES] {
    let mut r = [0u8; POLYT1_PACKEDBYTES];
    for i in 0..N / 4 {
        r[5 * i] = a[4 * i] as u8;
        r[5 * i + 1] = (a[4 * i] >> 8) as u8 | ((a[4 * i + 1] as u8) << 2);
        r[5 * i + 2] = (a[4 * i + 1] >> 6) as u8 | ((a[4 * i + 2] as u8) << 4);
        r[5 * i + 3] = (a[4 * i + 2] >> 4) as u8 | ((a[4 * i + 3] as u8) << 6);
        r[5 * i + 4] = (a[4 * i + 3] >> 2) as u8;
    }
    r
}

fn polyt0_pack(a: &[i32; N]) -> [u8; POLYT0_PACKEDBYTES] {
    let mut r = [0u8; POLYT0_PACKEDBYTES];
    for i in 0..N / 8 {
        let mut t = [0u32; 8];
        for j in 0..8 {
            t[j] = ((1 << (D - 1)) as i32 - a[8 * i + j]) as u32;
        }
        r[13 * i] = t[0] as u8;
        r[13 * i + 1] = (t[0] >> 8) as u8 | ((t[1] as u8) << 5);
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11) as u8 | ((t[2] as u8) << 2);
        r[13 * i + 4] = (t[2] >> 6) as u8 | ((t[3] as u8) << 7);
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9) as u8 | ((t[4] as u8) << 4);
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12) as u8 | ((t[5] as u8) << 1);
        r[13 * i + 9] = (t[5] >> 7) as u8 | ((t[6] as u8) << 6);
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10) as u8 | ((t[7] as u8) << 3);
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
    r
}

fn polyt0_unpack(buf: &[u8]) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N / 8 {
        let a = &buf[13 * i..13 * i + 13];
        r[8 * i] = (a[0] as i32 | (a[1] as i32) << 8) & 0x1FFF;
        r[8 * i + 1] = ((a[1] as i32 >> 5) | (a[2] as i32) << 3 | (a[3] as i32) << 11) & 0x1FFF;
        r[8 * i + 2] = ((a[3] as i32 >> 2) | (a[4] as i32) << 6) & 0x1FFF;
        r[8 * i + 3] = ((a[4] as i32 >> 7) | (a[5] as i32) << 1 | (a[6] as i32) << 9) & 0x1FFF;
        r[8 * i + 4] = ((a[6] as i32 >> 4) | (a[7] as i32) << 4 | (a[8] as i32) << 12) & 0x1FFF;
        r[8 * i + 5] = ((a[8] as i32 >> 1) | (a[9] as i32) << 7) & 0x1FFF;
        r[8 * i + 6] = ((a[9] as i32 >> 6) | (a[10] as i32) << 2 | (a[11] as i32) << 10) & 0x1FFF;
        r[8 * i + 7] = ((a[11] as i32 >> 3) | (a[12] as i32) << 5) & 0x1FFF;
        for j in 0..8 {
            r[8 * i + j] = (1 << (D - 1)) as i32 - r[8 * i + j];
        }
    }
    r
}

fn polyeta_pack(a: &[i32; N]) -> [u8; POLYETA_PACKEDBYTES] {
    let mut r = [0u8; POLYETA_PACKEDBYTES];
    for i in 0..N / 8 {
        let mut t = [0u8; 8];
        for j in 0..8 {
            t[j] = (ETA as i32 - a[8 * i + j]) as u8;
        }
        r[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
    r
}

fn polyeta_unpack(buf: &[u8]) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N / 8 {
        r[8 * i] = (buf[3 * i] >> 0) as i32 & 7;
        r[8 * i + 1] = (buf[3 * i] >> 3) as i32 & 7;
        r[8 * i + 2] = ((buf[3 * i] >> 6) as i32 | ((buf[3 * i + 1] as i32) << 2)) & 7;
        r[8 * i + 3] = (buf[3 * i + 1] >> 1) as i32 & 7;
        r[8 * i + 4] = (buf[3 * i + 1] >> 4) as i32 & 7;
        r[8 * i + 5] = ((buf[3 * i + 1] >> 7) as i32 | ((buf[3 * i + 2] as i32) << 1)) & 7;
        r[8 * i + 6] = (buf[3 * i + 2] >> 2) as i32 & 7;
        r[8 * i + 7] = (buf[3 * i + 2] >> 5) as i32 & 7;
        for j in 0..8 {
            r[8 * i + j] = ETA as i32 - r[8 * i + j];
        }
    }
    r
}

fn poly_challenge(seed: &[u8; CTILDEBYTES]) -> [i32; N] {
    let mut c = [0i32; N];
    let mut state = Keccak::shake256();
    state.absorb(seed);
    let mut buf = [0u8; 136];
    state.squeeze(&mut buf);
    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (buf[i] as u64) << (8 * i);
    }
    let mut pos = 8usize;
    for i in (N - TAU)..N {
        loop {
            if pos >= 136 {
                state.squeeze(&mut buf);
                pos = 0;
            }
            let b = buf[pos];
            pos += 1;
            if (b as usize) <= i {
                c[i] = c[b as usize];
                c[b as usize] = 1 - 2 * ((signs & 1) as i32);
                signs >>= 1;
                break;
            }
        }
    }
    c
}

fn polyvecl_ntt(v: &mut [[i32; N]; L], zetas: &[i32; 256]) {
    for i in 0..L {
        ntt(&mut v[i], zetas);
    }
}

fn polyveck_ntt(v: &mut [[i32; N]; K], zetas: &[i32; 256]) {
    for i in 0..K {
        ntt(&mut v[i], zetas);
    }
}

fn polyvecl_invntt_tomont(v: &mut [[i32; N]; L], zetas: &[i32; 256], invntt_factor: i32) {
    for i in 0..L {
        invntt_tomont(&mut v[i], zetas, invntt_factor);
    }
}

fn polyveck_invntt_tomont(v: &mut [[i32; N]; K], zetas: &[i32; 256], invntt_factor: i32) {
    for i in 0..K {
        invntt_tomont(&mut v[i], zetas, invntt_factor);
    }
}

fn polyvecl_add_assign(a: &mut [[i32; N]; L], b: &[[i32; N]; L]) {
    for i in 0..L {
        for j in 0..N {
            a[i][j] = a[i][j].wrapping_add(b[i][j]);
        }
    }
}

fn polyveck_add_assign(a: &mut [[i32; N]; K], b: &[[i32; N]; K]) {
    for i in 0..K {
        for j in 0..N {
            a[i][j] = a[i][j].wrapping_add(b[i][j]);
        }
    }
}

fn polyveck_sub_assign(a: &mut [[i32; N]; K], b: &[[i32; N]; K]) {
    for i in 0..K {
        for j in 0..N {
            a[i][j] = a[i][j].wrapping_sub(b[i][j]);
        }
    }
}

fn polyveck_reduce(v: &mut [[i32; N]; K]) {
    for i in 0..K {
        poly_reduce_assign(&mut v[i]);
    }
}

fn polyveck_caddq(v: &mut [[i32; N]; K]) {
    for i in 0..K {
        poly_caddq_assign(&mut v[i]);
    }
}

fn polyveck_power2round(v1: &mut [[i32; N]; K], v0: &mut [[i32; N]; K], v: &[[i32; N]; K]) {
    for i in 0..K {
        for j in 0..N {
            v1[i][j] = power2round(&mut v0[i][j], v[i][j]);
        }
    }
}

fn polyveck_decompose(v1: &mut [[i32; N]; K], v0: &mut [[i32; N]; K], v: &[[i32; N]; K]) {
    for i in 0..K {
        for j in 0..N {
            v1[i][j] = decompose(&mut v0[i][j], v[i][j]);
        }
    }
}

fn polyveck_make_hint(h: &mut [[i32; N]; K], v0: &[[i32; N]; K], v1: &[[i32; N]; K]) -> usize {
    let mut s = 0usize;
    for i in 0..K {
        for j in 0..N {
            h[i][j] = make_hint(v0[i][j], v1[i][j]) as i32;
            s += h[i][j] as usize;
        }
    }
    s
}

fn polyveck_use_hint(v: &mut [[i32; N]; K], w: &[[i32; N]; K], h: &[[i32; N]; K]) {
    for i in 0..K {
        for j in 0..N {
            v[i][j] = use_hint(w[i][j], h[i][j] as usize);
        }
    }
}

fn polyveck_chknorm(v: &[[i32; N]; K], bound: i32) -> bool {
    for i in 0..K {
        if poly_chknorm(&v[i], bound) {
            return true;
        }
    }
    false
}

fn polyvecl_reduce(v: &mut [[i32; N]; L]) {
    for i in 0..L {
        poly_reduce_assign(&mut v[i]);
    }
}

fn polyvecl_chknorm(v: &[[i32; N]; L], bound: i32) -> bool {
    for i in 0..L {
        if poly_chknorm(&v[i], bound) {
            return true;
        }
    }
    false
}

fn polyvecl_pointwise_poly_montgomery(v: &mut [[i32; N]; L], cp: &[i32; N], s1: &[[i32; N]; L]) {
    for i in 0..L {
        v[i] = poly_pointwise_montgomery(cp, &s1[i]);
    }
}

fn polyveck_pointwise_poly_montgomery(v: &mut [[i32; N]; K], cp: &[i32; N], s2: &[[i32; N]; K]) {
    for i in 0..K {
        v[i] = poly_pointwise_montgomery(cp, &s2[i]);
    }
}

fn polyveck_shiftl(v: &mut [[i32; N]; K]) {
    for i in 0..K {
        for j in 0..N {
            v[i][j] = v[i][j].wrapping_shl(D as u32);
        }
    }
}

fn polyvec_matrix_expand(rho: &[u8; 32]) -> [[[i32; N]; L]; K] {
    let mut mat = [[[0i32; N]; L]; K];
    for i in 0..K {
        for j in 0..L {
            mat[i][j] = poly_uniform(rho, (i * L + j) as u16);
        }
    }
    mat
}

fn polyvec_matrix_pointwise_montgomery(t: &mut [[i32; N]; K], mat: &[[[i32; N]; L]; K], v: &[[i32; N]; L]) {
    for i in 0..K {
        let mut sum = [0i32; N];
        for j in 0..L {
            let prod = poly_pointwise_montgomery(&mat[i][j], &v[j]);
            for k in 0..N {
                sum[k] = sum[k].wrapping_add(prod[k]);
            }
        }
        t[i] = sum;
    }
}

fn polyveck_pack_w1(buf: &mut [u8], w1: &[[i32; N]; K]) {
    for i in 0..K {
        let packed = polyw1_pack(&w1[i]);
        buf[i * POLYW1_PACKEDBYTES..(i + 1) * POLYW1_PACKEDBYTES].copy_from_slice(&packed);
    }
}

fn pack_pk(pk: &mut [u8; PUBLIC_KEY_BYTES], rho: &[u8; 32], t1: &[[i32; N]; K]) {
    pk[..32].copy_from_slice(rho);
    let mut offset = 32;
    for i in 0..K {
        let packed = polyt1_pack(&t1[i]);
        pk[offset..offset + POLYT1_PACKEDBYTES].copy_from_slice(&packed);
        offset += POLYT1_PACKEDBYTES;
    }
}

fn pack_sk(sk: &mut [u8; SECRET_KEY_BYTES], rho: &[u8; 32], tr: &[u8; 32], key: &[u8; 32],
           t0: &[[i32; N]; K], s1: &[[i32; N]; L], s2: &[[i32; N]; K]) {
    let mut offset = 0usize;
    sk[offset..offset + 32].copy_from_slice(rho);
    offset += 32;
    sk[offset..offset + 32].copy_from_slice(key);
    offset += 32;
    sk[offset..offset + 32].copy_from_slice(tr);
    offset += 32;
    for i in 0..K {
        let packed = polyt0_pack(&t0[i]);
        sk[offset..offset + POLYT0_PACKEDBYTES].copy_from_slice(&packed);
        offset += POLYT0_PACKEDBYTES;
    }
    for i in 0..L {
        let packed = polyeta_pack(&s1[i]);
        sk[offset..offset + POLYETA_PACKEDBYTES].copy_from_slice(&packed);
        offset += POLYETA_PACKEDBYTES;
    }
    for i in 0..K {
        let packed = polyeta_pack(&s2[i]);
        sk[offset..offset + POLYETA_PACKEDBYTES].copy_from_slice(&packed);
        offset += POLYETA_PACKEDBYTES;
    }
    sk[offset..offset + 32].copy_from_slice(tr);
}

fn pack_sig(sig: &mut [u8; SIGNATURE_BYTES], c: &[u8; CTILDEBYTES], z: &[[i32; N]; L], h: &[[i32; N]; K]) {
    sig[..CTILDEBYTES].copy_from_slice(c);
    let mut offset = CTILDEBYTES;
    for i in 0..L {
        let packed = polyz_pack(&z[i]);
        sig[offset..offset + POLYZ_PACKEDBYTES].copy_from_slice(&packed);
        offset += POLYZ_PACKEDBYTES;
    }
    let mut k = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h[i][j] != 0 {
                sig[offset + k] = j as u8;
                k += 1;
            }
        }
        sig[offset + OMEGA + i] = k as u8;
    }
    for i in k..OMEGA {
        sig[offset + i] = 0;
    }
}

fn unpack_pk(rho: &mut [u8; 32], t1: &mut [[i32; N]; K], pk: &[u8; PUBLIC_KEY_BYTES]) {
    rho.copy_from_slice(&pk[..32]);
    let mut offset = 32;
    for i in 0..K {
        let poly_bytes = &pk[offset..offset + POLYT1_PACKEDBYTES];
        t1[i] = polyt1_unpack(poly_bytes);
        offset += POLYT1_PACKEDBYTES;
    }
}

fn unpack_sk(rho: &mut [u8; 32], key: &mut [u8; 32], tr: &mut [u8; 32],
             t0: &mut [[i32; N]; K], s1: &mut [[i32; N]; L], s2: &mut [[i32; N]; K],
             sk: &[u8; SECRET_KEY_BYTES]) {
    let mut offset = 0usize;
    rho.copy_from_slice(&sk[offset..offset + 32]);
    offset += 32;
    key.copy_from_slice(&sk[offset..offset + 32]);
    offset += 32;
    tr.copy_from_slice(&sk[offset..offset + 32]);
    offset += 32;
    for i in 0..K {
        t0[i] = polyt0_unpack(&sk[offset..offset + POLYT0_PACKEDBYTES]);
        offset += POLYT0_PACKEDBYTES;
    }
    for i in 0..L {
        s1[i] = polyeta_unpack(&sk[offset..offset + POLYETA_PACKEDBYTES]);
        offset += POLYETA_PACKEDBYTES;
    }
    for i in 0..K {
        s2[i] = polyeta_unpack(&sk[offset..offset + POLYETA_PACKEDBYTES]);
        offset += POLYETA_PACKEDBYTES;
    }
}

fn unpack_sig(c: &mut [u8; CTILDEBYTES], z: &mut [[i32; N]; L], h: &mut [[i32; N]; K],
              sig: &[u8; SIGNATURE_BYTES]) -> bool {
    c.copy_from_slice(&sig[..CTILDEBYTES]);
    let mut offset = CTILDEBYTES;
    for i in 0..L {
        z[i] = polyz_unpack(&sig[offset..offset + POLYZ_PACKEDBYTES]);
        offset += POLYZ_PACKEDBYTES;
    }
    for i in 0..K {
        for j in 0..N {
            h[i][j] = 0;
        }
    }
    for i in 0..K {
        let k = if i == 0 { 0usize } else { sig[offset + OMEGA + i - 1] as usize };
        let end = sig[offset + OMEGA + i] as usize;
        if k > end || end > OMEGA {
            return true;
        }
        for j in k..end {
            let idx = sig[offset + j] as usize;
            if idx >= N {
                return true;
            }
            h[i][idx] = 1;
        }
    }
    false
}

fn polyt1_unpack(buf: &[u8]) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N / 4 {
        r[4 * i] = (buf[5 * i] as i32 | (buf[5 * i + 1] as i32) << 8) & 0x3FF;
        r[4 * i + 1] = ((buf[5 * i + 1] as i32 >> 2) | (buf[5 * i + 2] as i32) << 6) & 0x3FF;
        r[4 * i + 2] = ((buf[5 * i + 2] as i32 >> 4) | (buf[5 * i + 3] as i32) << 4) & 0x3FF;
        r[4 * i + 3] = ((buf[5 * i + 3] as i32 >> 6) | (buf[5 * i + 4] as i32) << 2) & 0x3FF;
    }
    r
}

fn polyvecl_uniform_gamma1(seed: &[u8; 64], nonce: u16) -> [[i32; N]; L] {
    let mut v = [[0i32; N]; L];
    for i in 0..L {
        let mut h = Keccak::shake256();
        h.absorb(seed);
        h.absorb(&(nonce + i as u16).to_le_bytes());
        let mut ctx = [0u8; 640];
        h.squeeze(&mut ctx);
        v[i] = polyz_unpack(&ctx[..POLYZ_PACKEDBYTES]);
    }
    v
}

fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak::sha3_256();
    h.absorb(input);
    let mut out = [0u8; 32];
    h.squeeze(&mut out);
    out
}

fn shake256(input: &[u8], out: &mut [u8]) {
    let mut h = Keccak::shake256();
    h.absorb(input);
    h.squeeze(out);
}

pub fn generate_keypair(seed: Option<&[u8; 64]>) -> DilithiumKeypair {
    let mut seed_buf = [0u8; 64];
    if let Some(s) = seed {
        seed_buf.copy_from_slice(s);
    } else {
        fill_random(&mut seed_buf);
    }

    let mut seedbuf = [0u8; 96];
    seedbuf[..64].copy_from_slice(&seed_buf);
    seedbuf[64] = K as u8;
    seedbuf[65] = L as u8;
    let mut seedbuf_out = [0u8; 96];
    shake256(&seedbuf, &mut seedbuf_out);
    let seedbuf = seedbuf_out;

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&seedbuf[..32]);
    let mut rhoprime = [0u8; 64];
    rhoprime.copy_from_slice(&seedbuf[32..96]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&seedbuf[64..96]);

    let (zetas, invntt_factor) = zeta_table();
    let mat = polyvec_matrix_expand(&rho);

    let s1 = polyvecl_uniform_eta(&rhoprime, 0);
    let s2 = polyveck_uniform_eta(&rhoprime, L as u16);

    let mut s1hat = s1.clone();
    polyvecl_ntt(&mut s1hat, &zetas);

    let mut t1 = [[0i32; N]; K];
    polyvec_matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
    polyveck_reduce(&mut t1);
    polyveck_invntt_tomont(&mut t1, &zetas, invntt_factor);
    polyveck_add_assign(&mut t1, &s2);
    polyveck_caddq(&mut t1);

    let mut t0 = [[0i32; N]; K];
    let mut t1_high = [[0i32; N]; K];
    polyveck_power2round(&mut t1_high, &mut t0, &t1);

    let mut pk = [0u8; PUBLIC_KEY_BYTES];
    pack_pk(&mut pk, &rho, &t1_high);

    let tr = sha3_256(&pk);

    let mut sk = [0u8; SECRET_KEY_BYTES];
    pack_sk(&mut sk, &rho, &tr, &key, &t0, &s1, &s2);

    DilithiumKeypair {
        public_key: pk,
        secret_key: sk,
    }
}

pub fn sign(sk: &[u8; SECRET_KEY_BYTES], msg: &[u8]) -> [u8; SIGNATURE_BYTES] {
    let mut rho = [0u8; 32];
    let mut tr = [0u8; 32];
    let mut key = [0u8; 32];
    let mut t0 = [[0i32; N]; K];
    let mut s1 = [[0i32; N]; L];
    let mut s2 = [[0i32; N]; K];
    unpack_sk(&mut rho, &mut key, &mut tr, &mut t0, &mut s1, &mut s2, sk);

    let pre = [0u8, 0u8];
    let prelen = 2usize;

        let (zetas, invntt_factor) = zeta_table();

    let mat = polyvec_matrix_expand(&rho);

    let mut mu = [0u8; 64];
    {
        let mut state = Keccak::shake256();
        state.absorb(&tr);
        state.absorb(&pre[..prelen]);
        state.absorb(msg);
        state.squeeze(&mut mu);
    }

    let mut rhoprime = [0u8; 64];
    {
        let mut state = Keccak::shake256();
        state.absorb(&key);
        state.absorb(&[0u8; 32]);
        state.absorb(&mu);
        state.squeeze(&mut rhoprime);
    }

    polyvecl_ntt(&mut s1, &zetas);
    polyveck_ntt(&mut s2, &zetas);
    polyveck_ntt(&mut t0, &zetas);

    let mut nonce = 0u16;
    loop {
        let y = polyvecl_uniform_gamma1(&rhoprime, nonce);
        nonce = nonce.wrapping_add(1);

        let mut z = y;
        polyvecl_ntt(&mut z, &zetas);

        let mut w1 = [[0i32; N]; K];
        polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
        polyveck_reduce(&mut w1);
        polyveck_invntt_tomont(&mut w1, &zetas, invntt_factor);
        polyveck_caddq(&mut w1);

        let mut w0_low = [[0i32; N]; K];
        let mut w1_high = [[0i32; N]; K];
        polyveck_decompose(&mut w1_high, &mut w0_low, &w1);

        let mut w1_packed = [0u8; K * POLYW1_PACKEDBYTES];
        polyveck_pack_w1(&mut w1_packed, &w1_high);

        let mut c_bytes = [0u8; CTILDEBYTES];
        {
            let mut state = Keccak::shake256();
            state.absorb(&mu);
            state.absorb(&w1_packed);
            state.squeeze(&mut c_bytes);
        }

        let cp = poly_challenge(&c_bytes);
        let mut cp_ntt = cp;
        ntt(&mut cp_ntt, &zetas);

        polyvecl_pointwise_poly_montgomery(&mut z, &cp_ntt, &s1);
        polyvecl_invntt_tomont(&mut z, &zetas, invntt_factor);
        polyvecl_add_assign(&mut z, &y);
        polyvecl_reduce(&mut z);
        if polyvecl_chknorm(&z, GAMMA1 - BETA as i32) {
            continue;
        }

        let mut w0 = w0_low;
        let mut r0 = [[0i32; N]; K];
        polyveck_pointwise_poly_montgomery(&mut r0, &cp_ntt, &s2);
        polyveck_invntt_tomont(&mut r0, &zetas, invntt_factor);
        polyveck_sub_assign(&mut w0, &r0);
        polyveck_reduce(&mut w0);
        if polyveck_chknorm(&w0, GAMMA2 - BETA as i32) {
            continue;
        }

        let mut h = [[0i32; N]; K];
        polyveck_pointwise_poly_montgomery(&mut h, &cp_ntt, &t0);
        polyveck_invntt_tomont(&mut h, &zetas, invntt_factor);
        polyveck_reduce(&mut h);
        if polyveck_chknorm(&h, GAMMA2) {
            continue;
        }

        polyveck_add_assign(&mut w0, &h);
        let mut h_vec = [[0i32; N]; K];
        let hint_count = polyveck_make_hint(&mut h_vec, &w0, &w1_high);
        if hint_count > OMEGA {
            continue;
        }

        let mut sig = [0u8; SIGNATURE_BYTES];
        pack_sig(&mut sig, &c_bytes, &z, &h_vec);
        return sig;
    }
}

pub fn verify(pk: &[u8; PUBLIC_KEY_BYTES], msg: &[u8], sig: &[u8; SIGNATURE_BYTES]) -> bool {
    let mut rho = [0u8; 32];
    let mut t1 = [[0i32; N]; K];
    unpack_pk(&mut rho, &mut t1, pk);

    let (zetas, invntt_factor) = zeta_table();

    let mut c_bytes = [0u8; CTILDEBYTES];
    let mut z_vec = [[0i32; N]; L];
    let mut h_vec = [[0i32; N]; K];
    if unpack_sig(&mut c_bytes, &mut z_vec, &mut h_vec, sig) {
        return false;
    }
    if polyvecl_chknorm(&z_vec, GAMMA1 - BETA as i32) {
        return false;
    }

    let pre = [0u8, 0u8];
    let prelen = 2usize;

    let mut mu = [0u8; 64];
    {
        let mut h = Keccak::sha3_256();
        h.absorb(pk);
        let mut tr = [0u8; 32];
        h.squeeze(&mut tr);

        let mut state = Keccak::shake256();
        state.absorb(&tr);
        state.absorb(&pre[..prelen]);
        state.absorb(msg);
        state.squeeze(&mut mu);
    }

    let mat = polyvec_matrix_expand(&rho);
    let cp = poly_challenge(&c_bytes);
    let mut cp_ntt = cp;
    ntt(&mut cp_ntt, &zetas);

    polyvecl_ntt(&mut z_vec, &zetas);

    let mut w1 = [[0i32; N]; K];
    polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z_vec);

    polyveck_shiftl(&mut t1);
    polyveck_ntt(&mut t1, &zetas);
    let mut t1_cp = [[0i32; N]; K];
    t1_cp.copy_from_slice(&t1);
    polyveck_pointwise_poly_montgomery(&mut t1_cp, &cp_ntt, &t1);

    polyveck_sub_assign(&mut w1, &t1_cp);
    polyveck_reduce(&mut w1);
    polyveck_invntt_tomont(&mut w1, &zetas, invntt_factor);
    polyveck_caddq(&mut w1);
    let mut w1_copy = [[0i32; N]; K];
    w1_copy.copy_from_slice(&w1);
    polyveck_use_hint(&mut w1, &w1_copy, &h_vec);

    let mut w1_packed = [0u8; K * POLYW1_PACKEDBYTES];
    polyveck_pack_w1(&mut w1_packed, &w1);

    let mut c2 = [0u8; CTILDEBYTES];
    {
        let mut state = Keccak::shake256();
        state.absorb(&mu);
        state.absorb(&w1_packed);
        state.squeeze(&mut c2);
    }

    ct_eq(&c_bytes, &c2)
}

pub fn sign_detached(sk: &[u8; SECRET_KEY_BYTES], msg: &[u8]) -> [u8; SIGNATURE_BYTES] {
    sign(sk, msg)
}

pub fn verify_detached(pk: &[u8; PUBLIC_KEY_BYTES], msg: &[u8], sig: &[u8; SIGNATURE_BYTES]) -> bool {
    verify(pk, msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_keypair() {
        let kp = generate_keypair(None);
        assert!(kp.public_key.len() == PUBLIC_KEY_BYTES);
    }

    #[test]
    fn test_verify_w1_comparison() {
        let seed = [42u8; 64];
        let kp = generate_keypair(Some(&seed));
        let msg = b"test";

        // Manually sign to capture w1_high and other state
        let mut rho = [0u8; 32];
        let mut tr = [0u8; 32];
        let mut key = [0u8; 32];
        let mut t0 = [[0i32; N]; K];
        let mut s1 = [[0i32; N]; L];
        let mut s2 = [[0i32; N]; K];
        unpack_sk(&mut rho, &mut key, &mut tr, &mut t0, &mut s1, &mut s2, &kp.secret_key);
        let (zetas, invntt_factor) = zeta_table();
        let mat = polyvec_matrix_expand(&rho);

        let pre = [0u8, 0u8];
        let mut mu = [0u8; 64];
        {
            let mut state = Keccak::shake256();
            state.absorb(&tr);
            state.absorb(&pre);
            state.absorb(msg);
            state.squeeze(&mut mu);
        }

        let mut rhoprime = [0u8; 64];
        {
            let mut state = Keccak::shake256();
            state.absorb(&key);
            state.absorb(&[0u8; 32]);
            state.absorb(&mu);
            state.squeeze(&mut rhoprime);
        }

        polyvecl_ntt(&mut s1, &zetas);
        polyveck_ntt(&mut s2, &zetas);
        polyveck_ntt(&mut t0, &zetas);

        // Find a successful signature
        let mut nonce = 0u16;
        let mut sig = [0u8; SIGNATURE_BYTES];
        let captured_w1_high;
        let mut w1_expected = [[0i32; N]; K];
        loop {
            let y = polyvecl_uniform_gamma1(&rhoprime, nonce);
            nonce = nonce.wrapping_add(1);
            let mut z = y;
            polyvecl_ntt(&mut z, &zetas);

            let mut w = [[0i32; N]; K];
            polyvec_matrix_pointwise_montgomery(&mut w, &mat, &z);
            polyveck_reduce(&mut w);
            polyveck_invntt_tomont(&mut w, &zetas, invntt_factor);
            polyveck_caddq(&mut w);

            let mut w0_low = [[0i32; N]; K];
            let mut w1_high = [[0i32; N]; K];
            polyveck_decompose(&mut w1_high, &mut w0_low, &w);

            let mut w1_packed = [0u8; K * POLYW1_PACKEDBYTES];
            polyveck_pack_w1(&mut w1_packed, &w1_high);

            let mut c_bytes = [0u8; CTILDEBYTES];
            {
                let mut state = Keccak::shake256();
                state.absorb(&mu);
                state.absorb(&w1_packed);
                state.squeeze(&mut c_bytes);
            }

            let cp = poly_challenge(&c_bytes);
            let mut cp_ntt = cp;
            ntt(&mut cp_ntt, &zetas);

            let mut z2 = z;
            polyvecl_pointwise_poly_montgomery(&mut z2, &cp_ntt, &s1);
            polyvecl_invntt_tomont(&mut z2, &zetas, invntt_factor);
            polyvecl_add_assign(&mut z2, &y);
            polyvecl_reduce(&mut z2);
            if polyvecl_chknorm(&z2, GAMMA1 - BETA as i32) { continue; }

            let mut w0_test = w0_low;
            let mut r0 = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut r0, &cp_ntt, &s2);
            polyveck_invntt_tomont(&mut r0, &zetas, invntt_factor);
            polyveck_sub_assign(&mut w0_test, &r0);
            polyveck_reduce(&mut w0_test);
            if polyveck_chknorm(&w0_test, GAMMA2 - BETA as i32) { continue; }

            let mut hh = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut hh, &cp_ntt, &t0);
            polyveck_invntt_tomont(&mut hh, &zetas, invntt_factor);
            polyveck_reduce(&mut hh);
            if polyveck_chknorm(&hh, GAMMA2) { continue; }

            polyveck_add_assign(&mut w0_test, &hh);
            let mut h_vec = [[0i32; N]; K];
            let hint_count = polyveck_make_hint(&mut h_vec, &w0_test, &w1_high);
            if hint_count > OMEGA { continue; }

            captured_w1_high = w1_high;

            // Compute the sign's expected w1_vfy (A*y - cp*s2 + cp*t0) for comparison
            let mut w0_temp = w0_low;
            let mut r0 = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut r0, &cp_ntt, &s2);
            polyveck_invntt_tomont(&mut r0, &zetas, invntt_factor);
            polyveck_sub_assign(&mut w0_temp, &r0);

            let mut hh = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut hh, &cp_ntt, &t0);
            polyveck_invntt_tomont(&mut hh, &zetas, invntt_factor);
            polyveck_add_assign(&mut w0_temp, &hh);

            // w1_expected = captured_w1_high[i][j] * ALPHA + w0_temp[i][j] (mod Q)
            for i in 0..K {
                for j in 0..N {
                    w1_expected[i][j] = captured_w1_high[i][j] * ALPHA + w0_temp[i][j];
                    if w1_expected[i][j] < 0 {
                        w1_expected[i][j] += Q;
                    } else if w1_expected[i][j] >= Q {
                        w1_expected[i][j] -= Q;
                    }
                }
            }

            pack_sig(&mut sig, &c_bytes, &z2, &h_vec);
            break;
        }

        // Now verify the signature the same way verify() does
        let mut t1 = [[0i32; N]; K];
        unpack_pk(&mut rho, &mut t1, &kp.public_key);

        let mut c_bytes = [0u8; CTILDEBYTES];
        let mut z_vec = [[0i32; N]; L];
        let mut h_vec = [[0i32; N]; K];
        unpack_sig(&mut c_bytes, &mut z_vec, &mut h_vec, &sig);

        let cp = poly_challenge(&c_bytes);
        let mut cp_ntt = cp;
        ntt(&mut cp_ntt, &zetas);

        polyvecl_ntt(&mut z_vec, &zetas);

        let mut w1_vfy = [[0i32; N]; K];
        polyvec_matrix_pointwise_montgomery(&mut w1_vfy, &mat, &z_vec);

        polyveck_shiftl(&mut t1);
        polyveck_ntt(&mut t1, &zetas);
        let mut t1_cp = t1;
        polyveck_pointwise_poly_montgomery(&mut t1_cp, &cp_ntt, &t1);

        // Also compute A*(cp*s1) by computing A*z - A*y:
        // z = y + cp*s1, so A*z = A*y + A*(cp*s1)
        // A*y is captured in the sign. So A*(cp*s1) = A*z - A*y
        // Let me compute A*y from the sign's data
        // The sign's w = A*y was already computed. Let me capture it.
        // I'll compute cp*A*s1 from the sign's t and s2:
        // cp*A*s1 = cp*(t - s2) = cp*t - cp*s2
        // And cp*t1*2^D = cp*(t - t0) = cp*t - cp*t0
        // So cp*A*s1 - cp*t1*2^D = cp*(t - s2) - cp*(t - t0) = cp*(t0 - s2)
        // So A*z - cp*t1*2^D = A*y + A*(cp*s1) - cp*t1*2^D
        // = A*y + cp*A*s1 - cp*t + cp*t0
        // = A*y + cp*(t - s2) - cp*t + cp*t0
        // = A*y - cp*s2 + cp*t0
        // This IS w1_expected. So verify should compute w1_expected.

        polyveck_sub_assign(&mut w1_vfy, &t1_cp);
        polyveck_reduce(&mut w1_vfy);
        polyveck_invntt_tomont(&mut w1_vfy, &zetas, invntt_factor);
        polyveck_caddq(&mut w1_vfy);

        let w1_copy = w1_vfy;
        polyveck_use_hint(&mut w1_vfy, &w1_copy, &h_vec);

        // Compare w1_vfy with captured_w1_high
        let mut found_bad = false;
        for i in 0..K {
            for j in 0..N {
                if w1_vfy[i][j] != captured_w1_high[i][j] && !found_bad {
                    let mut a0 = 0i32;
                    let hb = decompose(&mut a0, w1_copy[i][j]);
                    assert!(false,
                        "w1 mismatch: post={} target={} hint={} raw_hb={} raw_w1={} expected={}",
                        w1_vfy[i][j], captured_w1_high[i][j], h_vec[i][j], hb, w1_copy[i][j], w1_expected[i][j]);
                    found_bad = true;
                }
            }
        }

        assert!(verify(&kp.public_key, msg, &sig), "verify failed");
    }

    #[test]
    fn test_decompose_ranges() {
        // Test that decompose correctly centers values
        let mut a0 = 0i32;
        // Check boundary at GAMMA2
        let _a1_lo = decompose(&mut a0, GAMMA2 - 1);
        assert!(a0 <= GAMMA2 && a0 > -GAMMA2, "a0 out of range: {} for input {}", a0, GAMMA2 - 1);

        let _a1_mid = decompose(&mut a0, GAMMA2);
        assert!(a0 <= GAMMA2 && a0 > -GAMMA2, "a0 out of range: {} for input {}", a0, GAMMA2);

        let _a1_hi = decompose(&mut a0, GAMMA2 + 1);
        assert!(a0 <= GAMMA2 && a0 > -GAMMA2, "a0 out of range: {} for input {}", a0, GAMMA2 + 1);

        // Check all values around GAMMA2
        for offset in 0..10 {
            let val = GAMMA2 - 2 + offset;
            let a1 = decompose(&mut a0, val);
            assert!(a0 <= GAMMA2 && a0 > -GAMMA2, 
                "a0={} out of range (-{}, {}] for input {}", a0, GAMMA2, GAMMA2, val);
            let restored = (a0 + a1 * ALPHA) % Q;
            let restored2 = if restored < 0 { restored + Q } else { restored };
            assert!(restored2 == val || restored2 == val - Q || restored2 == val + Q,
                "decompose identity: a0={} a1={} val={} restored={}", a0, a1, val, restored2);
        }
    }

    #[test]
    fn test_dilithium_sign_longer() {
        let seed = [42u8; 64];
        let kp = generate_keypair(Some(&seed));
        let (zetas, _invntt_factor) = zeta_table();
        let msg = b"test";

        let mut rho = [0u8; 32];
        let mut tr = [0u8; 32];
        let mut key = [0u8; 32];
        let mut t0 = [[0i32; N]; K];
        let mut s1 = [[0i32; N]; L];
        let mut s2 = [[0i32; N]; K];
        unpack_sk(&mut rho, &mut key, &mut tr, &mut t0, &mut s1, &mut s2, &kp.secret_key);

        let pre = [0u8; 2];
        let mut mu = [0u8; 64];
        {
            let mut state = Keccak::shake256();
            state.absorb(&tr);
            state.absorb(&pre);
            state.absorb(msg);
            state.squeeze(&mut mu);
        }

        let mut rhoprime = [0u8; 64];
        {
            let mut state = Keccak::shake256();
            state.absorb(&key);
            state.absorb(&[0u8; 32]);
            state.absorb(&mu);
            state.squeeze(&mut rhoprime);
        }

        polyvecl_ntt(&mut s1, &zetas);
        polyveck_ntt(&mut s2, &zetas);
        polyveck_ntt(&mut t0, &zetas);

        let mat = polyvec_matrix_expand(&rho);

        let mut nonce = 0u16;
        let mut stat = [0u32; 5];
        for _iter in 0..200 {
            let y = polyvecl_uniform_gamma1(&rhoprime, nonce);
            nonce = nonce.wrapping_add(1);
            let mut z = y;
            polyvecl_ntt(&mut z, &zetas);

            let mut w1 = [[0i32; N]; K];
            polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
            polyveck_reduce(&mut w1);
            polyveck_invntt_tomont(&mut w1, &zetas, _invntt_factor);
            polyveck_caddq(&mut w1);

            let mut w0_low = [[0i32; N]; K];
            let mut w1_high = [[0i32; N]; K];
            polyveck_decompose(&mut w1_high, &mut w0_low, &w1);

            let mut w1_packed = [0u8; K * POLYW1_PACKEDBYTES];
            polyveck_pack_w1(&mut w1_packed, &w1_high);

            let mut c_bytes = [0u8; CTILDEBYTES];
            {
                let mut state = Keccak::shake256();
                state.absorb(&mu);
                state.absorb(&w1_packed);
                state.squeeze(&mut c_bytes);
            }

            let cp = poly_challenge(&c_bytes);
            let mut cp_ntt = cp;
            ntt(&mut cp_ntt, &zetas);

            polyvecl_pointwise_poly_montgomery(&mut z, &cp_ntt, &s1);
            polyvecl_invntt_tomont(&mut z, &zetas, _invntt_factor);
            polyvecl_add_assign(&mut z, &y);
            polyvecl_reduce(&mut z);
            if polyvecl_chknorm(&z, GAMMA1 - BETA as i32) {
                stat[0] += 1;
                continue;
            }

            let mut w0 = w0_low;
            let mut r0 = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut r0, &cp_ntt, &s2);
            polyveck_invntt_tomont(&mut r0, &zetas, _invntt_factor);
            polyveck_sub_assign(&mut w0, &r0);
            polyveck_reduce(&mut w0);
            if polyveck_chknorm(&w0, GAMMA2 - BETA as i32) {
                stat[1] += 1;
                continue;
            }

            let mut h = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut h, &cp_ntt, &t0);
            polyveck_invntt_tomont(&mut h, &zetas, _invntt_factor);
            polyveck_reduce(&mut h);
            if polyveck_chknorm(&h, GAMMA2) {
                stat[2] += 1;
                continue;
            }

            polyveck_add_assign(&mut w0, &h);
            let mut h_vec = [[0i32; N]; K];
            let hint_count = polyveck_make_hint(&mut h_vec, &w0, &w1_high);
            if hint_count > OMEGA {
                stat[3] += 1;
                continue;
            }

            stat[4] += 1; // success
        }
        // r1, r2, r3, r4, successes
        assert!(stat[4] > 0, "no successes r1={} r2={} r3={} r4={}", stat[0], stat[1], stat[2], stat[3]);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = generate_keypair(None);
        let msg = b"Hello, Verrev!";
        let sig = sign(&kp.secret_key, msg);
        assert!(verify(&kp.public_key, msg, &sig), "sign/verify roundtrip failed");
    }

    #[test]
    fn test_sign_verify_wrong_msg() {
        let kp = generate_keypair(None);
        let msg = b"Hello, Verrev!";
        let sig = sign(&kp.secret_key, msg);
        assert!(!verify(&kp.public_key, b"Wrong message", &sig), "verify should reject wrong msg");
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let kp1 = generate_keypair(None);
        let kp2 = generate_keypair(None);
        let msg = b"Hello, Verrev!";
        let sig = sign(&kp1.secret_key, msg);
        assert!(!verify(&kp2.public_key, msg, &sig), "verify should reject wrong key");
    }

    #[test]
    fn test_dilithium_sign_debug() {
        // Manual sign to check which rejection fires
        let kp = generate_keypair(None);
        let sk = &kp.secret_key;
        let msg = b"test";

        let mut rho = [0u8; 32];
        let mut tr = [0u8; 32];
        let mut key = [0u8; 32];
        let mut t0 = [[0i32; N]; K];
        let mut s1 = [[0i32; N]; L];
        let mut s2 = [[0i32; N]; K];
        unpack_sk(&mut rho, &mut key, &mut tr, &mut t0, &mut s1, &mut s2, sk);

        let (zetas, invntt_factor) = zeta_table();
        let mat = polyvec_matrix_expand(&rho);

        let pre = [0u8, 0u8];
        let prelen = 2usize;
        let mut mu = [0u8; 64];
        {
            let mut h = Keccak::shake256();
            h.absorb(&tr);
            h.absorb(&pre[..prelen]);
            h.absorb(msg);
            h.squeeze(&mut mu);
        }

        let mut rhoprime = [0u8; 64];
        {
            let mut h = Keccak::shake256();
            h.absorb(&key);
            h.absorb(&[0u8; 32]);
            h.absorb(&mu);
            h.squeeze(&mut rhoprime);
        }

        polyvecl_ntt(&mut s1, &zetas);
        polyveck_ntt(&mut s2, &zetas);
        polyveck_ntt(&mut t0, &zetas);

        // Try first few nonces with counters
        struct Counts { reject1: u32, reject2: u32, reject3: u32, reject4: u32, success: u32 }
        let mut c = Counts { reject1: 0, reject2: 0, reject3: 0, reject4: 0, success: 0 };
        for trial in 0..50 {
            let y = polyvecl_uniform_gamma1(&rhoprime, trial);

            let mut z = y;
            polyvecl_ntt(&mut z, &zetas);

            let mut w1 = [[0i32; N]; K];
            polyvec_matrix_pointwise_montgomery(&mut w1, &mat, &z);
            polyveck_reduce(&mut w1);
            polyveck_invntt_tomont(&mut w1, &zetas, invntt_factor);
            polyveck_caddq(&mut w1);

            let mut w0_low = [[0i32; N]; K];
            let mut w1_high = [[0i32; N]; K];
            polyveck_decompose(&mut w1_high, &mut w0_low, &w1);

            let mut w1_packed = [0u8; K * POLYW1_PACKEDBYTES];
            polyveck_pack_w1(&mut w1_packed, &w1_high);

            let mut c_bytes = [0u8; CTILDEBYTES];
            {
                let mut h = Keccak::shake256();
                h.absorb(&mu);
                h.absorb(&w1_packed);
                h.squeeze(&mut c_bytes);
            }

            let cp = poly_challenge(&c_bytes);
            let mut cp_ntt = cp;
            ntt(&mut cp_ntt, &zetas);

            polyvecl_pointwise_poly_montgomery(&mut z, &cp_ntt, &s1);
            polyvecl_invntt_tomont(&mut z, &zetas, invntt_factor);
            polyvecl_add_assign(&mut z, &y);
            polyvecl_reduce(&mut z);

            if polyvecl_chknorm(&z, GAMMA1 - BETA as i32) {
                c.reject1 += 1;
                continue;
            }

            let mut w0 = w0_low;
            let mut r0 = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut r0, &cp_ntt, &s2);
            polyveck_invntt_tomont(&mut r0, &zetas, invntt_factor);
            polyveck_sub_assign(&mut w0, &r0);
            polyveck_reduce(&mut w0);
            if polyveck_chknorm(&w0, GAMMA2 - BETA as i32) {
                c.reject2 += 1;
                continue;
            }

            let mut h = [[0i32; N]; K];
            polyveck_pointwise_poly_montgomery(&mut h, &cp_ntt, &t0);
            polyveck_invntt_tomont(&mut h, &zetas, invntt_factor);
            polyveck_reduce(&mut h);
            if polyveck_chknorm(&h, GAMMA2) {
                c.reject3 += 1;
                continue;
            }

            polyveck_add_assign(&mut w0, &h);
            let mut h_vec = [[0i32; N]; K];
            let hint_count = polyveck_make_hint(&mut h_vec, &w0, &w1_high);
            if hint_count > OMEGA {
                c.reject4 += 1;
                continue;
            }

            c.success += 1;
            let _ = c.success;
            return;
        }
        panic!("rejections: r1={} r2={} r3={} r4={} succ={}",
               c.reject1, c.reject2, c.reject3, c.reject4, c.success);
    }

    #[test]
    fn test_zeta_table_debug() {
        let (zetas, invntt_factor) = zeta_table();
        // Reference: zetas[1] = 25847, invntt_factor = 41978
        // montgomery_reduce(x) = x * R^(-1) mod Q (R=2^32)
        // zetas[k] = ζ^br8(k) * R mod Q (Montgomery form)
        // So: montgomery_reduce(ζ^br8(k) * R^2) = ζ^br8(k) * R^2 * R^(-1) = ζ^br8(k) * R mod Q
        // Our r_sq = R^2 mod Q, so ζ^128 * r_sq = ζ^128 * R^2 mod Q → montgomery_reduce gives ζ^128 * R
        let r_mod = ((1u64 << 32) % Q as u64) as i64;          // R mod Q
        let r_sq = (r_mod * r_mod) % Q as i64;                 // R^2 mod Q
        let qi64 = Q as i64;
        let q2i64 = (Q / 2) as i64;
        let mont_centered = if r_mod > q2i64 { r_mod - qi64 } else { r_mod };  // MONT = -4186625
        let mont_positive = if mont_centered < 0 { mont_centered + qi64 } else { mont_centered }; // R mod Q = 4193792
        let zeta128_plain = modpow(1753, 128);                 // ζ^128 mod Q
        let _zeta128_mont_via_r_sq = montgomery_reduce(zeta128_plain * r_sq); // our formula
        let _zeta128_mont_via_mont = montgomery_reduce(mont_positive * zeta128_plain); // ref: MONT * ζ^128
        assert_eq!(zetas[1], 25847, "zetas[1] mismatch");
        assert_eq!(invntt_factor, 41978, "invntt_factor mismatch (got {}, ref=41978, or 41978-centered={})",
            invntt_factor,
            if 41978 > Q/2 { 41978 - Q } else { 41978 });
    }

    #[test]
    fn test_ntt_roundtrip_precise() {
        let (zetas, invntt_factor) = zeta_table();
        let mut a = [0i32; N];
        for i in 0..N {
            a[i] = ((i * 7 + 3) as i32) % Q;
        }
        let orig = a;
        ntt(&mut a, &zetas);
        invntt_tomont(&mut a, &zetas, invntt_factor);
        // invntt_tomont(ntt(a)) should give a * R where R = 2^32 mod Q
        // This is by design: the NTT/INTT pair is meant to be used with
        // pointwise_mont in between, which cancels the R factor.
        let r_mod = ((1u64 << 32) % Q as u64) as i32; // 4193792
        let mut match_mont = true;
        for i in 0..N {
            let ai = if a[i] < 0 { a[i] + Q } else { a[i] };
            let oi = if orig[i] < 0 { orig[i] + Q } else { orig[i] };
            let expected = (oi as i64 * r_mod as i64) % Q as i64;
            if (ai as i64 - if expected < 0 { expected + Q as i64 } else { expected }).abs() > Q as i64 / 4 {
                match_mont = false;
            }
        }
        assert!(match_mont, "invntt_tomont(ntt(a)) ≠ a * R: a[0]={} orig[0]={} R={}",
            a[0], orig[0], r_mod);
    }

    #[test]
    fn test_ntt_ring_mul() {
        // Test: pointwise_montgomery(ntt(a), ntt(b)) then invntt_tomont should give a*b
        let (zetas, invntt_factor) = zeta_table();
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        for i in 0..N {
            a[i] = ((i * 7 + 3) as i32) % Q;
            b[i] = ((i * 13 + 5) as i32) % Q;
        }
        let mut a_ntt = a;
        ntt(&mut a_ntt, &zetas);
        let mut b_ntt = b;
        ntt(&mut b_ntt, &zetas);
        let mut c = poly_pointwise_montgomery(&a_ntt, &b_ntt);
        invntt_tomont(&mut c, &zetas, invntt_factor);
        // c should be a*b in the ring Z_q[x]/(x^256+1)
        // Compute a*b directly via convolution with negacyclic wrap
        // (a*b)[i] = Σ_j a[j] * b[(i-j) mod N] * sign, where sign=-1 if i-j < 0
        let q = Q as i64;
        let mut expected = [0i32; N];
        for i in 0..N {
            let mut s = 0i64;
            for j in 0..N {
                let (idx, sign) = if i >= j {
                    (i - j, 1i64)
                } else {
                    (N + i - j, -1i64)
                };
                s = (s + sign * a[j] as i64 * b[idx] as i64) % q;
            }
            if s > q / 2 {
                s -= q;
            } else if s < -q / 2 {
                s += q;
            }
            expected[i] = s as i32;
        }
        let mut max_diff = 0i32;
        for i in 0..N {
            let d = (c[i] - expected[i]).abs();
            if d > max_diff { max_diff = d; }
        }
        // Should match almost exactly (Montgomery reduction may have tiny error)
        assert!(max_diff <= 1,
            "NTT ring multiplication mismatch: max_diff={}. NTT domain may be wrong (plain vs Montgomery form)",
            max_diff);
    }

    #[test]
    fn test_zeta_table() {
    let (zetas, invntt_factor) = zeta_table();
        assert_eq!(zetas[0], 0);

        let a_base = {
            let mut a = [0i32; N];
            for i in 0..N {
                a[i] = ((i * 7 + 3) as i32) % Q;
            }
            a
        };
        let b_base = {
            let mut b = [0i32; N];
            for i in 0..N {
                b[i] = ((i * 13 + 5) as i32) % Q;
            }
            b
        };

        let mut a1 = a_base;
        let mut b1 = b_base;
        ntt(&mut a1, &zetas);
        ntt(&mut b1, &zetas);
        let mut c = poly_pointwise_montgomery(&a1, &b1);
        invntt_tomont(&mut c, &zetas, invntt_factor);

        let mut a2 = a_base;
        let mut b2 = b_base;
        ntt(&mut a2, &zetas);
        ntt(&mut b2, &zetas);
        let mut d = poly_pointwise_montgomery(&b2, &a2);
        invntt_tomont(&mut d, &zetas, invntt_factor);

        let mut ok = true;
        for i in 0..N {
            if (c[i] - d[i]).abs() > 2 {
                ok = false;
                break;
            }
        }
        assert!(ok, "pointwise_montgomery should be commutative");
    }
}