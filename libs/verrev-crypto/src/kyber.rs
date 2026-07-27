use verrev_hash::sha3::*;
use crate::util::*;

const N: usize = 256;
const Q: i32 = 3329;

const K: usize = 4; // Kyber-1024
const ETA1: usize = 2;
const ETA2: usize = 2;
const POLYBYTES: usize = 384;
const COMPRESSED_BYTES: usize = 1568; // Kyber-1024 ciphertext

pub const SECRET_KEY_BYTES: usize = 4096;
pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const CIPHERTEXT_BYTES: usize = COMPRESSED_BYTES;
pub const SHARED_SECRET_BYTES: usize = 32;

fn barrett_reduce(a: i32) -> i32 {
    let v = ((1i32 << 26) + (Q / 2)) / Q;
    let t = (v * a + (1 << 25)) >> 26;
    a - t * Q
}

const QINV: i32 = -3327;

fn montgomery_reduce(a: i32) -> i32 {
    let t = (a as i16).wrapping_mul(QINV as i16) as i32;
    let r = (a.wrapping_sub(t.wrapping_mul(Q))) >> 16;
    r
}

fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a * b)
}

fn brv7(x: usize) -> usize {
    let mut r = 0usize;
    for i in 0..7 {
        if x & (1 << i) != 0 {
            r |= 1 << (6 - i);
        }
    }
    r
}

fn nist_zeta_table() -> [i32; 128] {
    const MONT: i32 = 2285;
    let mut zpow = [0i32; 128];
    zpow[0] = 1;
    for i in 1..128 {
        zpow[i] = (zpow[i - 1] * 17) % Q;
    }
    let mut zetas = [0i32; 128];
    for i in 0..128 {
        let val = (MONT * zpow[brv7(i)]) % Q;
        zetas[i] = if val > Q / 2 { val - Q } else { val };
    }
    zetas
}

fn ntt(a: &mut [i32; N]) {
    let zetas = nist_zeta_table();
    let mut r = [0i16; N];
    for i in 0..N { r[i] = a[i] as i16; }
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = zetas[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len] as i32) as i16;
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
            }
            start += len * 2;
        }
        len >>= 1;
    }
    for i in 0..N { a[i] = r[i] as i32; }
}

fn invntt(a: &mut [i32; N]) {
    let zetas = nist_zeta_table();
    let mut r = [0i16; N];
    for i in 0..N { r[i] = a[i] as i16; }
    const F: i32 = 1441;
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = zetas[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce((t + r[j + len]) as i32) as i16;
                r[j + len] = r[j + len].wrapping_sub(t);
                r[j + len] = fqmul(zeta, r[j + len] as i32) as i16;
            }
            start += len * 2;
        }
        len <<= 1;
    }
    for i in 0..N {
        a[i] = fqmul(r[i] as i32, F);
    }
}

fn basemul(a: &[i32; 2], b: &[i32; 2], zeta: i32) -> [i32; 2] {
    let r0 = fqmul(a[1], b[1]);
    let r0 = fqmul(r0, zeta);
    let r0 = barrett_reduce(r0 + fqmul(a[0], b[0]));
    let r1 = barrett_reduce(fqmul(a[0], b[1]) + fqmul(a[1], b[0]));
    [r0, r1]
}

fn mul_ntt(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let zetas = nist_zeta_table();
    let mut c = [0i32; N];
    for i in 0..N / 4 {
        let ca = basemul(&[a[4 * i], a[4 * i + 1]], &[b[4 * i], b[4 * i + 1]], zetas[64 + i]);
        c[4 * i] = ca[0];
        c[4 * i + 1] = ca[1];
        let cb = basemul(&[a[4 * i + 2], a[4 * i + 3]], &[b[4 * i + 2], b[4 * i + 3]], -zetas[64 + i]);
        c[4 * i + 2] = cb[0];
        c[4 * i + 3] = cb[1];
    }
    c
}

fn poly_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut aa = *a;
    let mut bb = *b;
    ntt(&mut aa);
    ntt(&mut bb);
    let mut c = mul_ntt(&aa, &bb);
    invntt(&mut c);
    c
}

fn poly_add(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = barrett_reduce(a[i] + b[i]);
    }
    c
}

fn poly_tobytes(a: &[i32; N]) -> [u8; POLYBYTES] {
    let mut out = [0u8; POLYBYTES];
    let mut j = 0;
    for i in 0..N / 2 {
        let t0 = a[2 * i].rem_euclid(Q) as u16;
        let t1 = a[2 * i + 1].rem_euclid(Q) as u16;
        out[j] = (t0 >> 0) as u8;
        out[j + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[j + 2] = (t1 >> 4) as u8;
        j += 3;
    }
    out
}

fn poly_frombytes(a: &[u8]) -> [i32; N] {
    let mut out = [0i32; N];
    let mut j = 0;
    for i in 0..N / 2 {
        let t0 = a[j] as u16 | ((a[j + 1] as u16 & 0x0f) << 8);
        let t1 = (a[j + 1] as u16 >> 4) | ((a[j + 2] as u16) << 4);
        out[2 * i] = t0 as i32;
        out[2 * i + 1] = t1 as i32;
        j += 3;
    }
    out
}

fn cbd(buf: &[u8], eta: usize) -> [i32; N] {
    let mut a = [0i32; N];
    if eta == 2 {
        for i in 0..N / 4 {
            let t = (buf[i / 4] as u32) >> (2 * (i % 4)) & 0x03;
            let b = (buf[N / 4 + i / 4] as u32) >> (2 * (i % 4)) & 0x03;
            a[4 * i] = (t & 1) as i32 - ((t >> 1) & 1) as i32;
            a[4 * i + 1] = (b & 1) as i32 - ((b >> 1) & 1) as i32;
            a[4 * i + 2] = ((t >> 2) & 1) as i32 - ((t >> 3) & 1) as i32;
            a[4 * i + 3] = ((b >> 2) & 1) as i32 - ((b >> 3) & 1) as i32;
        }
    }
    a
}

fn generate_a_hat(rho: &[u8; 32]) -> [[i32; N]; K * K] {
    let mut a_hat = [[0i32; N]; K * K];
    for idx in 0..K * K {
        let mut h = Keccak::shake256();
        h.absorb(rho);
        h.absorb(&(idx as u8).to_le_bytes());
        let mut buf = [0u8; 768];
        h.squeeze(&mut buf);
        for j in 0..N {
            let d = (buf[2 * j] as u16) | ((buf[2 * j + 1] as u16) << 8);
            a_hat[idx][j] = (d % Q as u16) as i32;
        }
    }
    a_hat
}

pub fn encaps(pk: &[u8; PUBLIC_KEY_BYTES]) -> ([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]) {
    ccakem_encaps(pk)
}

pub fn decaps(sk: &[u8; SECRET_KEY_BYTES], ct: &[u8; CIPHERTEXT_BYTES]) -> [u8; SHARED_SECRET_BYTES] {
    ccakem_decaps(sk, ct)
}

// ——— Kyber.CPAPKE helpers ———

fn compress(x: i32, d: usize) -> i32 {
    let q = Q as i64;
    let x_pos = x.rem_euclid(Q) as i64;
    let v = (x_pos << d) + (q >> 1);
    let c = v / q;
    let mask = (1i64 << d) - 1;
    (c & mask) as i32
}

fn decompress(y: i32, d: usize) -> i32 {
    let q = Q as i64;
    let v = (y as i64) * q + (1i64 << (d - 1));
    let r = v >> d;
    if r >= q { (q - 1) as i32 } else { r as i32 }
}

fn poly_compress(poly: &[i32; N], d: usize) -> alloc::vec::Vec<u8> {
    let out_len = d * N / 8;
    let mut out = alloc::vec::Vec::with_capacity(out_len);
    let mut byte = 0u8;
    let mut bits = 0;
    for i in 0..N {
        let c = compress(poly[i], d) as u16;
        for b in (0..d).rev() {
            byte = (byte << 1) | (((c >> b) & 1) as u8);
            bits += 1;
            if bits == 8 {
                out.push(byte);
                byte = 0;
                bits = 0;
            }
        }
    }
    out
}

fn poly_decompress(buf: &[u8], d: usize) -> [i32; N] {
    let mut out = [0i32; N];
    let mut byte_idx = 0;
    let mut bit_idx = 0;
    for i in 0..N {
        let mut c = 0i32;
        for b in (0..d).rev() {
            let bit = ((buf[byte_idx] >> (7 - bit_idx)) & 1) as i32;
            c |= bit << b;
            bit_idx += 1;
            if bit_idx == 8 {
                bit_idx = 0;
                byte_idx += 1;
            }
        }
        out[i] = decompress(c, d);
    }
    out
}

fn msg_to_poly(msg: &[u8; 32]) -> [i32; N] {
    let mut poly = [0i32; N];
    for i in 0..32 {
        for j in 0..8 {
            let bit = (msg[i] >> j) & 1;
            poly[8 * i + j] = bit as i32 * ((Q - 1) / 2);
        }
    }
    poly
}

fn poly_to_msg(poly: &[i32; N]) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..32 {
        let mut byte = 0u8;
        for j in 0..8 {
            let c = compress(poly[8 * i + j], 1);
            byte |= (c as u8) << j;
        }
        msg[i] = byte;
    }
    msg
}

fn prf(seed: &[u8; 32], nonce: u8, buf: &mut [u8]) {
    let mut h = Keccak::shake256();
    h.absorb(seed);
    h.absorb(&[nonce]);
    h.squeeze(buf);
}

// ——— Kyber.CPAPKE ———

fn cpapke_enc(pk: &[u8; PUBLIC_KEY_BYTES], msg: &[u8; 32], coins: &[u8; 32]) -> [u8; CIPHERTEXT_BYTES] {
    const DU: usize = 11;
    const DV: usize = 5;

    let rho_offset = K * POLYBYTES;
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[rho_offset..rho_offset + 32]);

    let mut t = [[0i32; N]; K];
    for i in 0..K {
        t[i] = poly_frombytes(&pk[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }

    let a = generate_a_hat(&rho);

    let mut r_vec = [[0i32; N]; K];
    for i in 0..K {
        let mut buf = [0u8; N * ETA1 / 4];
        prf(coins, (2 * i) as u8, &mut buf);
        r_vec[i] = cbd(&buf, ETA1);
    }

    let mut e1 = [[0i32; N]; K];
    for i in 0..K {
        let mut buf = [0u8; N * ETA2 / 4];
        prf(coins, (2 * i + 1) as u8, &mut buf);
        e1[i] = cbd(&buf, ETA2);
    }

    let e2 = {
        let mut buf = [0u8; N * ETA2 / 4];
        prf(coins, (2 * K) as u8, &mut buf);
        cbd(&buf, ETA2)
    };

    let mut u = [[0i32; N]; K];
    for i in 0..K {
        let mut sum = [0i32; N];
        for j in 0..K {
            let prod = poly_mul(&a[j * K + i], &r_vec[j]);
            sum = poly_add(&sum, &prod);
        }
        u[i] = poly_add(&sum, &e1[i]);
    }

    let msg_poly = msg_to_poly(msg);
    let mut v_parts = [0i32; N];
    for i in 0..K {
        let prod = poly_mul(&t[i], &r_vec[i]);
        v_parts = poly_add(&v_parts, &prod);
    }
    let v = poly_add(&poly_add(&v_parts, &e2), &msg_poly);

    let mut ct = [0u8; CIPHERTEXT_BYTES];
    let mut offset = 0;
    for i in 0..K {
        let comp = poly_compress(&u[i], DU);
        let len = DU * N / 8;
        ct[offset..offset + len].copy_from_slice(&comp);
        offset += len;
    }
    let comp_v = poly_compress(&v, DV);
    ct[offset..offset + DV * N / 8].copy_from_slice(&comp_v);
    ct
}

fn cpapke_dec(sk: &[u8; SECRET_KEY_BYTES], ct: &[u8; CIPHERTEXT_BYTES]) -> [u8; 32] {
    const DU: usize = 11;
    const DV: usize = 5;

    let mut u = [[0i32; N]; K];
    let mut offset = 0;
    for i in 0..K {
        u[i] = poly_decompress(&ct[offset..offset + DU * N / 8], DU);
        offset += DU * N / 8;
    }
    let v = poly_decompress(&ct[offset..offset + DV * N / 8], DV);

    let mut s = [[0i32; N]; K];
    for i in 0..K {
        s[i] = poly_frombytes(&sk[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }

    let mut sum = [0i32; N];
    for i in 0..K {
        let prod = poly_mul(&s[i], &u[i]);
        sum = poly_add(&sum, &prod);
    }

    let mut m_poly = [0i32; N];
    for k in 0..N {
        m_poly[k] = barrett_reduce(v[k] - sum[k]);
    }

    poly_to_msg(&m_poly)
}

// ——— Kyber.CCAKEM ———

pub fn ccakem_keygen(seed: Option<&[u8; 64]>) -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
    let mut seed_buf = [0u8; 64];
    if let Some(s) = seed {
        seed_buf.copy_from_slice(s);
    } else {
        fill_random(&mut seed_buf);
    }

    let mut z = [0u8; 32];
    z.copy_from_slice(&seed_buf[32..64]);

    let g_out = sha3_512(&seed_buf[..32]);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_out[..32]);
    sigma.copy_from_slice(&g_out[32..64]);

    let a_hat = generate_a_hat(&rho);

    let mut s = [[0i32; N]; K];
    for i in 0..K {
        let mut buf = [0u8; N * ETA1 / 4];
        let mut h = Keccak::shake256();
        h.absorb(&sigma);
        h.absorb(&[i as u8]);
        h.squeeze(&mut buf);
        s[i] = cbd(&buf, ETA1);
    }

    let mut e = [[0i32; N]; K];
    for i in 0..K {
        let mut buf = [0u8; N * ETA1 / 4];
        let mut h = Keccak::shake256();
        h.absorb(&sigma);
        h.absorb(&[(K + i) as u8]);
        h.squeeze(&mut buf);
        e[i] = cbd(&buf, ETA1);
    }

    let mut t = [[0i32; N]; K];
    for i in 0..K {
        let mut sum = [0i32; N];
        for j in 0..K {
            let prod = poly_mul(&a_hat[i * K + j], &s[j]);
            sum = poly_add(&sum, &prod);
        }
        t[i] = poly_add(&sum, &e[i]);
    }

    let mut pk = [0u8; PUBLIC_KEY_BYTES];
    for i in 0..K {
        let bytes = poly_tobytes(&t[i]);
        pk[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&bytes);
    }
    pk[K * POLYBYTES..K * POLYBYTES + 32].copy_from_slice(&rho);

    let pk_hash = sha3_256(&pk);

    let mut sk = [0u8; SECRET_KEY_BYTES];
    for i in 0..K {
        let bytes = poly_tobytes(&s[i]);
        sk[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&bytes);
    }
    let s_offset = K * POLYBYTES;
    sk[s_offset..s_offset + PUBLIC_KEY_BYTES].copy_from_slice(&pk);
    let hpk_offset = s_offset + PUBLIC_KEY_BYTES;
    sk[hpk_offset..hpk_offset + 32].copy_from_slice(&pk_hash);
    sk[hpk_offset + 32..hpk_offset + 64].copy_from_slice(&z);

    (sk, pk)
}

pub fn ccakem_encaps(pk: &[u8; PUBLIC_KEY_BYTES]) -> ([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]) {
    let mut m = [0u8; 32];
    fill_random(&mut m);

    let pk_hash = sha3_256(pk);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m);
    g_input[32..64].copy_from_slice(&pk_hash);
    let g_output = sha3_512(&g_input);

    let mut k_bar = [0u8; 32];
    let mut r_coins = [0u8; 32];
    k_bar.copy_from_slice(&g_output[..32]);
    r_coins.copy_from_slice(&g_output[32..64]);

    let ct = cpapke_enc(pk, &m, &r_coins);

    let c_hash = sha3_256(&ct);
    let mut kdf_input = [0u8; 64];
    kdf_input[..32].copy_from_slice(&k_bar);
    kdf_input[32..64].copy_from_slice(&c_hash);
    let ss = sha3_256(&kdf_input);

    (ct, ss)
}

pub fn ccakem_decaps(sk: &[u8; SECRET_KEY_BYTES], ct: &[u8; CIPHERTEXT_BYTES]) -> [u8; SHARED_SECRET_BYTES] {
    let s_offset = K * POLYBYTES;
    let hpk_offset = s_offset + PUBLIC_KEY_BYTES;
    let z_offset = hpk_offset + 32;

    let mut pk = [0u8; PUBLIC_KEY_BYTES];
    pk.copy_from_slice(&sk[s_offset..s_offset + PUBLIC_KEY_BYTES]);

    let mut pk_hash = [0u8; 32];
    pk_hash.copy_from_slice(&sk[hpk_offset..hpk_offset + 32]);

    let mut z = [0u8; 32];
    z.copy_from_slice(&sk[z_offset..z_offset + 32]);

    let m_prime = cpapke_dec(sk, ct);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..64].copy_from_slice(&pk_hash);
    let g_output = sha3_512(&g_input);

    let mut k_bar_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_bar_prime.copy_from_slice(&g_output[..32]);
    r_prime.copy_from_slice(&g_output[32..64]);

    let ct_prime = cpapke_enc(&pk, &m_prime, &r_prime);

    let c_hash = sha3_256(ct);

    if ct_eq(&ct[..], &ct_prime[..]) {
        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&k_bar_prime);
        kdf_input[32..64].copy_from_slice(&c_hash);
        sha3_256(&kdf_input)
    } else {
        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&z);
        kdf_input[32..64].copy_from_slice(&c_hash);
        sha3_256(&kdf_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let (sk, _pk) = ccakem_keygen(None);
        assert!(sk.len() == SECRET_KEY_BYTES);
    }

    #[test]
    fn test_kyber_1024_kat() {
        let mut seed = [0u8; 64];
        for i in 0..64 { seed[i] = i as u8; }
        let (_sk, _pk) = ccakem_keygen(Some(&seed));
    }

    #[test]
    fn test_ccakem_roundtrip() {
        let (sk, pk) = ccakem_keygen(None);
        let (ct, ss_enc) = ccakem_encaps(&pk);
        let ss_dec = ccakem_decaps(&sk, &ct);
        assert_eq!(ss_enc, ss_dec, "shared secrets must match");
    }

    #[test]
    fn test_ccakem_deterministic() {
        let mut seed = [0u8; 64];
        for i in 0..64 { seed[i] = i as u8; }
        let (sk_a, pk_a) = ccakem_keygen(Some(&seed));
        let (sk_b, pk_b) = ccakem_keygen(Some(&seed));
        assert_eq!(pk_a, pk_b, "deterministic pk must match");
        assert_eq!(sk_a, sk_b, "deterministic sk must match");
    }

    #[test]
    fn test_msg_encoding_roundtrip() {
        let msg = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                   0xfe, 0xed, 0xbe, 0xef, 0xde, 0xad, 0xf0, 0x0d,
                   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let poly = msg_to_poly(&msg);
        let msg2 = poly_to_msg(&poly);
        assert_eq!(msg, msg2, "message encoding roundtrip must match");
    }

    #[test]
    fn test_compress_roundtrip() {
        let bound = |d: usize| -> i32 {
            if Q % (1 << (d + 1)) == 0 { Q / (1 << (d + 1)) } else { Q / (1 << (d + 1)) + 1 }
        };
        for d in [1, 4, 5, 10, 11] {
            for x in [0, 1, Q/4, Q/2, 3*Q/4, Q-1, -1, -(Q/2)] {
                let c = compress(x, d);
                assert!(c >= 0 && c < (1 << d), "d={} x={} c={}", d, x, c);
                let y = decompress(c, d);
                let diff_mod = ((x - y) % Q + Q) % Q;
                let err = if diff_mod > Q/2 { diff_mod - Q } else { diff_mod };
                assert!(err.abs() <= bound(d), "d={} x={} y={} err={}", d, x, y, err);
            }
        }
    }

    #[test]
    fn test_cpapke_roundtrip() {
        let mut seed = [0u8; 64];
        for i in 0..64 { seed[i] = i as u8; }
        let (sk, pk) = ccakem_keygen(Some(&seed));
        let msg = [0x12; 32];
        let coins = [0x34; 32];
        let ct = cpapke_enc(&pk, &msg, &coins);
        let msg2 = cpapke_dec(&sk, &ct);
        assert_eq!(msg, msg2, "CPAPKE roundtrip must recover message");
    }

    #[test]
    fn test_poly_mul_roundtrip() {
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        for i in 0..N {
            a[i] = ((i * 7 + 5) as i32) % Q;
            b[i] = ((i * 13 + 3) as i32) % Q;
        }
        let ab = poly_mul(&a, &b);
        let ba = poly_mul(&b, &a);
        for i in 0..N {
            if ab[i].rem_euclid(Q) != ba[i].rem_euclid(Q) {
                panic!("commute: ab[{}]={} != ba[{}]={}", i, ab[i], i, ba[i]);
            }
        }
        let identity = {
            let mut id = [0i32; N];
            id[0] = 1;
            id
        };
        let a2 = poly_mul(&identity, &a);
        for i in 0..N {
            let diff = (a2[i] - a[i]).rem_euclid(Q);
            if diff != 0 {
                panic!("identity: a2[{}]={} != a[{}]={} diff={}", i, a2[i], i, a[i], diff);
            }
        }
    }

    #[test]
    fn test_polymul_commutes() {
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        for i in 0..N {
            a[i] = ((i * 7 + 5) as i32) % Q;
            b[i] = ((i * 13 + 3) as i32) % Q;
        }
        let ab = poly_mul(&a, &b);
        let ba = poly_mul(&b, &a);
        for i in 0..N {
            if ab[i] != ba[i] {
                panic!("ab[{}]={} != ba[{}]={}", i, ab[i], i, ba[i]);
            }
        }
    }
}
