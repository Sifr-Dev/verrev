//! ML-KEM-1024 as specified by FIPS 203.
//!
//! Public operations obtain fresh entropy from the operating system and report
//! failures. Fixed-seed operations are deliberately compiled only for tests.

use crate::util::{fill_random, RandomnessError};
use verrev_hash::sha3::*;

const N: usize = 256;
const Q: i32 = 3329;
const K: usize = 4;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 11;
const DV: usize = 5;
const POLYBYTES: usize = 384;
const PKE_SECRET_KEY_BYTES: usize = K * POLYBYTES;

pub const SECRET_KEY_BYTES: usize = 3168;
pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const CIPHERTEXT_BYTES: usize = 1568;
pub const SHARED_SECRET_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Randomness(RandomnessError),
    InvalidEncapsulationKey,
    InvalidDecapsulationKey,
}

impl From<RandomnessError> for Error {
    fn from(error: RandomnessError) -> Self {
        Self::Randomness(error)
    }
}

#[inline]
fn mod_q(value: i32) -> i32 {
    value.rem_euclid(Q)
}

#[inline]
fn add_q(a: i32, b: i32) -> i32 {
    mod_q(a + b)
}

#[inline]
fn sub_q(a: i32, b: i32) -> i32 {
    mod_q(a - b)
}

#[inline]
fn mul_q(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) % Q as i64) as i32
}

fn bit_rev7(value: usize) -> usize {
    let mut input = value;
    let mut output = 0;
    for _ in 0..7 {
        output = (output << 1) | (input & 1);
        input >>= 1;
    }
    output
}

fn mod_pow(mut base: i32, mut exponent: usize) -> i32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul_q(result, base);
        }
        base = mul_q(base, base);
        exponent >>= 1;
    }
    result
}

fn ntt_zetas() -> [i32; 128] {
    let mut zetas = [0; 128];
    for (index, zeta) in zetas.iter_mut().enumerate() {
        *zeta = mod_pow(17, bit_rev7(index));
    }
    zetas
}

fn base_case_zetas() -> [i32; 128] {
    let mut zetas = [0; 128];
    for (index, zeta) in zetas.iter_mut().enumerate() {
        *zeta = mod_pow(17, 2 * bit_rev7(index) + 1);
    }
    zetas
}

fn ntt(poly: &mut [i32; N]) {
    let zetas = ntt_zetas();
    let mut index = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = zetas[index];
            index += 1;
            for offset in 0..len {
                let j = start + offset;
                let t = mul_q(zeta, poly[j + len]);
                poly[j + len] = sub_q(poly[j], t);
                poly[j] = add_q(poly[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn inv_ntt(poly: &mut [i32; N]) {
    let zetas = ntt_zetas();
    let mut index = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = zetas[index];
            index -= 1;
            for offset in 0..len {
                let j = start + offset;
                let t = poly[j];
                poly[j] = add_q(t, poly[j + len]);
                poly[j + len] = mul_q(zeta, sub_q(poly[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let scale = mod_pow(128, (Q - 2) as usize);
    for coefficient in poly {
        *coefficient = mul_q(*coefficient, scale);
    }
}

fn multiply_ntts(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let zetas = base_case_zetas();
    let mut result = [0; N];
    for i in 0..128 {
        let a0 = a[2 * i];
        let a1 = a[2 * i + 1];
        let b0 = b[2 * i];
        let b1 = b[2 * i + 1];
        result[2 * i] = add_q(mul_q(a0, b0), mul_q(mul_q(a1, b1), zetas[i]));
        result[2 * i + 1] = add_q(mul_q(a0, b1), mul_q(a1, b0));
    }
    result
}

fn poly_add(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut result = [0; N];
    for i in 0..N {
        result[i] = add_q(a[i], b[i]);
    }
    result
}

fn poly_sub(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut result = [0; N];
    for i in 0..N {
        result[i] = sub_q(a[i], b[i]);
    }
    result
}

fn byte_encode(poly: &[i32; N], d: usize, output: &mut [u8]) {
    debug_assert_eq!(output.len(), 32 * d);
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut offset = 0;
    for coefficient in poly {
        let value = if d == 12 {
            mod_q(*coefficient) as u32
        } else {
            *coefficient as u32
        };
        accumulator |= value << bits;
        bits += d;
        while bits >= 8 {
            output[offset] = accumulator as u8;
            offset += 1;
            accumulator >>= 8;
            bits -= 8;
        }
    }
}

fn byte_decode(input: &[u8], d: usize) -> [i32; N] {
    debug_assert_eq!(input.len(), 32 * d);
    let mask = (1u32 << d) - 1;
    let mut poly = [0; N];
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut offset = 0;
    for coefficient in &mut poly {
        while bits < d {
            accumulator |= (input[offset] as u32) << bits;
            offset += 1;
            bits += 8;
        }
        let value = accumulator & mask;
        accumulator >>= d;
        bits -= d;
        *coefficient = if d == 12 {
            value as i32 % Q
        } else {
            value as i32
        };
    }
    poly
}

fn poly_tobytes(poly: &[i32; N]) -> [u8; POLYBYTES] {
    let mut output = [0; POLYBYTES];
    byte_encode(poly, 12, &mut output);
    output
}

fn poly_frombytes(input: &[u8]) -> [i32; N] {
    byte_decode(input, 12)
}

fn sample_ntt(rho: &[u8; 32], column: u8, row: u8) -> [i32; N] {
    let mut xof = Keccak::shake128();
    xof.absorb(rho);
    xof.absorb(&[column, row]);
    let mut poly = [0; N];
    let mut count = 0;
    let mut block = [0u8; 168];
    while count < N {
        xof.squeeze(&mut block);
        let mut offset = 0;
        while count < N && offset + 3 <= block.len() {
            let d1 = block[offset] as u16 | ((block[offset + 1] as u16 & 15) << 8);
            let d2 = (block[offset + 1] as u16 >> 4) | ((block[offset + 2] as u16) << 4);
            offset += 3;
            if d1 < Q as u16 {
                poly[count] = d1 as i32;
                count += 1;
            }
            if d2 < Q as u16 && count < N {
                poly[count] = d2 as i32;
                count += 1;
            }
        }
    }
    poly
}

fn generate_a_hat(rho: &[u8; 32]) -> [[i32; N]; K * K] {
    let mut matrix = [[0; N]; K * K];
    for row in 0..K {
        for column in 0..K {
            matrix[row * K + column] = sample_ntt(rho, column as u8, row as u8);
        }
    }
    matrix
}

fn sample_poly_cbd(input: &[u8], eta: usize) -> [i32; N] {
    debug_assert_eq!(input.len(), 64 * eta);
    let mut poly = [0; N];
    for i in 0..N {
        let mut x = 0;
        let mut y = 0;
        for j in 0..eta {
            let x_bit = 2 * i * eta + j;
            let y_bit = x_bit + eta;
            x += ((input[x_bit / 8] >> (x_bit % 8)) & 1) as i32;
            y += ((input[y_bit / 8] >> (y_bit % 8)) & 1) as i32;
        }
        poly[i] = mod_q(x - y);
    }
    poly
}

fn prf(seed: &[u8; 32], nonce: u8, eta: usize) -> [u8; 128] {
    let mut xof = Keccak::shake256();
    xof.absorb(seed);
    xof.absorb(&[nonce]);
    let mut output = [0; 128];
    xof.squeeze(&mut output[..64 * eta]);
    output
}

fn sampled_noise(seed: &[u8; 32], nonce: u8, eta: usize) -> [i32; N] {
    sample_poly_cbd(&prf(seed, nonce, eta)[..64 * eta], eta)
}

fn compress(value: i32, d: usize) -> i32 {
    let q = Q as i64;
    ((((mod_q(value) as i64) << d) + q / 2) / q & ((1i64 << d) - 1)) as i32
}

fn decompress(value: i32, d: usize) -> i32 {
    ((value as i64 * Q as i64 + (1i64 << (d - 1))) >> d) as i32
}

fn poly_compress(poly: &[i32; N], d: usize, output: &mut [u8]) {
    let mut compressed = [0; N];
    for i in 0..N {
        compressed[i] = compress(poly[i], d);
    }
    byte_encode(&compressed, d, output);
}

fn poly_decompress(input: &[u8], d: usize) -> [i32; N] {
    let mut poly = byte_decode(input, d);
    for coefficient in &mut poly {
        *coefficient = decompress(*coefficient, d);
    }
    poly
}

fn msg_to_poly(msg: &[u8; 32]) -> [i32; N] {
    let decoded = byte_decode(msg, 1);
    let mut poly = [0; N];
    for i in 0..N {
        poly[i] = decompress(decoded[i], 1);
    }
    poly
}

fn poly_to_msg(poly: &[i32; N]) -> [u8; 32] {
    let mut msg = [0; 32];
    poly_compress(poly, 1, &mut msg);
    msg
}

fn matrix_vector_product(
    matrix: &[[i32; N]; K * K],
    vector: &[[i32; N]; K],
    transpose: bool,
) -> [[i32; N]; K] {
    let mut result = [[0; N]; K];
    for row in 0..K {
        for column in 0..K {
            let index = if transpose {
                column * K + row
            } else {
                row * K + column
            };
            let product = multiply_ntts(&matrix[index], &vector[column]);
            result[row] = poly_add(&result[row], &product);
        }
    }
    result
}

fn cpapke_keygen(d: &[u8; 32]) -> ([u8; PUBLIC_KEY_BYTES], [u8; PKE_SECRET_KEY_BYTES]) {
    let mut g_input = [0; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = K as u8;
    let expanded = sha3_512(&g_input);
    let mut rho = [0; 32];
    let mut sigma = [0; 32];
    rho.copy_from_slice(&expanded[..32]);
    sigma.copy_from_slice(&expanded[32..]);

    let matrix = generate_a_hat(&rho);
    let mut s = [[0; N]; K];
    let mut e = [[0; N]; K];
    for i in 0..K {
        s[i] = sampled_noise(&sigma, i as u8, ETA1);
        e[i] = sampled_noise(&sigma, (K + i) as u8, ETA1);
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }

    let mut t = matrix_vector_product(&matrix, &s, false);
    let mut ek = [0; PUBLIC_KEY_BYTES];
    let mut dk = [0; PKE_SECRET_KEY_BYTES];
    for i in 0..K {
        t[i] = poly_add(&t[i], &e[i]);
        ek[i * POLYBYTES..(i + 1) * POLYBYTES]
            .copy_from_slice(&poly_tobytes(&t[i]));
        dk[i * POLYBYTES..(i + 1) * POLYBYTES]
            .copy_from_slice(&poly_tobytes(&s[i]));
    }
    ek[K * POLYBYTES..].copy_from_slice(&rho);
    (ek, dk)
}

fn cpapke_enc(
    ek: &[u8; PUBLIC_KEY_BYTES],
    msg: &[u8; 32],
    randomness: &[u8; 32],
) -> [u8; CIPHERTEXT_BYTES] {
    let mut t = [[0; N]; K];
    for i in 0..K {
        t[i] = poly_frombytes(&ek[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
    let mut rho = [0; 32];
    rho.copy_from_slice(&ek[K * POLYBYTES..]);
    let matrix = generate_a_hat(&rho);

    let mut y = [[0; N]; K];
    let mut e1 = [[0; N]; K];
    for i in 0..K {
        y[i] = sampled_noise(randomness, i as u8, ETA1);
        e1[i] = sampled_noise(randomness, (K + i) as u8, ETA2);
        ntt(&mut y[i]);
    }
    let e2 = sampled_noise(randomness, (2 * K) as u8, ETA2);

    let mut u = matrix_vector_product(&matrix, &y, true);
    let mut v = [0; N];
    for i in 0..K {
        u[i] = inv_ntt_result(&u[i]);
        u[i] = poly_add(&u[i], &e1[i]);
        let product = multiply_ntts(&t[i], &y[i]);
        v = poly_add(&v, &product);
    }
    let mut v = inv_ntt_result(&v);
    v = poly_add(&v, &e2);
    v = poly_add(&v, &msg_to_poly(msg));

    let mut ciphertext = [0; CIPHERTEXT_BYTES];
    for (i, poly) in u.iter().enumerate() {
        poly_compress(poly, DU, &mut ciphertext[i * 32 * DU..(i + 1) * 32 * DU]);
    }
    poly_compress(&v, DV, &mut ciphertext[K * 32 * DU..]);
    ciphertext
}

fn inv_ntt_result(poly: &[i32; N]) -> [i32; N] {
    let mut result = *poly;
    inv_ntt(&mut result);
    result
}

fn cpapke_dec(dk: &[u8], ciphertext: &[u8; CIPHERTEXT_BYTES]) -> [u8; 32] {
    let mut s = [[0; N]; K];
    for i in 0..K {
        s[i] = poly_frombytes(&dk[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
    let mut product_sum = [0; N];
    for i in 0..K {
        let mut u = poly_decompress(&ciphertext[i * 32 * DU..(i + 1) * 32 * DU], DU);
        ntt(&mut u);
        let product = multiply_ntts(&s[i], &u);
        product_sum = poly_add(&product_sum, &product);
    }
    let v = poly_decompress(&ciphertext[K * 32 * DU..], DV);
    let recovered = poly_sub(&v, &inv_ntt_result(&product_sum));
    poly_to_msg(&recovered)
}

fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
    let (ek, pke_dk) = cpapke_keygen(d);
    let mut dk = [0; SECRET_KEY_BYTES];
    dk[..PKE_SECRET_KEY_BYTES].copy_from_slice(&pke_dk);
    dk[PKE_SECRET_KEY_BYTES..PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES].copy_from_slice(&ek);
    let hash = sha3_256(&ek);
    let hash_offset = PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES;
    dk[hash_offset..hash_offset + 32].copy_from_slice(&hash);
    dk[hash_offset + 32..].copy_from_slice(z);
    (dk, ek)
}

fn encaps_internal(
    ek: &[u8; PUBLIC_KEY_BYTES],
    msg: &[u8; 32],
) -> ([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]) {
    let mut g_input = [0; 64];
    g_input[..32].copy_from_slice(msg);
    g_input[32..].copy_from_slice(&sha3_256(ek));
    let expanded = sha3_512(&g_input);
    let mut shared = [0; 32];
    let mut randomness = [0; 32];
    shared.copy_from_slice(&expanded[..32]);
    randomness.copy_from_slice(&expanded[32..]);
    (cpapke_enc(ek, msg, &randomness), shared)
}

fn decaps_internal(
    dk: &[u8; SECRET_KEY_BYTES],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
) -> [u8; SHARED_SECRET_BYTES] {
    let mut ek = [0; PUBLIC_KEY_BYTES];
    ek.copy_from_slice(&dk[PKE_SECRET_KEY_BYTES..PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES]);
    let hash_offset = PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES;
    let msg = cpapke_dec(&dk[..PKE_SECRET_KEY_BYTES], ciphertext);
    let mut g_input = [0; 64];
    g_input[..32].copy_from_slice(&msg);
    g_input[32..].copy_from_slice(&dk[hash_offset..hash_offset + 32]);
    let expanded = sha3_512(&g_input);
    let mut randomness = [0; 32];
    randomness.copy_from_slice(&expanded[32..]);
    let candidate = cpapke_enc(&ek, &msg, &randomness);

    let mut fallback_input = [0; 32 + CIPHERTEXT_BYTES];
    fallback_input[..32].copy_from_slice(&dk[hash_offset + 32..]);
    fallback_input[32..].copy_from_slice(ciphertext);
    let fallback = shake256_output(&fallback_input);
    let equal = crate::util::ct_eq(ciphertext, &candidate);
    let mut output = [0; 32];
    crate::util::ct_select(!equal as u8, &fallback, &expanded[..32], &mut output);
    output
}

fn shake256_output(input: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    shake256(input, &mut output);
    output
}

pub fn valid_encapsulation_key(ek: &[u8; PUBLIC_KEY_BYTES]) -> bool {
    let mut encoded = [0; K * POLYBYTES];
    for i in 0..K {
        let decoded = poly_frombytes(&ek[i * POLYBYTES..(i + 1) * POLYBYTES]);
        encoded[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&poly_tobytes(&decoded));
    }
    crate::util::ct_eq(&encoded, &ek[..K * POLYBYTES])
}

pub fn valid_decapsulation_key(dk: &[u8; SECRET_KEY_BYTES]) -> bool {
    let hash_offset = PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES;
    crate::util::ct_eq(
        &sha3_256(&dk[PKE_SECRET_KEY_BYTES..hash_offset]),
        &dk[hash_offset..hash_offset + 32],
    )
}

/// Generate a fresh ML-KEM-1024 key pair. The returned tuple is `(dk, ek)`.
pub fn keygen() -> Result<([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]), Error> {
    let mut d = [0; 32];
    let mut z = [0; 32];
    fill_random(&mut d)?;
    fill_random(&mut z)?;
    Ok(keygen_internal(&d, &z))
}

pub fn encaps(
    ek: &[u8; PUBLIC_KEY_BYTES],
) -> Result<([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]), Error> {
    if !valid_encapsulation_key(ek) {
        return Err(Error::InvalidEncapsulationKey);
    }
    let mut msg = [0; 32];
    fill_random(&mut msg)?;
    Ok(encaps_internal(ek, &msg))
}

pub fn decaps(
    dk: &[u8; SECRET_KEY_BYTES],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
) -> Result<[u8; SHARED_SECRET_BYTES], Error> {
    if !valid_decapsulation_key(dk) {
        return Err(Error::InvalidDecapsulationKey);
    }
    Ok(decaps_internal(dk, ciphertext))
}

#[cfg(any(test, feature = "test-vectors"))]
pub fn keygen_deterministic(
    d: &[u8; 32],
    z: &[u8; 32],
) -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
    keygen_internal(d, z)
}

#[cfg(any(test, feature = "test-vectors"))]
pub fn encaps_deterministic(
    ek: &[u8; PUBLIC_KEY_BYTES],
    msg: &[u8; 32],
) -> ([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]) {
    encaps_internal(ek, msg)
}

#[cfg(any(test, feature = "test-vectors"))]
pub fn decaps_deterministic(
    dk: &[u8; SECRET_KEY_BYTES],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
) -> [u8; SHARED_SECRET_BYTES] {
    decaps_internal(dk, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_multiplication_matches_naive_negacyclic_product() {
        let mut a = [0; N];
        let mut b = [0; N];
        for i in 0..N {
            a[i] = ((i * 7 + 5) % Q as usize) as i32;
            b[i] = ((i * 13 + 3) % Q as usize) as i32;
        }
        let mut a_hat = a;
        let mut b_hat = b;
        ntt(&mut a_hat);
        ntt(&mut b_hat);
        let actual = inv_ntt_result(&multiply_ntts(&a_hat, &b_hat));
        for i in 0..N {
            let mut expected = 0;
            for j in 0..N {
                let (index, sign) = if i >= j {
                    (i - j, 1)
                } else {
                    (N + i - j, -1)
                };
                expected = add_q(expected, sign * mul_q(a[j], b[index]));
            }
            assert_eq!(actual[i], expected, "coefficient {i}");
        }
    }

    #[test]
    fn compression_is_little_endian_and_bounded() {
        for d in [1, 4, 5, 10, 11] {
            for value in [0, 1, Q / 4, Q / 2, 3 * Q / 4, Q - 1, -1, -(Q / 2)] {
                let compressed = compress(value, d);
                assert!((0..1 << d).contains(&compressed));
                let decompressed = decompress(compressed, d);
                let difference = sub_q(value, decompressed);
                let centered = if difference > Q / 2 {
                    difference - Q
                } else {
                    difference
                };
                assert!(centered.abs() <= Q / (1 << (d + 1)) + 1);
            }
        }
    }

    #[test]
    fn msg_encoding_roundtrip() {
        let msg = [0xa5; 32];
        assert_eq!(poly_to_msg(&msg_to_poly(&msg)), msg);
    }
}
