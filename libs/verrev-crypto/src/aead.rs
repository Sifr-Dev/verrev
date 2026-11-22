// ——— ChaCha20 ———

const CHACHA_CONST: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn chacha20_double_round(s: &mut [u32; 16]) {
    quarter_round(s, 0, 4, 8, 12);
    quarter_round(s, 1, 5, 9, 13);
    quarter_round(s, 2, 6, 10, 14);
    quarter_round(s, 3, 7, 11, 15);
    quarter_round(s, 0, 5, 10, 15);
    quarter_round(s, 1, 6, 11, 12);
    quarter_round(s, 2, 7, 8, 13);
    quarter_round(s, 3, 4, 9, 14);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let k = [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
    ];
    let n0 = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    let n1 = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    let n2 = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let mut s = [
        CHACHA_CONST[0], CHACHA_CONST[1], CHACHA_CONST[2], CHACHA_CONST[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        counter, n0, n1, n2,
    ];
    let initial = s;

    for _ in 0..10 {
        chacha20_double_round(&mut s);
    }

    for i in 0..16 {
        s[i] = s[i].wrapping_add(initial[i]);
    }

    let mut out = [0u8; 64];
    for (i, w) in s.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let k = [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
    ];
    let n = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        u32::from_le_bytes([nonce[12], nonce[13], nonce[14], nonce[15]]),
    ];

    let mut s = [
        CHACHA_CONST[0], CHACHA_CONST[1], CHACHA_CONST[2], CHACHA_CONST[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        n[0], n[1], n[2], n[3],
    ];

    for _ in 0..10 {
        chacha20_double_round(&mut s);
    }

    let mut out = [0u8; 32];
    let top = [s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15]];
    for (i, w) in top.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn xor_keystream(key: &[u8; 32], counter_start: u32, nonce: &[u8; 12], input: &[u8], output: &mut [u8]) {
    let len = input.len().min(output.len());
    let mut counter = counter_start;
    let mut pos = 0usize;
    while pos < len {
        let block = chacha20_block(key, counter, nonce);
        let chunk = (len - pos).min(64);
        for i in 0..chunk {
            output[pos + i] = input[pos + i] ^ block[i];
        }
        counter = counter.wrapping_add(1);
        pos += 64;
    }
}

// ——— Poly1305 (5-limb 26-bit arithmetic, incremental) ———

struct Poly1305Ctx {
    r: [u64; 5],
    h: [u64; 5],
    buf: [u8; 16],
    buf_len: usize,
    key: [u8; 32],
}

impl Poly1305Ctx {
    fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u64; 5];
        r[0] = (u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x03FFFFFF) as u64;
        r[1] = ((u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2) & 0x03FFFF03) as u64;
        let mut clamped = [0u8; 16];
        clamped.copy_from_slice(&key[..16]);
        clamped[3] &= 15;
        clamped[7] &= 15;
        clamped[11] &= 15;
        clamped[15] &= 15;
        clamped[4] &= 252;
        clamped[8] &= 252;
        clamped[12] &= 252;
        let clamped = u128::from_le_bytes(clamped);
        r[0] = clamped as u64 & 0x03FFFFFF;
        r[1] = (clamped >> 26) as u64 & 0x03FFFFFF;
        r[2] = (clamped >> 52) as u64 & 0x03FFFFFF;
        r[3] = (clamped >> 78) as u64 & 0x03FFFFFF;
        r[4] = (clamped >> 104) as u64;
        Poly1305Ctx { r, h: [0u64; 5], buf: [0u8; 16], buf_len: 0, key: *key }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buf_len > 0 {
            let space = 16 - self.buf_len;
            let take = if space < data.len() { space } else { data.len() };
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 16 {
                self.accumulate(16);
                self.buf_len = 0;
            }
        }
        while offset + 16 <= data.len() {
            self.buf.copy_from_slice(&data[offset..offset + 16]);
            self.accumulate(16);
            offset += 16;
        }
        if offset < data.len() {
            let rem = data.len() - offset;
            self.buf[..rem].copy_from_slice(&data[offset..]);
            self.buf_len = rem;
        }
    }

    fn accumulate(&mut self, n: usize) {
        let b = u128::from_le_bytes(self.buf);
        self.h[0] += b as u64 & 0x03FFFFFF;
        self.h[1] += (b >> 26) as u64 & 0x03FFFFFF;
        self.h[2] += (b >> 52) as u64 & 0x03FFFFFF;
        self.h[3] += (b >> 78) as u64 & 0x03FFFFFF;
        self.h[4] += (b >> 104) as u64;
        if n == 16 {
            self.h[4] += 1u64 << 24;
        } else {
            let pad = 1u128 << (8 * n);
            self.h[0] += pad as u64 & 0x03FFFFFF;
            self.h[1] += (pad >> 26) as u64 & 0x03FFFFFF;
            self.h[2] += (pad >> 52) as u64 & 0x03FFFFFF;
            self.h[3] += (pad >> 78) as u64 & 0x03FFFFFF;
            self.h[4] += (pad >> 104) as u64;
        }
        self.propagate();
        self.mul_by_r();
    }

    fn propagate(&mut self) {
        let c0 = self.h[0] >> 26; self.h[0] &= 0x03FFFFFF; self.h[1] += c0;
        let c1 = self.h[1] >> 26; self.h[1] &= 0x03FFFFFF; self.h[2] += c1;
        let c2 = self.h[2] >> 26; self.h[2] &= 0x03FFFFFF; self.h[3] += c2;
        let c3 = self.h[3] >> 26; self.h[3] &= 0x03FFFFFF; self.h[4] += c3;
        let c4 = self.h[4] >> 26; self.h[4] &= 0x03FFFFFF;
        self.h[0] = self.h[0].wrapping_add(c4 * 5);
        let c0 = self.h[0] >> 26; self.h[0] &= 0x03FFFFFF; self.h[1] += c0;
        let c1 = self.h[1] >> 26; self.h[1] &= 0x03FFFFFF; self.h[2] += c1;
        let c2 = self.h[2] >> 26; self.h[2] &= 0x03FFFFFF; self.h[3] += c2;
        let c3 = self.h[3] >> 26; self.h[3] &= 0x03FFFFFF; self.h[4] += c3;
        let c4 = self.h[4] >> 26; self.h[4] &= 0x03FFFFFF;
        self.h[0] = self.h[0].wrapping_add(c4 * 5);
    }

    fn mul_by_r(&mut self) {
        let (h0, h1, h2, h3, h4) = (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);
        let (r0, r1, r2, r3, r4) = (self.r[0], self.r[1], self.r[2], self.r[3], self.r[4]);

        let d0 = h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1;
        let d1 = h0*r1 + h1*r0 + h2*5*r4 + h3*5*r3 + h4*5*r2;
        let d2 = h0*r2 + h1*r1 + h2*r0 + h3*5*r4 + h4*5*r3;
        let d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*5*r4;
        let d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

        self.h[0] = d0 & 0x03FFFFFF; let mut c = d0 >> 26;
        self.h[1] = (d1 + c) & 0x03FFFFFF; c = (d1 + c) >> 26;
        self.h[2] = (d2 + c) & 0x03FFFFFF; c = (d2 + c) >> 26;
        self.h[3] = (d3 + c) & 0x03FFFFFF; c = (d3 + c) >> 26;
        self.h[4] = (d4 + c) & 0x03FFFFFF; c = (d4 + c) >> 26;
        self.h[0] = self.h[0].wrapping_add(c * 5);
        let c0 = self.h[0] >> 26; self.h[0] &= 0x03FFFFFF; self.h[1] = self.h[1].wrapping_add(c0);
        let c1 = self.h[1] >> 26; self.h[1] &= 0x03FFFFFF; self.h[2] = self.h[2].wrapping_add(c1);
        let c2 = self.h[2] >> 26; self.h[2] &= 0x03FFFFFF; self.h[3] = self.h[3].wrapping_add(c2);
        let c3 = self.h[3] >> 26; self.h[3] &= 0x03FFFFFF; self.h[4] = self.h[4].wrapping_add(c3);
        let c4 = self.h[4] >> 26; self.h[4] &= 0x03FFFFFF;
        self.h[0] = self.h[0].wrapping_add(c4 * 5);
    }

    #[cfg(test)]
    fn tap_update(mut self, data: &[u8]) -> [u8; 16] {
        self.update(data);
        self.finalize()
    }

    fn finalize(mut self) -> [u8; 16] {
        self.pad();
        self.propagate();

        // Select the canonical representative modulo 2^130 - 5 before
        // serializing the low 128 bits.
        let mut g = [0u64; 5];
        g[0] = self.h[0] + 5;
        let mut carry = g[0] >> 26;
        g[0] &= 0x03FFFFFF;
        for i in 1..5 {
            g[i] = self.h[i] + carry;
            carry = g[i] >> 26;
            g[i] &= 0x03FFFFFF;
        }
        g[4] = g[4].wrapping_sub(1 << 26);
        let use_g = (g[4] >> 63).wrapping_sub(1);
        for i in 0..5 {
            self.h[i] = (self.h[i] & !use_g) | (g[i] & use_g);
        }

        let s = u128::from_le_bytes([
            self.key[16], self.key[17], self.key[18], self.key[19],
            self.key[20], self.key[21], self.key[22], self.key[23],
            self.key[24], self.key[25], self.key[26], self.key[27],
            self.key[28], self.key[29], self.key[30], self.key[31],
        ]);
        let acc = (self.h[0] as u128) | ((self.h[1] as u128) << 26) | ((self.h[2] as u128) << 52)
            | ((self.h[3] as u128) << 78) | ((self.h[4] as u128) << 104);
        acc.wrapping_add(s).to_le_bytes()
    }

    fn pad(&mut self) {
        if self.buf_len > 0 {
            let n = self.buf_len;
            self.buf[n..].fill(0);
            self.accumulate(n);
            self.buf_len = 0;
        }
    }
}

// ——— XChaCha20Poly1305 AEAD ———

pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl XChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        XChaCha20Poly1305 { key: *key }
    }

    pub fn encrypt(&self, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> [u8; 16] {
        let mut nonce16 = [0u8; 16];
        nonce16.copy_from_slice(&nonce[..16]);
        let subkey = hchacha20(&self.key, &nonce16);
        let mut poly_nonce = [0u8; 12];
        poly_nonce[4..12].copy_from_slice(&nonce[16..24]);

        let block0 = chacha20_block(&subkey, 0, &poly_nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block0[..32]);

        xor_keystream(&subkey, 1, &poly_nonce, plaintext, ciphertext);

        let aad_pad = (16 - aad.len() % 16) % 16;
        let ct_pad = (16 - plaintext.len() % 16) % 16;
        let mut ctx = Poly1305Ctx::new(&poly_key);
        ctx.update(aad);
        ctx.update(&[0u8; 16][..aad_pad]);
        ctx.update(&ciphertext[..plaintext.len()]);
        ctx.update(&[0u8; 16][..ct_pad]);
        ctx.update(&(aad.len() as u64).to_le_bytes());
        ctx.update(&(plaintext.len() as u64).to_le_bytes());
        ctx.finalize()
    }

    pub fn decrypt(&self, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16], plaintext: &mut [u8]) -> bool {
        let mut nonce16 = [0u8; 16];
        nonce16.copy_from_slice(&nonce[..16]);
        let subkey = hchacha20(&self.key, &nonce16);
        let mut poly_nonce = [0u8; 12];
        poly_nonce[4..12].copy_from_slice(&nonce[16..24]);

        let block0 = chacha20_block(&subkey, 0, &poly_nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block0[..32]);

        let aad_pad = (16 - aad.len() % 16) % 16;
        let ct_pad = (16 - ciphertext.len() % 16) % 16;
        let mut ctx = Poly1305Ctx::new(&poly_key);
        ctx.update(aad);
        ctx.update(&[0u8; 16][..aad_pad]);
        ctx.update(ciphertext);
        ctx.update(&[0u8; 16][..ct_pad]);
        ctx.update(&(aad.len() as u64).to_le_bytes());
        ctx.update(&(ciphertext.len() as u64).to_le_bytes());
        let computed = ctx.finalize();

        if !crate::util::ct_eq(tag, &computed) {
            return false;
        }

        xor_keystream(&subkey, 1, &poly_nonce, ciphertext, plaintext);
        true
    }
}

// ——— AES-256 ———



const fn gf256_mul_const(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut x = a;
    let mut y = b;
    let mut i = 0;
    while i < 8 {
        if y & 1 != 0 { p ^= x; }
        y >>= 1;
        if x & 0x80 != 0 { x = (x << 1) ^ 0x1B; }
        else { x <<= 1; }
        i += 1;
    }
    p
}

const fn gf256_inv_const(a: u8) -> u8 {
    if a == 0 { return 0; }
    let mut r = a;
    let mut i = 0;
    while i < 6 {
        r = gf256_mul_const(r, r);
        r = gf256_mul_const(r, a);
        i += 1;
    }
    r = gf256_mul_const(r, r);
    r
}

const AES_SBOX: [u8; 256] = {
    let mut sbox = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let inv = gf256_inv_const(i as u8);
        let x = inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4);
        sbox[i] = x ^ 0x63;
        i += 1;
    }
    sbox
};

fn gf256_mul(a: u8, b: u8) -> u8 {
    gf256_mul_const(a, b)
}

fn aes256_key_expansion(key: &[u8; 32]) -> [u8; 240] {
    let mut rcon = [0u8; 14];
    rcon[0] = 0x01;
    let mut i = 1;
    while i < 14 {
        rcon[i] = gf256_mul(rcon[i - 1], 0x02);
        i += 1;
    }

    let mut w = [0u32; 60];
    let mut i = 0;
    while i < 8 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        i += 1;
    }
    let mut i = 8;
    while i < 60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = t.rotate_left(8);
            let b0 = AES_SBOX[(t >> 24) as usize] as u32;
            let b1 = AES_SBOX[(t >> 16 & 0xFF) as usize] as u32;
            let b2 = AES_SBOX[(t >> 8 & 0xFF) as usize] as u32;
            let b3 = AES_SBOX[(t & 0xFF) as usize] as u32;
            t = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
            t ^= (rcon[i / 8 - 1] as u32) << 24;
        } else if i % 8 == 4 {
            let b0 = AES_SBOX[(t >> 24) as usize] as u32;
            let b1 = AES_SBOX[(t >> 16 & 0xFF) as usize] as u32;
            let b2 = AES_SBOX[(t >> 8 & 0xFF) as usize] as u32;
            let b3 = AES_SBOX[(t & 0xFF) as usize] as u32;
            t = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        }
        w[i] = w[i - 8] ^ t;
        i += 1;
    }

    let mut rk = [0u8; 240];
    let mut i = 0;
    while i < 60 {
        rk[4 * i..4 * i + 4].copy_from_slice(&w[i].to_be_bytes());
        i += 1;
    }
    rk
}

fn aes256_encrypt_block(block: &[u8; 16], rk: &[u8; 240]) -> [u8; 16] {
    let mut state = *block;

    for i in 0..16 { state[i] ^= rk[i]; }

    let mut round = 1;
    while round <= 13 {
        let mut i = 0;
        while i < 16 {
            state[i] = AES_SBOX[state[i] as usize];
            i += 1;
        }

        let t = state;
        state = [t[0], t[5], t[10], t[15], t[4], t[9], t[14], t[3], t[8], t[13], t[2], t[7], t[12], t[1], t[6], t[11]];

        let mut c = 0;
        while c < 4 {
            let i = 4 * c;
            let (a0, a1, a2, a3) = (state[i], state[i+1], state[i+2], state[i+3]);
            state[i]   = gf256_mul(2, a0) ^ gf256_mul(3, a1) ^ a2 ^ a3;
            state[i+1] = a0 ^ gf256_mul(2, a1) ^ gf256_mul(3, a2) ^ a3;
            state[i+2] = a0 ^ a1 ^ gf256_mul(2, a2) ^ gf256_mul(3, a3);
            state[i+3] = gf256_mul(3, a0) ^ a1 ^ a2 ^ gf256_mul(2, a3);
            c += 1;
        }

        let mut i = 0;
        while i < 16 {
            state[i] ^= rk[round * 16 + i];
            i += 1;
        }
        round += 1;
    }

    let mut i = 0;
    while i < 16 {
        state[i] = AES_SBOX[state[i] as usize];
        i += 1;
    }
    let t = state;
    state = [t[0], t[5], t[10], t[15], t[4], t[9], t[14], t[3], t[8], t[13], t[2], t[7], t[12], t[1], t[6], t[11]];
    let mut i = 0;
    while i < 16 {
        state[i] ^= rk[14 * 16 + i];
        i += 1;
    }

    state
}

// ——— GHASH (with 4-bit window multiplication) ———

const GHASH_R: u128 = 0xE1000000000000000000000000000000;

// table[i] = i * H in GF(2^128), using the SP 800-38D bit ordering: the
// multiplicand's bits are consumed most-significant first and the running
// value is reduced by shifting right into R = 0xE1 << 120.
// gfmul128_4bit consumes one nibble at a time and applies exactly four of
// those shifts between table lookups, so the table must cover four steps.
fn ghash_precompute(h: u128) -> [u128; 16] {
    let mut table = [0u128; 16];
    let mut i = 0usize;
    while i < 16 {
        let val = i as u128;
        let mut z = 0u128;
        let mut v = h;
        let mut j = 0;
        while j < 4 {
            if (val >> (3 - j)) & 1 != 0 { z ^= v; }
            if v & 1 != 0 { v = (v >> 1) ^ GHASH_R; }
            else { v >>= 1; }
            j += 1;
        }
        table[i] = z;
        i += 1;
    }
    table
}

fn gfmul128_4bit(x: u128, table: &[u128; 16]) -> u128 {
    // Horner form of Z = sum_n alpha^(4n) * table[nibble_n], where nibble 0 is
    // the MOST significant nibble of x and alpha is the SP 800-38D shift.
    // Evaluation therefore starts at the LEAST significant nibble and works
    // upwards: each step applies four reductions to the accumulated value and
    // then xors in the next table entry. Consuming nibbles most-significant
    // first instead computes a different product, which is invisible to
    // encrypt/decrypt round-trip tests and only shows up against known answers.
    let mut z = 0u128;
    let mut i = 0;
    while i < 128 {
        let nibble = ((x >> i) & 0xF) as usize;
        let mut j = 0;
        while j < 4 {
            let lsb = z & 1;
            z >>= 1;
            if lsb != 0 { z ^= GHASH_R; }
            j += 1;
        }
        z ^= table[nibble];
        i += 4;
    }
    z
}

struct GhashCtx {
    table: [u128; 16],
    y: u128,
    buf: [u8; 16],
    buf_len: usize,
}

impl GhashCtx {
    fn new(h: u128) -> Self {
        GhashCtx {
            table: ghash_precompute(h),
            y: 0,
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 16 {
                self.accumulate();
                self.buf_len = 0;
            }
        }
        while offset + 16 <= data.len() {
            self.buf.copy_from_slice(&data[offset..offset + 16]);
            self.accumulate();
            offset += 16;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    fn accumulate(&mut self) {
        self.y = gfmul128_4bit(self.y ^ u128::from_be_bytes(self.buf), &self.table);
    }

    fn finalize(mut self) -> u128 {
        if self.buf_len > 0 {
            self.buf[self.buf_len..].fill(0);
            self.accumulate();
        }
        self.y
    }
}

// ——— Aes256Gcm ———

pub struct Aes256Gcm {
    key: [u8; 32],
}

impl Aes256Gcm {
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256Gcm { key: *key }
    }

    fn encrypt_ctr(&self, counter_block: &[u8; 16], plaintext: &[u8], ciphertext: &mut [u8]) {
        let rk = aes256_key_expansion(&self.key);
        let mut ctr = *counter_block;
        for byte in ctr.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        let mut pos = 0usize;
        while pos < plaintext.len() {
            let ks = aes256_encrypt_block(&ctr, &rk);
            let chunk = (plaintext.len() - pos).min(16);
            for i in 0..chunk { ciphertext[pos + i] = plaintext[pos + i] ^ ks[i]; }
            for i in (0..16).rev() {
                ctr[i] = ctr[i].wrapping_add(1);
                if ctr[i] != 0 { break; }
            }
            pos += 16;
        }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> [u8; 16] {
        let rk = aes256_key_expansion(&self.key);

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let h = u128::from_be_bytes(aes256_encrypt_block(&[0u8; 16], &rk));
        self.encrypt_ctr(&j0, plaintext, ciphertext);

        let aad_pad = (16 - aad.len() % 16) % 16;
        let ct_pad = (16 - plaintext.len() % 16) % 16;
        let mut ctx = GhashCtx::new(h);
        ctx.update(aad);
        ctx.update(&[0u8; 16][..aad_pad]);
        ctx.update(&ciphertext[..plaintext.len()]);
        ctx.update(&[0u8; 16][..ct_pad]);
        // SP 800-38D step 6: the final GHASH block is [len(A)]64 || [len(C)]64
        // with both lengths encoded in BITS, not bytes. Using byte lengths
        // leaves the empty-message known answer correct and corrupts every
        // other tag, which is precisely the blind spot of round-trip tests.
        ctx.update(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
        ctx.update(&(plaintext.len() as u64).wrapping_mul(8).to_be_bytes());
        let s = ctx.finalize();

        let e = u128::from_be_bytes(aes256_encrypt_block(&j0, &rk));
        (s ^ e).to_be_bytes()
    }

    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16], plaintext: &mut [u8]) -> bool {
        let rk = aes256_key_expansion(&self.key);

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let h = u128::from_be_bytes(aes256_encrypt_block(&[0u8; 16], &rk));

        let aad_pad = (16 - aad.len() % 16) % 16;
        let ct_pad = (16 - ciphertext.len() % 16) % 16;
        let mut ctx = GhashCtx::new(h);
        ctx.update(aad);
        ctx.update(&[0u8; 16][..aad_pad]);
        ctx.update(ciphertext);
        ctx.update(&[0u8; 16][..ct_pad]);
        ctx.update(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
        ctx.update(&(ciphertext.len() as u64).wrapping_mul(8).to_be_bytes());
        let s = ctx.finalize();

        let e = u128::from_be_bytes(aes256_encrypt_block(&j0, &rk));
        let computed = (s ^ e).to_be_bytes();

        if !crate::util::ct_eq(tag, &computed) {
            return false;
        }

        self.encrypt_ctr(&j0, ciphertext, plaintext);
        true
    }
}

#[cfg(test)]
mod tests {
    // Straight-from-the-spec GF(2^128) reference: SP 800-38D Algorithm 1.
    // Used as a differential oracle for the table-driven fast path.
    fn gfmul_reference(x: u128, y: u128) -> u128 {
        let mut z = 0u128;
        let mut v = x;
        for i in 0..128 {
            if (y >> (127 - i)) & 1 != 0 {
                z ^= v;
            }
            v = if v & 1 != 0 { (v >> 1) ^ GHASH_R } else { v >> 1 };
        }
        z
    }

    #[test]
    fn gfmul_fast_path_matches_spec_reference() {
        let mut seed = 0x243f6a8885a308d313198a2e03707344u128;
        for _ in 0..4096 {
            seed = seed.wrapping_mul(6364136223846793005u128).wrapping_add(1442695040888963407u128);
            let x = seed ^ (seed >> 37);
            seed = seed.wrapping_mul(6364136223846793005u128).wrapping_add(1442695040888963407u128);
            let y = seed ^ (seed >> 61);
            let table = ghash_precompute(x);
            assert_eq!(gfmul128_4bit(y, &table), gfmul_reference(x, y), "x={x:032x} y={y:032x}");
        }
        // Degenerate operands catch reduction and endianness errors that a
        // purely random sweep can statistically miss.
        for &x in &[0u128, 1, u128::MAX, 1 << 127] {
            for &y in &[0u128, 1, u128::MAX, 1 << 127] {
                assert_eq!(gfmul128_4bit(y, &ghash_precompute(x)), gfmul_reference(x, y));
            }
        }
    }
    use super::*;

    #[test]
    fn test_chacha20_block_known() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let block = chacha20_block(&key, 0, &nonce);
        let expected: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
            0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
            0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
            0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(block, expected, "ChaCha20 block KAT mismatch");
    }

    #[test]
    fn test_aes256_encrypt_known() {
        let key = [0u8; 32];
        let pt = [0u8; 16];
        let rk = aes256_key_expansion(&key);
        let ct = aes256_encrypt_block(&pt, &rk);
        let expected: [u8; 16] = [
            0xDC, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0x89,
            0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20, 0x87,
        ];
        assert_eq!(ct, expected, "AES-256 KAT mismatch");
    }

    #[test]
    fn rfc8439_poly1305_known_answer() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let tag = Poly1305Ctx::new(&key)
            .tap_update(b"Cryptographic Forum Research Group");
        assert_eq!(
            tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
            ]
        );
    }

    #[test]
    fn ietf_xchacha20poly1305_a1_known_answer() {
        // draft-irtf-cfrg-xchacha-03, Appendix A.1 / A.3.1:
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = 0x80 + index as u8;
        }
        for (index, byte) in nonce.iter_mut().enumerate() {
            *byte = 0x40 + index as u8;
        }
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext = [
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
            0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
            0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
            0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
            0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
            0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
            0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
            0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
            0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
            0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
            0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
            0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
            0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e,
        ];
        let expected_tag = [
            0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
            0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
        ];
        let mut ciphertext = [0u8; 114];
        let mut decrypted = [0u8; 114];
        let aead = XChaCha20Poly1305::new(&key);

        let mut tag = aead.encrypt(&nonce, &aad, plaintext, &mut ciphertext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);
        assert!(aead.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted));
        assert_eq!(&decrypted, plaintext);

        tag[0] ^= 1;
        decrypted.fill(0);
        assert!(!aead.decrypt(&nonce, &aad, &ciphertext, &tag, &mut decrypted));
    }

    #[test]
    fn nist_gcm_aes256_empty_and_single_block_known_answers() {
        // NIST GCMVS gcmEncryptExtIV256.rsp cases 1 and 2; specification:
        // https://doi.org/10.6028/NIST.SP.800-38D
        let aead = Aes256Gcm::new(&[0u8; 32]);
        let nonce = [0u8; 12];
        let mut empty_ciphertext = [];
        let empty_tag = aead.encrypt(&nonce, &[], &[], &mut empty_ciphertext);
        assert_eq!(
            empty_tag,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
                0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
            ]
        );
        let mut empty_plaintext = [];
        assert!(aead.decrypt(&nonce, &[], &[], &empty_tag, &mut empty_plaintext));

        let plaintext = [0u8; 16];
        let mut ciphertext = [0u8; 16];
        let tag = aead.encrypt(&nonce, &[], &plaintext, &mut ciphertext);
        assert_eq!(
            ciphertext,
            [
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
            ]
        );
        assert_eq!(
            tag,
            [
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
            ]
        );
        let mut decrypted = [0u8; 16];
        assert!(aead.decrypt(&nonce, &[], &ciphertext, &tag, &mut decrypted));
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256gcm_matches_independent_openssl_vectors() {
        for (index, v) in crate::gcm_vectors::VECTORS.iter().enumerate() {
            let aead = Aes256Gcm::new(&v.key);
            let mut ciphertext = alloc::vec![0u8; v.plaintext.len()];
            let tag = aead.encrypt(&v.nonce, v.aad, v.plaintext, &mut ciphertext);
            assert_eq!(ciphertext.as_slice(), v.ciphertext, "ciphertext, vector {index}");
            assert_eq!(tag, v.tag, "tag, vector {index}");

            let mut plaintext = alloc::vec![0u8; v.plaintext.len()];
            assert!(aead.decrypt(&v.nonce, v.aad, &ciphertext, &tag, &mut plaintext),
                    "decrypt, vector {index}");
            assert_eq!(plaintext.as_slice(), v.plaintext, "plaintext, vector {index}");

            // Authentication must fail when the tag or the body is altered.
            let mut bad_tag = tag;
            bad_tag[index % 16] ^= 1;
            assert!(!aead.decrypt(&v.nonce, v.aad, &ciphertext, &bad_tag, &mut plaintext));
            if !ciphertext.is_empty() {
                let mut bad_ciphertext = ciphertext.clone();
                bad_ciphertext[0] ^= 1;
                assert!(!aead.decrypt(&v.nonce, v.aad, &bad_ciphertext, &tag, &mut plaintext));
            }
            if !v.aad.is_empty() {
                let mut bad_aad = v.aad.to_vec();
                bad_aad[0] ^= 1;
                assert!(!aead.decrypt(&v.nonce, &bad_aad, &ciphertext, &tag, &mut plaintext));
            }
        }
    }

    #[test]
    fn ghash_incremental_updates_equal_single_shot() {
        // AAD/ciphertext are fed through a buffering layer; split points must
        // not change the result, otherwise a partial final block is lost.
        // The byte stream is built exactly as Aes256Gcm::encrypt builds it,
        // including the zero padding and the bit-length trailer.
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let aad: alloc::vec::Vec<u8> = (0..37u8).collect();
        let plaintext: alloc::vec::Vec<u8> = (0..91u8).map(|b| b.wrapping_mul(3)).collect();
        let aead = Aes256Gcm::new(&key);
        let mut whole = alloc::vec![0u8; plaintext.len()];
        let expected = aead.encrypt(&nonce, &aad, &plaintext, &mut whole);

        let mut stream = aad.clone();
        stream.resize(48, 0);
        stream.extend_from_slice(&whole);
        stream.resize(48 + 96, 0);
        stream.extend_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        stream.extend_from_slice(&(plaintext.len() as u64 * 8).to_be_bytes());

        let rk = aes256_key_expansion(&key);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&nonce);
        j0[15] = 1;
        let h = u128::from_be_bytes(aes256_encrypt_block(&[0u8; 16], &rk));
        let e = u128::from_be_bytes(aes256_encrypt_block(&j0, &rk));
        for split in 0..=stream.len() {
            let mut ctx = GhashCtx::new(h);
            ctx.update(&stream[..split]);
            ctx.update(&stream[split..]);
            let s = ctx.finalize();
            assert_eq!((s ^ e).to_be_bytes(), expected, "split {split}");
        }
    }

    #[test]
    fn test_xchacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 24];
        let aad = b"test aad";
        let pt = b"Hello, Verrev! This is a test message for AEAD.";
        let mut ct = [0u8; 128];
        let aead = XChaCha20Poly1305::new(&key);
        let tag = aead.encrypt(&nonce, aad, pt, &mut ct[..pt.len()]);
        let mut dec = [0u8; 128];
        let ok = aead.decrypt(&nonce, aad, &ct[..pt.len()], &tag, &mut dec[..pt.len()]);
        assert!(ok);
        assert_eq!(&dec[..pt.len()], pt);
    }

    #[test]
    fn test_xchacha20poly1305_wrong_key() {
        let key = [0x42u8; 32];
        let wrong = [0xFFu8; 32];
        let nonce = [0x24u8; 24];
        let aad = b"test";
        let pt = b"Hello!";
        let mut ct = [0u8; 64];
        let tag = XChaCha20Poly1305::new(&key).encrypt(&nonce, aad, pt, &mut ct[..pt.len()]);
        let mut dec = [0u8; 64];
        let ok = XChaCha20Poly1305::new(&wrong).decrypt(&nonce, aad, &ct[..pt.len()], &tag, &mut dec[..pt.len()]);
        assert!(!ok);
    }

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"test aad";
        let pt = b"Hello, Verrev! AES-GCM test.";
        let mut ct = [0u8; 128];
        let aead = Aes256Gcm::new(&key);
        let tag = aead.encrypt(&nonce, aad, pt, &mut ct[..pt.len()]);
        let mut dec = [0u8; 128];
        let ok = aead.decrypt(&nonce, aad, &ct[..pt.len()], &tag, &mut dec[..pt.len()]);
        assert!(ok);
        assert_eq!(&dec[..pt.len()], pt);
    }

    #[test]
    fn test_aes256gcm_wrong_key() {
        let key = [0x42u8; 32];
        let wrong = [0xFFu8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"test";
        let pt = b"Hello!";
        let mut ct = [0u8; 64];
        let tag = Aes256Gcm::new(&key).encrypt(&nonce, aad, pt, &mut ct[..pt.len()]);
        let mut dec = [0u8; 64];
        let ok = Aes256Gcm::new(&wrong).decrypt(&nonce, aad, &ct[..pt.len()], &tag, &mut dec[..pt.len()]);
        assert!(!ok);
    }
}
