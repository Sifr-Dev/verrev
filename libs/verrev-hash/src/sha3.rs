fn rc(t: usize) -> u64 {
    if t.is_multiple_of(255) {
        return 1;
    }
    let mut r: u64 = 0x01;
    for _ in 0..(t % 255) {
        r <<= 1;
        if r & 0x100 != 0 {
            r ^= 0x171;
        }
        r &= 0xFF;
    }
    r & 1
}

fn rc_constants() -> [u64; 24] {
    let mut rcs = [0u64; 24];
    for (ir, round_constant) in rcs.iter_mut().enumerate() {
        let mut val = 0u64;
        for j in 0..7 {
            if rc(j + 7 * ir) != 0 {
                val ^= 1u64 << ((1u64 << j) - 1);
            }
        }
        *round_constant = val;
    }
    rcs
}

fn rho_constants() -> [[u32; 5]; 5] {
    let mut rho = [[0u32; 5]; 5];
    let mut x = 1usize;
    let mut y = 0usize;
    for t in 0..24 {
        rho[x][y] = (((t + 1) * (t + 2)) / 2) as u32 % 64;
        let nx = y;
        let ny = (2 * x + 3 * y) % 5;
        x = nx;
        y = ny;
    }
    rho
}

pub struct Keccak {
    state: [u64; 25],
    rate: usize,
    output_len: usize,
    offset: usize,
    squeezing: bool,
}

impl Keccak {
    pub fn new(capacity: usize, output_len: usize) -> Self {
        Keccak {
            state: [0u64; 25],
            rate: (1600 - capacity) / 8,
            output_len,
            offset: 0,
            squeezing: false,
        }
    }

    pub fn sha3_256() -> Self {
        Self::new(512, 32)
    }

    pub fn sha3_512() -> Self {
        Self::new(1024, 64)
    }

    pub fn shake128() -> Self {
        Self::new(256, 0)
    }

    pub fn shake256() -> Self {
        Self::new(512, 0)
    }

    fn keccak_f(&mut self) {
        let rc = rc_constants();
        let rho = rho_constants();
        for round_constant in rc {
            let mut c: [u64; 5] = [0; 5];
            for x in 0..5 {
                c[x] = self.state[x] ^ self.state[x + 5] ^ self.state[x + 10] ^ self.state[x + 15] ^ self.state[x + 20];
            }

            let mut d: [u64; 5] = [0; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }

            for x in 0..5 {
                for y in 0..5 {
                    self.state[x + 5 * y] ^= d[x];
                }
            }

            let mut b: [u64; 25] = [0; 25];
            for x in 0..5 {
                for y in 0..5 {
                    let r = rho[x][y];
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = self.state[x + 5 * y].rotate_left(r);
                }
            }
            self.state = b;

            for y in 0..5 {
                let mut e: [u64; 25] = self.state;
                for x in 0..5 {
                    e[x + 5 * y] = self.state[x + 5 * y]
                        ^ (!self.state[(x + 1) % 5 + 5 * y] & self.state[(x + 2) % 5 + 5 * y]);
                }
                self.state = e;
            }

            self.state[0] ^= round_constant;
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        if self.squeezing {
            return;
        }
        let mut pos = 0;
        while pos < data.len() {
            let chunk = core::cmp::min(self.rate - self.offset, data.len() - pos);
            for i in 0..chunk {
                let byte_idx = self.offset + i;
                let lane = byte_idx / 8;
                let byte_in_lane = byte_idx % 8;
                self.state[lane] ^= (data[pos + i] as u64) << (byte_in_lane * 8);
            }
            self.offset += chunk;
            pos += chunk;
            if self.offset == self.rate {
                self.keccak_f();
                self.offset = 0;
            }
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            if self.output_len > 0 {
                self.state[self.offset / 8] ^= 0x06u64 << ((self.offset % 8) * 8);
            } else {
                self.state[self.offset / 8] ^= 0x1fu64 << ((self.offset % 8) * 8);
            }
            self.state[(self.rate - 1) / 8] ^= 0x80u64 << (((self.rate - 1) % 8) * 8);
            self.keccak_f();
            self.squeezing = true;
            self.offset = 0;
        }

        let mut pos = 0;
        while pos < out.len() {
            let chunk = core::cmp::min(self.rate - self.offset, out.len() - pos);
            for i in 0..chunk {
                let byte_idx = self.offset + i;
                let lane = byte_idx / 8;
                let byte_in_lane = byte_idx % 8;
                out[pos + i] = (self.state[lane] >> (byte_in_lane * 8)) as u8;
            }
            self.offset += chunk;
            pos += chunk;
            if self.offset == self.rate {
                self.keccak_f();
                self.offset = 0;
            }
        }
    }

    pub fn hash(data: &[u8], output: &mut [u8]) {
        let mut k = Keccak::new(512, output.len());
        k.absorb(data);
        k.squeeze(output);
    }

    pub fn shake(data: &[u8], output: &mut [u8]) {
        let mut k = Keccak::new(512, 0);
        k.absorb(data);
        k.squeeze(output);
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::sha3_256();
    k.absorb(data);
    k.squeeze(&mut out);
    out
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut k = Keccak::sha3_512();
    k.absorb(data);
    k.squeeze(&mut out);
    out
}

pub fn shake128(data: &[u8], out: &mut [u8]) {
    let mut k = Keccak::shake128();
    k.absorb(data);
    k.squeeze(out);
}

pub fn shake256(data: &[u8], out: &mut [u8]) {
    Keccak::shake(data, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST FIPS 202 examples, linked from the NIST example-values page:
    // https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    // SHA3-512_Msg0.pdf, SHAKE128_Msg0.pdf, and SHAKE256_Msg0.pdf.
    const SHA3_512_EMPTY: [u8; 64] = [
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
    ];

    #[test]
    fn nist_sha3_512_empty() {
        assert_eq!(sha3_512(b""), SHA3_512_EMPTY);
    }

    #[test]
    fn nist_shake128_empty() {
        let mut output = [0u8; 32];
        shake128(b"", &mut output);
        assert_eq!(
            output,
            [
                0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
                0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
                0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
                0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
            ]
        );
    }

    #[test]
    fn nist_shake256_empty() {
        let mut output = [0u8; 32];
        shake256(b"", &mut output);
        assert_eq!(
            output,
            [
                0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
                0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
                0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
                0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
            ]
        );
    }

    #[test]
    fn test_sha3_256_empty() {
        let result = sha3_256(b"");
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(result, expected, "got {:02x?}", result);
    }

    #[test]
    fn test_sha3_256_abc() {
        let result = sha3_256(b"abc");
        let expected = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(result, expected, "got {:02x?}", result);
    }
}
