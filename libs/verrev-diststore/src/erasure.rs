use alloc::vec::Vec;
use crate::*;

// GF(2^8) multiplication using Russian Peasant algorithm
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while a != 0 && b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1d; // x^8 + x^4 + x^3 + x^2 + 1
        }
        b >>= 1;
    }
    p
}

pub fn encode(data: &[u8], data_shards: usize, parity_shards: usize) -> Result<Vec<Vec<u8>>> {
    if data_shards == 0 || data.is_empty() {
        return Err(DistStoreError::RepairFailed);
    }
    
    let chunk_size = data.len().div_ceil(data_shards);
    let mut padded_data = data.to_vec();
    padded_data.resize(chunk_size * data_shards, 0);
    
    let mut shards = Vec::with_capacity(data_shards + parity_shards);
    for i in 0..data_shards {
        shards.push(padded_data[i * chunk_size..(i + 1) * chunk_size].to_vec());
    }
    
    // Vandermonde matrix encoding for parity
    for i in 0..parity_shards {
        let mut parity = alloc::vec![0u8; chunk_size];
        for (j, shard) in shards.iter().enumerate().take(data_shards) {
            // coefficient = (j + 1)^(i + 1)
            let mut coef = 1;
            for _ in 0..=i { coef = gf_mul(coef, (j + 1) as u8); }
            
            for k in 0..chunk_size {
                parity[k] ^= gf_mul(coef, shard[k]);
            }
        }
        shards.push(parity);
    }
    
    Ok(shards)
}

pub fn decode(shards: &[Vec<u8>], data_shards: usize) -> Result<Vec<u8>> {
    // For Phase 0, we assume the first `data_shards` are intact.
    // Full Reed-Solomon decoding requires matrix inversion which is complex.
    // If we have the original data shards, just concatenate.
    if shards.len() < data_shards {
        return Err(DistStoreError::RepairFailed);
    }
    
    let mut result = Vec::new();
    for shard in shards.iter().take(data_shards) {
        result.extend_from_slice(shard);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erasure_encode_decode() {
        let data = b"Hello, distributed world!";
        let data_shards = 4;
        let parity_shards = 2;
        
        let shards = encode(data, data_shards, parity_shards).unwrap();
        assert_eq!(shards.len(), data_shards + parity_shards);
        
        let decoded = decode(&shards, data_shards).unwrap();
        
        // decoded might have padding, so we check if it starts with the original data
        assert!(decoded.starts_with(data));
    }
}
