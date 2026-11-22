use alloc::collections::BinaryHeap;
use alloc::vec::Vec;

use verrev_identity::Identity;

use crate::*;

pub struct RoutingTable {
    local_id: Identity,
    buckets: Vec<KBucket>,
}

struct KBucket {
    entries: Vec<PeerInfo>,
}

impl RoutingTable {
    pub fn new(local_id: Identity) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket { entries: Vec::with_capacity(K) });
        }
        RoutingTable { local_id, buckets }
    }

    pub fn insert(&mut self, peer: PeerInfo) -> bool {
        let dist = xor_distance(self.local_id.as_bytes(), peer.identity.as_bytes());
        let bucket_idx = leading_zero_bits(&dist);
        if bucket_idx >= 256 {
            return false;
        }
        let bucket = &mut self.buckets[bucket_idx];

        if let Some(pos) = bucket.entries.iter().position(|p| p.identity == peer.identity) {
            bucket.entries.remove(pos);
            bucket.entries.insert(0, peer);
            return true;
        }

        if bucket.entries.len() < K {
            bucket.entries.insert(0, peer);
            return true;
        }

        false
    }

    pub fn find_closest(&self, target: &Identity, count: usize) -> Vec<PeerInfo> {
        let k = if count == 0 { K } else { count };
        let mut heap: BinaryHeap<(u32, PeerInfo)> = BinaryHeap::with_capacity(k + 1);

        for bucket in &self.buckets {
            for node in &bucket.entries {
                let d = xor_distance(target.as_bytes(), node.identity.as_bytes());
                let d_val = (d[0] as u32) << 24 | (d[1] as u32) << 16
                          | (d[2] as u32) << 8 | (d[3] as u32);
                heap.push((d_val, node.clone()));
                if heap.len() > k {
                    heap.pop();
                }
            }
        }

        heap.into_sorted_vec().into_iter().map(|(_, n)| n).collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| bucket.entries.is_empty())
    }

    pub fn bucket_len(&self, idx: usize) -> usize {
        self.buckets.get(idx).map(|b| b.entries.len()).unwrap_or(0)
    }
}

pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

pub fn leading_zero_bits(x: &[u8; 32]) -> usize {
    let mut count = 0;
    for &byte in x {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zeros() {
        let mut arr = [0u8; 32];
        arr[3] = 0x80;
        assert_eq!(leading_zero_bits(&arr), 24);
        assert_eq!(leading_zero_bits(&[0xFF; 32]), 0);
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
    }

    #[test]
    fn test_xor_distance() {
        let a = [0xFF; 32];
        let b = [0x00; 32];
        let d = xor_distance(&a, &b);
        assert_eq!(d, [0xFF; 32]);
    }

    fn make_id(seed: u8) -> Identity {
        let mut s = [0u8; 64];
        s[0] = seed;
        let kp = verrev_crypto::dilithium::generate_keypair(Some(&s));
        Identity::from_public_key(&kp.public_key)
    }

    #[test]
    fn test_insert_and_find() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        let peers: Vec<PeerInfo> = (1..5).map(|i| PeerInfo {
            identity: make_id(i),
            addrs: Vec::new(),
            distance: [0u8; 32],
        }).collect();

        for p in &peers {
            assert!(rt.insert(p.clone()));
        }
        assert_eq!(rt.len(), peers.len());

        let closest = rt.find_closest(&local, 10);
        assert_eq!(closest.len(), peers.len());
    }

    #[test]
    fn test_insert_duplicate() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        let p1 = PeerInfo { identity: make_id(1), addrs: Vec::new(), distance: [0u8; 32] };
        let p2 = PeerInfo { identity: make_id(2), addrs: Vec::new(), distance: [0u8; 32] };
        assert!(rt.insert(p1.clone()));
        assert!(rt.insert(p2.clone()));
        assert!(rt.insert(p1.clone()));
        assert_eq!(rt.len(), 2);
    }

    #[test]
    fn test_find_closest_returns_at_most_k() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        for i in 0..30 {
            rt.insert(PeerInfo { identity: make_id(i + 1), addrs: Vec::new(), distance: [0u8; 32] });
        }
        let closest = rt.find_closest(&local, K);
        assert!(closest.len() <= K);
        assert!(!closest.is_empty());
    }

    #[test]
    fn test_many_inserts_no_panic() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        for i in 0..100 {
            rt.insert(PeerInfo { identity: make_id(i as u8 + 1), addrs: Vec::new(), distance: [0u8; 32] });
        }
        assert!(!rt.is_empty());
    }
}
