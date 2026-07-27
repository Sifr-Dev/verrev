use alloc::vec::Vec;
use crate::*;
use verrev_hash::sha3::sha3_256;

pub struct MerkleTree {
    leaves: Vec<[u8; HASH_SIZE]>,
    levels: Vec<Vec<[u8; HASH_SIZE]>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree { leaves: Vec::new(), levels: Vec::new() }
    }

    pub fn insert(&mut self, data: &[u8]) {
        let leaf_idx = self.leaves.len();
        self.leaves.push(sha3_256(data));

        let mut prev_len = self.leaves.len();
        let mut update_idx = leaf_idx;
        let mut level = 0;

        while prev_len > 1 {
            let parent_count = (prev_len + 1) / 2;
            let pair_idx = update_idx / 2;

            while self.levels.len() <= level {
                self.levels.push(Vec::new());
            }
            while self.levels[level].len() < parent_count {
                self.levels[level].push([0u8; HASH_SIZE]);
            }

            let children = if level == 0 {
                &self.leaves[..]
            } else {
                &self.levels[level - 1][..]
            };

            let left = children[2 * pair_idx];
            let right = if 2 * pair_idx + 1 < children.len() {
                children[2 * pair_idx + 1]
            } else {
                left
            };

            let mut combined = [0u8; 64];
            combined[..HASH_SIZE].copy_from_slice(&left);
            combined[HASH_SIZE..].copy_from_slice(&right);
            self.levels[level][pair_idx] = sha3_256(&combined);

            prev_len = parent_count;
            update_idx = pair_idx;
            level += 1;
        }
    }

    pub fn root_hash(&self) -> [u8; HASH_SIZE] {
        if self.leaves.is_empty() {
            return [0u8; HASH_SIZE];
        }
        if self.leaves.len() == 1 {
            return self.leaves[0];
        }
        if let Some(top) = self.levels.last() {
            if let Some(&hash) = top.first() {
                return hash;
            }
        }
        [0u8; HASH_SIZE]
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn get_leaf(&self, index: usize) -> Option<&[u8; HASH_SIZE]> {
        self.leaves.get(index)
    }

    fn hash_at(&self, level: usize, pos: usize) -> Option<[u8; HASH_SIZE]> {
        if level == 0 {
            return self.leaves.get(pos).copied();
        }
        self.levels.get(level - 1).and_then(|l| l.get(pos)).copied()
    }

    pub fn diff(&self, other: &MerkleTree) -> Vec<usize> {
        if self.root_hash() == other.root_hash() && self.leaf_count() == other.leaf_count() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let max_leaves = self.leaves.len().max(other.leaves.len());
        let root_level = self.levels.len().max(other.levels.len());
        self.diff_rec(other, root_level, 0, max_leaves, &mut result);
        result
    }

    fn diff_rec(
        &self, other: &MerkleTree,
        level: usize, pos: usize,
        max_leaves: usize,
        result: &mut Vec<usize>,
    ) {
        let leaf_span = 1usize << level;
        let range_start = pos * leaf_span;
        if range_start >= max_leaves {
            return;
        }
        let range_end = (range_start + leaf_span).min(max_leaves);

        if range_end - range_start == 1 {
            let a = self.leaves.get(range_start);
            let b = other.leaves.get(range_start);
            if a != b {
                result.push(range_start);
            }
            return;
        }

        if range_end - range_start == 0 {
            return;
        }

        let self_h = self.hash_at(level, pos);
        let other_h = other.hash_at(level, pos);

        if self_h.is_some() && other_h.is_some() && self_h == other_h {
            return;
        }

        if level > 0 {
            self.diff_rec(other, level - 1, pos * 2, max_leaves, result);
            self.diff_rec(other, level - 1, pos * 2 + 1, max_leaves, result);
        } else {
            let left = pos * 2;
            let right = pos * 2 + 1;
            if left < max_leaves {
                let a = self.leaves.get(left);
                let b = other.leaves.get(left);
                if a != b { result.push(left); }
            }
            if right < max_leaves {
                let a = self.leaves.get(right);
                let b = other.leaves.get(right);
                if a != b { result.push(right); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let mt = MerkleTree::new();
        assert_eq!(mt.leaf_count(), 0);
        assert_eq!(mt.root_hash(), [0u8; HASH_SIZE]);
    }

    #[test]
    fn test_single_leaf() {
        let mut mt = MerkleTree::new();
        mt.insert(b"hello");
        assert_eq!(mt.leaf_count(), 1);
        assert_eq!(mt.root_hash(), sha3_256(b"hello"));
    }

    #[test]
    fn test_two_leaves() {
        let mut mt = MerkleTree::new();
        mt.insert(b"a");
        mt.insert(b"b");
        assert_eq!(mt.leaf_count(), 2);

        let h0 = sha3_256(b"a");
        let h1 = sha3_256(b"b");
        let mut combined = [0u8; 64];
        combined[..HASH_SIZE].copy_from_slice(&h0);
        combined[HASH_SIZE..].copy_from_slice(&h1);
        let expected = sha3_256(&combined);
        assert_eq!(mt.root_hash(), expected);
    }

    #[test]
    fn test_three_leaves() {
        let mut mt = MerkleTree::new();
        mt.insert(b"a");
        mt.insert(b"b");
        mt.insert(b"c");
        assert_eq!(mt.leaf_count(), 3);

        let h0 = sha3_256(b"a");
        let h1 = sha3_256(b"b");
        let h2 = sha3_256(b"c");

        let mut p0 = [0u8; 64];
        p0[..HASH_SIZE].copy_from_slice(&h0);
        p0[HASH_SIZE..].copy_from_slice(&h1);
        let pair0 = sha3_256(&p0);

        let mut p1 = [0u8; 64];
        p1[..HASH_SIZE].copy_from_slice(&h2);
        p1[HASH_SIZE..].copy_from_slice(&h2);
        let pair1 = sha3_256(&p1);

        let mut root = [0u8; 64];
        root[..HASH_SIZE].copy_from_slice(&pair0);
        root[HASH_SIZE..].copy_from_slice(&pair1);
        assert_eq!(mt.root_hash(), sha3_256(&root));
    }

    #[test]
    fn test_identical_trees_no_diff() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        for i in 0..10 {
            a.insert(&[i]);
            b.insert(&[i]);
        }
        assert_eq!(a.root_hash(), b.root_hash());
        assert!(a.diff(&b).is_empty());
    }

    #[test]
    fn test_diff_single_change() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        for i in 0..10 {
            a.insert(&[i]);
            b.insert(&[i]);
        }
        b.insert(&[99]); // 11th leaf
        let diff = a.diff(&b);
        assert!(!diff.is_empty());
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0], 10);
    }

    #[test]
    fn test_diff_middle_change() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        for i in 0..10 {
            let val = if i == 5 { 0xFF } else { i };
            a.insert(&[i]);
            b.insert(&[val]);
        }
        let diff = a.diff(&b);
        assert!(diff.contains(&5));
    }

    #[test]
    fn test_diff_different_sizes() {
        let mut a = MerkleTree::new();
        let mut b = MerkleTree::new();
        for i in 0..5 {
            a.insert(&[i as u8]);
        }
        for i in 0..8 {
            b.insert(&[i as u8]);
        }
        let diff = a.diff(&b);
        assert_eq!(diff, [5, 6, 7]);
    }

    #[test]
    fn test_consistency_after_rebuild() {
        let mut mt = MerkleTree::new();
        for i in 0..20 {
            mt.insert(&[i as u8]);
        }
        let root = mt.root_hash();

        let mut mt2 = MerkleTree::new();
        for i in 0..20 {
            mt2.insert(&[i as u8]);
        }
        assert_eq!(mt2.root_hash(), root);
        assert!(mt.diff(&mt2).is_empty());
    }
}
