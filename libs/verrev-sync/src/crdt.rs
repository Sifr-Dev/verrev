use alloc::vec::Vec;
use core::cmp::Ordering;

use verrev_hash::sha3;
use crate::*;

pub type LamportTs = u64;
pub type SiteId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpId {
    pub site: SiteId,
    pub seq: u64,
    pub ts: LamportTs,
}

impl Ord for OpId {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.ts, self.seq, &self.site[..]).cmp(&(other.ts, other.seq, &other.site[..]))
    }
}

impl PartialOrd for OpId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub enum CrdtValue {
    Text(TextCursor),
    Map,
    List,
    Counter(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct TextCursor {
    pub id: OpId,
    pub pos: u32,
}

pub struct TextCrdt {
    items: Vec<CharItem>,
}

#[derive(Debug, Clone)]
struct CharItem {
    id: OpId,
    char: char,
    is_deleted: bool,
    parent_left: Option<OpId>,
    parent_right: Option<OpId>,
}

impl TextCrdt {
    pub fn new() -> Self {
        TextCrdt { items: Vec::new() }
    }

    pub fn insert(&mut self, site: SiteId, pos: usize, c: char, ts: LamportTs) -> Result<()> {
        let mut visible_count = 0;
        let mut insert_idx = 0;
        let mut parent_left = None;
        
        if pos > 0 {
            for (i, item) in self.items.iter().enumerate() {
                if !item.is_deleted {
                    visible_count += 1;
                    if visible_count == pos {
                        parent_left = Some(item.id.clone());
                        insert_idx = i + 1;
                        break;
                    }
                }
            }
            if visible_count < pos {
                return Err(SyncError::InvalidState);
            }
        }
        
        let op_id = OpId { site, seq: self.items.len() as u64, ts };
        
        self.items.insert(insert_idx, CharItem {
            id: op_id,
            char: c,
            is_deleted: false,
            parent_left,
            parent_right: None,
        });
        
        Ok(())
    }

    pub fn delete(&mut self, site: SiteId, pos: usize, ts: LamportTs) -> Result<()> {
        let mut visible_count = 0;
        for item in self.items.iter_mut() {
            if !item.is_deleted {
                if visible_count == pos {
                    item.is_deleted = true;
                    // In a real CRDT, we would also emit an operation with `ts` and `site`.
                    // For Phase 0 local deletes, we just mark it deleted.
                    return Ok(());
                }
                visible_count += 1;
            }
        }
        Err(SyncError::InvalidState)
    }

    pub fn get_text(&self) -> Vec<char> {
        self.items.iter().filter(|i| !i.is_deleted).map(|i| i.char).collect()
    }

    pub fn get_hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = sha3::Keccak::sha3_256();
        for item in self.items.iter() {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&item.id.seq.to_le_bytes());
            hasher.absorb(&buf);
            buf.copy_from_slice(&item.id.site);
            hasher.absorb(&buf);
            let mut char_buf = [0u8; 4];
            char_buf.copy_from_slice(&(item.char as u32).to_le_bytes());
            hasher.absorb(&char_buf);
            hasher.absorb(&[item.is_deleted as u8]);
        }
        let mut out = [0u8; HASH_SIZE];
        hasher.squeeze(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_crdt() {
        let mut crdt = TextCrdt::new();
        let site = [1u8; 32];
        
        crdt.insert(site, 0, 'h', 1).unwrap();
        crdt.insert(site, 1, 'e', 2).unwrap();
        crdt.insert(site, 2, 'l', 3).unwrap();
        crdt.insert(site, 3, 'l', 4).unwrap();
        crdt.insert(site, 4, 'o', 5).unwrap();
        
        assert_eq!(crdt.get_text(), alloc::vec!['h', 'e', 'l', 'l', 'o']);
        
        crdt.delete(site, 4, 6).unwrap(); // delete 'o'
        assert_eq!(crdt.get_text(), alloc::vec!['h', 'e', 'l', 'l']);
        
        crdt.insert(site, 4, 'p', 7).unwrap(); // insert 'p'
        assert_eq!(crdt.get_text(), alloc::vec!['h', 'e', 'l', 'l', 'p']);
    }
}
