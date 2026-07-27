#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    NotADirectory,
    NotAFile,
    PermissionDenied,
    AlreadyExists,
}

pub type Result<T> = core::result::Result<T, FsError>;

pub struct Directory {
    entries: Vec<DirEntry>,
}

struct DirEntry {
    name: Vec<u8>,
    hash: [u8; 32],
    is_directory: bool,
}

impl Directory {
    pub fn new() -> Self {
        Directory { entries: Vec::new() }
    }

    pub fn lookup(&self, name: &[u8]) -> Option<[u8; 32]> {
        self.entries.iter().find(|e| e.name.as_slice() == name).map(|e| e.hash)
    }

    pub fn add_entry(&mut self, name: &[u8], hash: [u8; 32], is_directory: bool) -> Result<()> {
        if self.entries.iter().any(|e| e.name.as_slice() == name) {
            return Err(FsError::AlreadyExists);
        }
        self.entries.push(DirEntry {
            name: name.to_vec(),
            hash,
            is_directory,
        });
        Ok(())
    }
}
