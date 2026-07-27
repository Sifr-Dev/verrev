#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_capability::Capability;
use verrev_identity::Identity;
use verrev_runtime::WasmModule;

pub mod scheduler;
pub mod verification;
pub mod credit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeError {
    NoAvailableWorker,
    VerificationFailed,
    BudgetExceeded,
    DeadlineExceeded,
    CreditInsufficient,
    FunctionNotFound,
}

pub type Result<T> = core::result::Result<T, ComputeError>;

pub struct Job {
    pub id: [u8; 32],
    pub function_hash: [u8; 32],
    pub args_hash: [u8; 32],
    pub budget: u64,
    pub deadline: u64,
    pub submitter: Identity,
}

pub struct ComputeNode {
    identity: Identity,
    capabilities: Vec<Capability>,
    jobs_completed: u64,
}

impl ComputeNode {
    pub fn new(identity: Identity) -> Self {
        ComputeNode {
            identity,
            capabilities: Vec::new(),
            jobs_completed: 0,
        }
    }

    pub fn execute_job(&mut self, _job: &Job, _module: &WasmModule) -> Result<Vec<u8>> {
        Err(ComputeError::NoAvailableWorker)
    }

    pub fn submit_job(&self, _function_hash: [u8; 32], _args: &[u8]) -> Result<Vec<u8>> {
        Err(ComputeError::NoAvailableWorker)
    }
}
