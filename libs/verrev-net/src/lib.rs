#![no_std]

extern crate alloc;

pub mod simulation;
pub mod chaos;

pub const DEFAULT_LOSS_RATE: f32 = 0.0;
pub const DEFAULT_REORDER_RATE: f32 = 0.0;
pub const DEFAULT_DELAY_MS: u32 = 0;
