use alloc::vec;
use alloc::vec::Vec;

pub struct NetworkSimulation {
    peers: usize,
    latency_matrix: Vec<Vec<u32>>,
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,
}

impl NetworkSimulation {
    pub fn new(peers: usize) -> Self {
        let latency_matrix = (0..peers).map(|_| vec![0u32; peers]).collect();
        NetworkSimulation {
            peers,
            latency_matrix,
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
        }
    }

    pub fn set_latency(&mut self, from: usize, to: usize, ms: u32) {
        if from < self.peers && to < self.peers {
            self.latency_matrix[from][to] = ms;
        }
    }

    pub fn latency(&self, from: usize, to: usize) -> u32 {
        if from < self.peers && to < self.peers {
            self.latency_matrix[from][to]
        } else {
            0
        }
    }

    pub fn send(&mut self, from: usize, to: usize, loss_rate: f32) -> bool {
        self.packets_sent += 1;
        if from >= self.peers || to >= self.peers {
            self.packets_lost += 1;
            return false;
        }
        if loss_rate > 0.0 && self.bernoulli_trial(loss_rate) {
            self.packets_lost += 1;
            return false;
        }
        self.packets_received += 1;
        true
    }

    /// Bernoulli trial using a deterministic hash of the packet counter.
    /// Each call is an independent trial with probability `rate` of returning true.
    fn bernoulli_trial(&self, rate: f32) -> bool {
        let state = self.packets_sent.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hash = state ^ (state >> 16);
        (hash as f64 / u64::MAX as f64) < rate as f64
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.packets_sent, self.packets_received, self.packets_lost)
    }

    pub fn run(&self) {
        // Placeholder for full simulation execution
    }
}
