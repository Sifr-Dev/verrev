pub struct ChaosConfig {
    pub loss_rate: f32,
    pub reorder_rate: f32,
    pub min_delay_ms: u32,
    pub max_delay_ms: u32,
    pub corruption_rate: f32,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        ChaosConfig {
            loss_rate: 0.0,
            reorder_rate: 0.0,
            min_delay_ms: 0,
            max_delay_ms: 0,
            corruption_rate: 0.0,
        }
    }
}
