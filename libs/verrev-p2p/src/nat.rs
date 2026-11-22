pub enum NatType {
    None,
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
}

pub struct NatTraversal;

impl NatTraversal {
    pub fn detect() -> NatType {
        NatType::None
    }

    pub fn punch_hole(_addr: &super::PeerAddr) -> bool {
        false
    }
}
