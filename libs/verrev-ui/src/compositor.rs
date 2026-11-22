use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::*;

pub struct Compositor;

impl Compositor {
    pub fn new() -> Self {
        Compositor
    }

    pub fn initialize(&mut self) -> bool {
        true
    }

    pub fn present(&mut self, _scene: &Scene) {
    }
}

impl Default for Compositor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Scene {
    pub root: SceneNode,
}

pub enum SceneNode {
    Rectangle { rect: Rect, color: Color, children: Box<[SceneNode]> },
    Text { rect: Rect, text: Vec<char>, color: Color, font_size: f32 },
    Image { rect: Rect, data: &'static [u8] },
    Clip { rect: Rect, child: Box<SceneNode> },
    Transform { matrix: [f32; 16], child: Box<SceneNode> },
}

impl Scene {
    pub fn new() -> Self {
        Scene { root: SceneNode::Rectangle { rect: Rect::new(0.0, 0.0, 800.0, 600.0), color: [0.1, 0.1, 0.12, 1.0], children: Box::new([]) } }
    }
}

impl Default for Scene {
    fn default() -> Self {
        Self::new()
    }
}
