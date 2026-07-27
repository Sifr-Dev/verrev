use alloc::vec::Vec;
use crate::*;

pub struct Button {
    pub rect: Rect,
    pub label: Vec<char>,
    pub pressed: bool,
    pub enabled: bool,
}

impl Button {
    pub fn new(label: &str) -> Self {
        let mut chars = Vec::new();
        for c in label.chars() {
            chars.push(c);
        }
        Button { rect: Rect::new(0.0, 0.0, 100.0, 32.0), label: chars, pressed: false, enabled: true }
    }
}

pub struct TextInput {
    pub rect: Rect,
    pub content: Vec<char>,
    pub cursor_pos: usize,
    pub focused: bool,
}

impl TextInput {
    pub fn new() -> Self {
        TextInput { rect: Rect::new(0.0, 0.0, 300.0, 32.0), content: Vec::new(), cursor_pos: 0, focused: false }
    }
}

pub struct ScrollView {
    pub rect: Rect,
    pub scroll_offset: Point,
    pub content_size: Size,
}
