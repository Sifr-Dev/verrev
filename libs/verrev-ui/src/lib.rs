#![no_std]

extern crate alloc;

pub mod compositor;
pub mod widgets;
pub mod text;

pub struct Point {
    pub x: f32,
    pub y: f32,
}

pub struct Size {
    pub width: f32,
    pub height: f32,
}

pub struct Rect {
    pub origin: Point,
    pub size: Size,
}

pub type Color = [f32; 4];

impl Rect {
    pub fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Rect { origin: Point { x, y }, size: Size { width: w, height: h } }
    }
}
