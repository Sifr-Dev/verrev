pub struct Font {
    data: &'static [u8],
    size: f32,
}

impl Font {
    pub fn new(data: &'static [u8], size: f32) -> Self {
        Font { data, size }
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }

    pub fn measure(&self, text: &[char]) -> (f32, f32) {
        // Phase 0: Monospace approximation
        let char_width = self.size * 0.6;
        let total_width = text.len() as f32 * char_width;
        (total_width, self.size)
    }
}

use alloc::vec::Vec;

pub struct TextLayout {
    pub glyphs: Vec<GlyphPlacement>,
    pub size: (f32, f32),
}

pub struct GlyphPlacement {
    pub glyph_id: u32,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}
