use crate::model::data::{Message, U16};
use std::io::Cursor;

/// Use to to_unicode function for String
pub trait Unicode {
    fn to_unicode(&self) -> Vec<u8>;
}

impl Unicode for String {
    /// Convert any string into utf-16le string
    ///
    /// # Example
    /// ```
    /// use rdp::model::unicode::Unicode;
    /// let s = "foo".to_string();
    /// assert_eq!(s.to_unicode(), [102, 0, 111, 0, 111, 0])
    /// ```
    fn to_unicode(&self) -> Vec<u8> {
        let mut result = Cursor::new(Vec::new());
        for c in self.encode_utf16() {
            let encode_char = U16::LE(c);
            encode_char.write(&mut result).unwrap();
        }
        result.into_inner()
    }
}

pub fn parse_utf16le(bytes: &[u8]) -> String {
    let x: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| (pair[1] as u16) << 8 | pair[0] as u16)
        .collect();

    // strip last null character
    String::from_utf16_lossy(&x[..x.len() - 1])
}
