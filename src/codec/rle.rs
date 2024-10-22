use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

fn process_plane(
    input: &mut dyn Read,
    width: u32,
    height: u32,
    output: &mut [u8],
) -> RdpResult<()> {
    // process_plane operates on RDP 6.0 RLE Segments, see:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/f7e4c717-669e-4f31-8b34-e8f5ab2e107e

    let mut this_line: u32;
    let mut last_line: u32 = 0;
    let mut raw = 0u8;

    let mut indexh = 0;
    while indexh < height {
        let mut out = (width * height * 4) - ((indexh + 1) * width * 4);
        this_line = out;
        let mut indexw = 0;

        // first line uses absolute values, so the raw value is written directly to output
        if last_line == 0 {
            while indexw < width {
                let (mut run_length, mut raw_bytes) = parse_control_byte(input.read_u8()?);
                while raw_bytes > 0 {
                    raw = input.read_u8()?;
                    output[out as usize] = raw;
                    out += 4;
                    indexw += 1;
                    raw_bytes -= 1;
                }
                while run_length > 0 {
                    output[out as usize] = raw;
                    out += 4;
                    indexw += 1;
                    run_length -= 1;
                }
            }
        } else {
            // subsequent scan lines compute delta values from the previous line,
            // so there's some extra math before we write into output
            let mut delta = 0;
            while indexw < width {
                let (mut run_length, mut raw_bytes) = parse_control_byte(input.read_u8()?);

                // the unsigned, 8-bit delta values are added to the absolute values of the
                // previous scan-line using 1-byte arithmetic
                let mut compute_delta = |d: i8| {
                    output[out as usize] =
                        (output[(last_line + (indexw * 4)) as usize] as i32 + d as i32) as u8;
                    out += 4;
                    indexw += 1;
                };

                while raw_bytes > 0 {
                    delta = decode_delta(input.read_u8()?);
                    compute_delta(delta);
                    raw_bytes -= 1;
                }
                while run_length > 0 {
                    compute_delta(delta);
                    run_length -= 1;
                }
            }
        }
        indexh += 1;
        last_line = this_line;
    }
    Ok(())
}

/// Extracts the run length and number of raw bytes from the
/// RDP 6.0 RLE Segment's control byte.
///
/// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/f7e4c717-669e-4f31-8b34-e8f5ab2e107e
fn parse_control_byte(control: u8) -> (u8, u8) {
    let mut run_length = control & 0xf;
    let mut raw_bytes = (control >> 4) & 0xf;

    // TODO: check for control==0 which is not allowed per spec

    // Because a RUN MUST be a sequence of at least three values (section 3.1.9.2),
    // the values 1 and 2 are used in the run length field to encode extra long
    // RUN sequences of more than 16 values:
    let revcode = (run_length << 4) | raw_bytes;
    if (16..=47).contains(&revcode) {
        run_length = revcode;
        raw_bytes = 0;
    }

    (run_length, raw_bytes)
}

/// Performs delta transformation to the delta value as per section 3.1.9.2.3.
/// This applies to all scan lines other than the first line.
///
/// See See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/46a9972c-0cdd-4673-add4-87f89b837742
fn decode_delta(mut delta: u8) -> i8 {
    if delta & 1 != 0 {
        // If the encoded delta value is odd, then decrement it by 1,
        // shift it 1 bit toward the lowest bit, and subtract it from 255.
        delta >>= 1;
        delta += 1;
        -(delta as i32) as i8
    } else {
        // If the encoded delta value is even, shift it 1 bit toward the lowest bit.
        delta >>= 1;
        delta as i8
    }
}

const FORMAT_HEADER_CLL_MASK: u8 = 0x07;
const FORMAT_HEADER_CS: u8 = 1 << 3;
const FORMAT_HEADER_RLE: u8 = 1 << 4;
const FORMAT_HEADER_NA: u8 = 1 << 5;

/// Run length encoding decoding function for 32 bpp
pub fn rle_32_decompress(
    input: &[u8],
    width: u32,
    height: u32,
    output: &mut [u8],
) -> RdpResult<()> {
    // Note: this implementation supports only a subset of the decompression
    // process. For a more complete illustration of all of the steps, see
    //
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/872615ff-e1ac-469b-9448-2c4452b0d21b
    // https://github.com/FreeRDP/FreeRDP/blob/9a80afeb08acfbc99992323b4bb41d8dd7befff5/libfreerdp/codec/planar.c#L633

    let mut input_cursor = Cursor::new(input);

    // Check the format header:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/9b422f69-8e05-4c6d-b6fb-fa02ef75a8f2
    let format_header = input_cursor.read_u8()?;
    let cll = format_header & FORMAT_HEADER_CLL_MASK;
    let cs = format_header & FORMAT_HEADER_CS != 0;
    let rle = format_header & FORMAT_HEADER_RLE != 0;
    let skip_alpha = format_header & FORMAT_HEADER_NA != 0;

    // this is invalid per the spec and should never happen
    if cll == 0 && cs {
        return Err(Error::RdpError(RdpError::new(
            RdpErrorKind::UnexpectedType,
            "chroma subsampling requires AYCoCg and does not work with RGB data",
        )));
    }

    // these are valid configurations, but not currently supported in this library
    if !rle {
        return Err(Error::RdpError(RdpError::new(
            RdpErrorKind::UnexpectedType,
            "expected RLE compression: raw color planes are not supported",
        )));
    }
    if cs {
        return Err(Error::RdpError(RdpError::new(
            RdpErrorKind::UnexpectedType,
            "chroma subsampling is not supported",
        )));
    }

    if skip_alpha {
        // TODO: create a fully opaque alpha plane instead
        return Err(Error::RdpError(RdpError::new(
            RdpErrorKind::UnexpectedType,
            "expected alpha plane: skip alpha not supported",
        )));
    }

    process_plane(&mut input_cursor, width, height, &mut output[3..])?; // alpha
    process_plane(&mut input_cursor, width, height, &mut output[2..])?; // blue
    process_plane(&mut input_cursor, width, height, &mut output[1..])?; // green
    process_plane(&mut input_cursor, width, height, &mut output[0..])?; // red

    // we always overwrite the alpha to be fully opaque
    // (either because it wasn't sent, or because Windows often sends it as fully transparent)
    set_plane(0xFF, width, height, &mut output[3..]);

    Ok(())
}

fn set_plane(value: u8, width: u32, height: u32, output: &mut [u8]) {
    for indexh in 0..height {
        for indexw in 0..width {
            let out = (indexh * width * 4) + (4 * indexw);
            output[out as usize] = value;
        }
    }
}

macro_rules! repeat {
    ($expr:expr, $count:expr, $x:expr, $width:expr) => {
        while (($count & !0x7) != 0) && ($x + 8) < $width {
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
        }
        while $count > 0 && $x < $width {
            $expr;
            $count -= 1;
            $x += 1;
        }
    };
}

pub fn rle_16_decompress(
    input: &[u8],
    width: usize,
    mut height: usize,
    output: &mut [u16],
) -> RdpResult<()> {
    let mut input_cursor = Cursor::new(input);

    let mut code: u8;
    let mut opcode: u8;
    let mut lastopcode: u8 = 0xFF;
    let mut count: u16;
    let mut offset: u16;
    let mut isfillormix;
    let mut insertmix = false;
    let mut x: usize = width;
    let mut prevline: Option<usize> = None;
    let mut line: Option<usize> = None;
    let mut colour1 = 0;
    let mut colour2 = 0;
    let mut mix = 0xffff;
    let mut mask: u8 = 0;
    let mut fom_mask: u8;
    let mut mixmask: u8;
    let mut bicolour = false;

    while (input_cursor.position() as usize) < input.len() {
        fom_mask = 0;
        code = input_cursor.read_u8()?;
        opcode = code >> 4;

        match opcode {
            12..=14 => {
                opcode -= 6;
                count = (code & 0xf) as u16;
                offset = 16;
            }
            0xF => {
                opcode = code & 0xf;
                if opcode < 9 {
                    count = input_cursor.read_u16::<LittleEndian>()?
                } else if opcode < 0xb {
                    count = 8
                } else {
                    count = 1
                }
                offset = 0;
            }
            _ => {
                opcode >>= 1;
                count = (code & 0x1f) as u16;
                offset = 32;
            }
        }

        if offset != 0 {
            isfillormix = (opcode == 2) || (opcode == 7);
            if count == 0 {
                if isfillormix {
                    count = input_cursor.read_u8()? as u16 + 1;
                } else {
                    count = input_cursor.read_u8()? as u16 + offset;
                }
            } else if isfillormix {
                count <<= 3;
            }
        }

        match opcode {
            0 => {
                if lastopcode == opcode && !(x == width && prevline.is_none()) {
                    insertmix = true;
                }
            }
            8 => {
                colour1 = input_cursor.read_u16::<LittleEndian>()?;
                colour2 = input_cursor.read_u16::<LittleEndian>()?;
            }
            3 => {
                colour2 = input_cursor.read_u16::<LittleEndian>()?;
            }
            6 | 7 => {
                mix = input_cursor.read_u16::<LittleEndian>()?;
                opcode -= 5;
            }
            9 => {
                mask = 0x03;
                opcode = 0x02;
                fom_mask = 3;
            }
            0xa => {
                mask = 0x05;
                opcode = 0x02;
                fom_mask = 5;
            }
            _ => (),
        }
        lastopcode = opcode;
        mixmask = 0;

        while count > 0 {
            if x >= width {
                x = 0;
                height -= 1;
                prevline = line;
                line = Some(height * width);
            }

            match opcode {
                0 => {
                    if insertmix {
                        if let Some(e) = prevline {
                            output[line.unwrap() + x] = output[e + x] ^ mix;
                        } else {
                            output[line.unwrap() + x] = mix;
                        }
                        insertmix = false;
                        count -= 1;
                        x += 1;
                    }

                    if let Some(e) = prevline {
                        repeat!(output[line.unwrap() + x] = output[e + x], count, x, width);
                    } else {
                        repeat!(output[line.unwrap() + x] = 0, count, x, width);
                    }
                }
                1 => {
                    if let Some(e) = prevline {
                        repeat!(
                            output[line.unwrap() + x] = output[e + x] ^ mix,
                            count,
                            x,
                            width
                        );
                    } else {
                        repeat!(output[line.unwrap() + x] = mix, count, x, width);
                    }
                }
                2 => {
                    if let Some(e) = prevline {
                        repeat!(
                            {
                                mixmask <<= 1;
                                if mixmask == 0 {
                                    mask = if fom_mask != 0 {
                                        fom_mask
                                    } else {
                                        input_cursor.read_u8()?
                                    };
                                    mixmask = 1;
                                }
                                if (mask & mixmask) != 0 {
                                    output[line.unwrap() + x] = output[e + x] ^ mix;
                                } else {
                                    output[line.unwrap() + x] = output[e + x];
                                }
                            },
                            count,
                            x,
                            width
                        );
                    } else {
                        repeat!(
                            {
                                mixmask <<= 1;
                                if mixmask == 0 {
                                    mask = if fom_mask != 0 {
                                        fom_mask
                                    } else {
                                        input_cursor.read_u8()?
                                    };
                                    mixmask = 1;
                                }
                                if (mask & mixmask) != 0 {
                                    output[line.unwrap() + x] = mix;
                                } else {
                                    output[line.unwrap() + x] = 0;
                                }
                            },
                            count,
                            x,
                            width
                        );
                    }
                }
                3 => {
                    repeat!(output[line.unwrap() + x] = colour2, count, x, width);
                }
                4 => {
                    repeat!(
                        output[line.unwrap() + x] = input_cursor.read_u16::<LittleEndian>()?,
                        count,
                        x,
                        width
                    );
                }
                8 => {
                    repeat!(
                        {
                            if bicolour {
                                output[line.unwrap() + x] = colour2;
                                bicolour = false;
                            } else {
                                output[line.unwrap() + x] = colour1;
                                bicolour = true;
                                count += 1;
                            };
                        },
                        count,
                        x,
                        width
                    );
                }
                0xd => {
                    repeat!(output[line.unwrap() + x] = 0xffff, count, x, width);
                }
                0xe => {
                    repeat!(output[line.unwrap() + x] = 0, count, x, width);
                }
                _ => panic!("opcode"),
            }
        }
    }

    Ok(())
}

pub fn rgb565torgb32(input: &[u16], width: usize, height: usize) -> Vec<u8> {
    let mut result_32_bpp = vec![0_u8; width * height * 4];
    for i in 0..height {
        for j in 0..width {
            let index = i * width + j;
            let v = input[index];
            result_32_bpp[index * 4 + 3] = 0xff;
            result_32_bpp[index * 4 + 2] = (((((v >> 11) & 0x1f) * 527) + 23) >> 6) as u8;
            result_32_bpp[index * 4 + 1] = (((((v >> 5) & 0x3f) * 259) + 33) >> 6) as u8;
            result_32_bpp[index * 4] = ((((v & 0x1f) * 527) + 23) >> 6) as u8;
        }
    }
    result_32_bpp
}

#[cfg(test)]
mod tests {
    use super::process_plane;
    use super::rle_32_decompress;
    use super::set_plane;
    use std::io::Cursor;

    #[test]
    fn test_process_plane() {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/46a9972c-0cdd-4673-add4-87f89b837742
        let encoded_plane: Vec<u8> = vec![
            0x13, 0xFF, 0x20, 0xFE, 0xFD, 0x60, 0x01, 0x7D, 0xF5, 0xC2, 0x9A, 0x38, 0x60, 0x01,
            0x67, 0x8B, 0xA3, 0x78, 0xAF,
        ];
        let (width, height) = (6u32, 3u32);

        let mut input_cursor = Cursor::new(encoded_plane);

        // width * height * 4 bytes/pixel
        let mut output = vec![0_u8; width as usize * height as usize * 4];
        process_plane(&mut input_cursor, width, height, &mut output).expect("decode failed");

        // the decoded plane from the MSFT example
        // (in the doc the scan lines are listed in reverse order)
        let decoded: Vec<u8> = vec![
            253, 140, 62, 14, 135, 193, //
            254, 192, 132, 96, 75, 25, //
            255, 255, 255, 255, 254, 253, //
        ];

        // process_plane assumes 32 bits per pixel, and writes a decoded
        // value one every 4 bytes, so construct the expected value first
        let mut want = Vec::with_capacity(decoded.len() * 4);
        for d in decoded.iter() {
            want.push(*d);
            want.push(0);
            want.push(0);
            want.push(0);
        }

        assert_eq!(output, want);
    }

    #[test]
    fn test_rle_32_decompress() {
        for entry in std::fs::read_dir("./src/codec/rle/testdata").expect("reading testdata") {
            let mut name = entry.unwrap().path();
            match name.extension() {
                Some(ext) if ext == "in" => {}
                _ => continue,
            }

            let (width, height) = (64u32, 64u32);

            let input = std::fs::read(&name).unwrap_or_else(|_| panic!("reading in {name:?}"));

            assert!(name.set_extension("out"));
            let mut out = std::fs::read(&name).unwrap_or_else(|_| panic!("reading out {name:?}"));
            set_plane(0xFF, width, height, &mut out[3..]); // set alpha plane to opaque

            let mut result = vec![0_u8; width as usize * height as usize * 4];
            rle_32_decompress(&input, width, height, &mut result).unwrap();

            assert_eq!(out.len(), result.len());
            assert_eq!(out, result, "for file {name:?}");
        }
    }
}
