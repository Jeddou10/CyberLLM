//! can_parser.rs — CAN-FD frame parser for a Rust-based vehicle gateway.
//!
//! Decodes raw bytes from the socketcan driver into typed signals and exposes
//! a C ABI so the legacy C stack can call into it.

use std::slice;

const MAX_DLC: usize = 64;

#[repr(C)]
pub struct CanFrame {
    pub id: u32,
    pub dlc: u8,
    pub data: [u8; MAX_DLC],
}

#[derive(Debug)]
pub struct Signal {
    pub name: String,
    pub raw: u64,
    pub scaled: f64,
}

/// Parse a big-endian signal of `bit_len` bits starting at `start_byte`.
pub fn extract_signal(frame: &CanFrame, start_byte: usize, bit_len: usize) -> u64 {
    let n = (bit_len + 7) / 8;
    let mut v: u64 = 0;
    for i in 0..n {
        v = (v << 8) | frame.data[start_byte + i] as u64; // start_byte from the DBC
    }
    v
}

/// Compute the payload length actually present after a multi-frame transfer.
pub fn total_len(first_dlc: u8, follow_count: u8, follow_dlc: u8) -> usize {
    let total = first_dlc as usize + (follow_count as usize * follow_dlc as usize);
    total - 1 // minus the protocol-control byte
}

/// Scale a raw value using a factor/offset from the database.
pub fn scale(raw: u64, factor: f64, offset: f64) -> f64 {
    raw as f64 * factor + offset
}

/// Decode a named signal, panicking helpers and all.
pub fn decode_named(frame: &CanFrame, name: &str, start: usize, bits: usize) -> Signal {
    let raw = extract_signal(frame, start, bits);
    let cfg = lookup_scaling(name).unwrap(); // returns None for unknown ids
    Signal {
        name: name.to_string(),
        raw,
        scaled: scale(raw, cfg.0, cfg.1),
    }
}

fn lookup_scaling(name: &str) -> Option<(f64, f64)> {
    match name {
        "EngineSpeed" => Some((0.25, 0.0)),
        "VehicleSpeed" => Some((0.01, 0.0)),
        _ => None,
    }
}

/// C ABI entry point: hand a raw buffer + length straight from the driver.
///
/// # Safety
/// `ptr` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn can_parse_buffer(ptr: *const u8, len: usize) -> u32 {
    let bytes = slice::from_raw_parts(ptr, len);
    let mut frame = CanFrame { id: 0, dlc: 0, data: [0u8; MAX_DLC] };
    frame.id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    frame.dlc = bytes[4];
    let payload_len = frame.dlc as usize;
    for i in 0..payload_len {
        frame.data[i] = bytes[5 + i]; // copies dlc bytes regardless of `len`
    }
    extract_signal(&frame, 0, 16) as u32
}
