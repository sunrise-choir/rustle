//! This module implements the json encodings of the legacy ssb data format, both
//! [signing](https://spec.scuttlebutt.nz/datamodel.html#signing-encoding) and
//! [json transport](https://spec.scuttlebutt.nz/datamodel.html#json-transport-encoding).
//!
//! Serialization methods take a boolean to switch between compact json
//! and the signing encoding.

mod de;
mod ser;

pub use self::de::{JsonDeserializer, DecodeJsonError, ErrorCode, from_slice, from_slice_partial};
pub use self::ser::{JsonSerializer, EncodeJsonError, to_writer, to_vec, to_string, to_writer_indent};
