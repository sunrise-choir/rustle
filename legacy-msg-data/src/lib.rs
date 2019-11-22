//! This crate implements the ssb
//! [legacy data format](https://spec.scuttlebutt.nz/datamodel.html),
//! i.e. the free-form data that forms the content of legacy messages.
//!
//! Two encodings are implemented: the
//! [signing encoding](https://spec.scuttlebutt.nz/datamodel.html#signing-encoding), and the
//! [json transport encoding](https://spec.scuttlebutt.nz/datamodel.html#json-transport-encoding).
#![warn(missing_docs)]

extern crate encode_unicode;
extern crate indexmap;
extern crate ryu_ecmascript;
extern crate serde;
extern crate strtod;
#[macro_use]
extern crate serde_derive;
extern crate base64;

pub mod json;
pub mod value;

use std::cmp::Ordering;
use std::fmt;

/// A wrapper around `f64` to indicate that the float is compatible with the ssb legacy message
/// data model, i.e. it is [neither an infinity, nor `-0.0`, nor a `NaN`](https://spec.scuttlebutt.nz/datamodel.html#floats).
///
/// Because a `LegacyF64` is never `NaN`, it can implement `Eq` and `Ord`, which regular `f64`
/// can not.
///
/// To obtain the inner value, use the `From<LegacyF64> for f64` impl.
#[derive(Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
pub struct LegacyF64(f64);

impl LegacyF64 {
    /// Safe conversion of an arbitrary `f64` into a `LegacyF64`.
    ///
    /// ```
    /// use ssb_legacy_msg_data::LegacyF64;
    ///
    /// assert!(LegacyF64::from_f64(0.0).is_some());
    /// assert!(LegacyF64::from_f64(-1.1).is_some());
    /// assert!(LegacyF64::from_f64(-0.0).is_none());
    /// assert!(LegacyF64::from_f64(std::f64::INFINITY).is_none());
    /// assert!(LegacyF64::from_f64(std::f64::NEG_INFINITY).is_none());
    /// assert!(LegacyF64::from_f64(std::f64::NAN).is_none());
    /// ```
    pub fn from_f64(f: f64) -> Option<LegacyF64> {
        if LegacyF64::is_valid(f) {
            Some(LegacyF64(f))
        } else {
            None
        }
    }

    /// Wraps the given `f64` as a `LegacyF64` without checking if it is valid.
    ///
    /// When the `debug_assertions` feature is enabled (when compiling without optimizations),
    /// this function panics when given an invalid `f64`.
    ///
    /// # Safety
    /// You must not pass infinity, negative infinity, negative zero or a `NaN` to this
    /// function. Any method on the resulting `LegacyF64` could panic or exhibit undefined
    /// behavior.
    ///
    /// ```
    /// use ssb_legacy_msg_data::LegacyF64;
    ///
    /// let fine = unsafe { LegacyF64::from_f64_unchecked(1.1) };
    ///
    /// // Never do this:
    /// // let everything_is_terrible = unsafe { LegacyF64::from_f64_unchecked(-0.0) };
    /// ```
    pub unsafe fn from_f64_unchecked(f: f64) -> LegacyF64 {
        debug_assert!(LegacyF64::is_valid(f));
        LegacyF64(f)
    }

    /// Checks whether a given `f64`
    /// [may be used](https://spec.scuttlebutt.nz/datamodel.html#floats) as a `LegacyF64`.
    pub fn is_valid(f: f64) -> bool {
        if f == 0.0 {
            f.is_sign_positive()
        } else {
            f.is_finite() && (f != 0.0)
        }
    }
}

impl fmt::Display for LegacyF64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
}

impl fmt::Debug for LegacyF64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
}

impl Eq for LegacyF64 {}

impl Ord for LegacyF64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl From<LegacyF64> for f64 {
    fn from(f: LegacyF64) -> Self {
        f.0
    }
}

/// Checks whether a given `u64` is allowed for usage in ssb data (it is
/// not larger than 2^53).
pub fn is_u64_valid(n: u64) -> bool {
    n < 9007199254740992
}

/// Checks whether a given `i64` is allowed for usage in ssb data (its
/// absolute value is not larger than 2^53).
pub fn is_i64_valid(n: i64) -> bool {
    n < 9007199254740992 && n > -9007199254740992
}

/// An iterator that yields the
/// [bytes](https://spec.scuttlebutt.nz/datamodel.html#legacy-hash-computation) needed to compute
/// a hash of some legacy data.
///
/// Created by [`to_weird_encoding`](to_weird_encoding).
///
/// The total number of bytes yielded by this is also the
/// [length](https://spec.scuttlebutt.nz/datamodel.html#legacy-length-computation) of the data.
pub struct WeirdEncodingIterator<'a>(std::iter::Map<std::str::EncodeUtf16<'a>, fn(u16) -> u8>);

impl<'a> Iterator for WeirdEncodingIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// Create an owned representation of the
/// [weird encoding](https://spec.scuttlebutt.nz/datamodel.html#legacy-hash-computation)
/// used for hash computation of legacy ssb messages. The number of bytes yielded by this
/// iterator coincides with the
/// [length](https://spec.scuttlebutt.nz/datamodel.html#legacy-length-computation)
/// of the data.
pub fn to_weird_encoding<'a>(s: &'a str) -> WeirdEncodingIterator<'a> {
    WeirdEncodingIterator(s.encode_utf16().map(|x| x as u8))
}

/// Compute the [length](https://spec.scuttlebutt.nz/datamodel.html#legacy-length-computation)
/// of some data. Note that this takes time linear in the length of the data,
/// so you might want to use a [`WeirdEncodingIterator`](WeirdEncodingIterator)
/// for computing hash and length in one go.
pub fn legacy_length(s: &str) -> usize {
    let mut len = 0;
    for c in s.chars() {
        if c as u32 <= 0xFFFF {
            len += 1;
        } else {
            len += 2;
        }
    }
    len
}
