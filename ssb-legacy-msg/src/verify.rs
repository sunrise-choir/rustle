//! Ssb legacy message verification.
//!
//! The `signing_encoding` argument can be obtained by using the `json::to_legacy_vec(&msg, true)`.
use std::io::Write;

use crypto_hash::{Algorithm, Hasher};

use ssb_multiformats::{
    multihash::{Multihash, Target},
    multikey::{Multikey, Multisig},
};
use ssb_legacy_msg_data::{to_weird_encoding, legacy_length};

use super::Message;

/// Compute the hash and length of the given signing encoding in one go.
pub fn hash_and_length(signing_encoding: &str) -> (Multihash, usize) {
    let mut len = 0;

    let mut hasher = Hasher::new(Algorithm::SHA256);
    for b in to_weird_encoding(&signing_encoding) {
        len += 1;
        hasher.write_all(&[b]).unwrap();
    }

    let digest = hasher.finish();
    debug_assert!(digest.len() == 32);
    let mut data = [0; 32];
    for i in 0..32 {
        data[i] = digest[i];
    }

    (Multihash::from_sha256(data, Target::Message), len)
}

/// Compute the hash of the given signing encoding.
pub fn hash(signing_encoding: &str) -> Multihash {
    let mut hasher = Hasher::new(Algorithm::SHA256);
    for b in to_weird_encoding(&signing_encoding) {
        hasher.write_all(&[b]).unwrap();
    }

    let digest = hasher.finish();
    debug_assert!(digest.len() == 32);
    let mut data = [0; 32];
    for i in 0..32 {
        data[i] = digest[i];
    }

    Multihash::from_sha256(data, Target::Message)
}

/// Compute the length of the given signing encoding.
pub fn length(signing_encoding: &str) -> usize {
    legacy_length(signing_encoding)
}

/// Check whether the given message has the correct sequence number compared to the previous
/// message's sequence number. If the message is the first of its feed, call this as
/// `check_sequence(&msg, 0)`.
pub fn check_sequence<T>(msg: &Message<T>, prev_seq: u64) -> bool {
    msg.sequence == prev_seq + 1
}

/// Check whether the given message has the correct `previous` entry with respect to the hash
/// of the previous message (or None if it is the first message of the feed).
pub fn check_previous<T>(msg: &Message<T>, prev_hash: &Option<Multihash>) -> bool {
    msg.previous == *prev_hash
}

/// Check whether a length (as obtained from `length(&signing_encoding)`) is valid.
pub fn check_length(len: usize) -> bool {
    len < 16385
}

/// Check whether the signature signs the signing encoding by the author.
///
/// This is *not* the same as checking the signature against the raw bytes of the signing encoding,
/// first some bytes need to be spliced out.
pub fn check_signature(signing_encoding: &str, author: &Multikey, signature: &Multisig) -> bool {
    let raw = signing_encoding.as_bytes();
    let raw_len = raw.len();
    let mut enc_without_sig = Vec::with_capacity(raw_len - 120); // signature entry + whitespace take up 120 bytes
    enc_without_sig.extend_from_slice(&raw[..raw_len - 121]); // one more bytes for the closing brace
    enc_without_sig.extend_from_slice(b"\n}");
    author.is_signature_correct(&enc_without_sig, signature)
}
