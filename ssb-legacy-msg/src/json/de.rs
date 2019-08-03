use std::slice::SliceIndex;
use serde::de::DeserializeOwned;
use strtod::strtod;

use ssb_legacy_msg_data::{
    LegacyF64,
};
use ssb_multiformats::{
    multihash::{Multihash, self},
    multikey::{Multikey, self, DecodeSignatureError},
    multibox::{Multibox, self}
};
use ssb_legacy_msg_data::json;

use super::super::{Message, Content};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct DecodeJsonError {
    pub code: ErrorCode,
    pub position: usize,
}

/// Everything that can go wrong when decoding a `Message` from legacy json.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// Needed more data but got EOF instead.
    UnexpectedEndOfInput,
    /// Expected a decimal digit.
    Digit,
    /// A generic syntax error. Any valid json would have been ok, but alas...
    Syntax,
    /// A number is valid json but it evaluates to -0 or an infinity
    InvalidNumber,
    ExpectedNumber,
    ExpectedNull,
    /// First metadata entry must be "previous".
    ExpectedPrevious,
    InvalidPrevious(multihash::DecodeLegacyError),
    ExpectedAuthorOrSequence,
    ExpectedAuthor,
    InvalidAuthor(multikey::DecodeLegacyError),
    ExpectedSequence,
    OutOfBoundsSequence,
    ExpectedTimestamp,
    ExpectedHash,
    InvalidHash,
    ExpectedContent,
    InvalidPrivateContent(multibox::DecodeLegacyError),
    ExpectedSignature,
    InvalidSignature(DecodeSignatureError),
    Content(json::ErrorCode),
}

// TODO: From<tuple> is ugly
impl From<(json::DecodeJsonError, usize)> for DecodeJsonError {
    fn from((e, pos): (json::DecodeJsonError, usize)) -> DecodeJsonError {
        DecodeJsonError {
            code: ErrorCode::Content(e.code),
            position: pos + e.position
        }
    }
}

impl From<(multihash::DecodeLegacyError, usize)> for DecodeJsonError {
    fn from((e, pos): (multihash::DecodeLegacyError, usize)) -> DecodeJsonError {
        DecodeJsonError {
            code: ErrorCode::InvalidPrevious(e),
            position: pos,
        }
    }
}

impl From<(multikey::DecodeLegacyError, usize)> for DecodeJsonError {
    fn from((e, pos): (multikey::DecodeLegacyError, usize)) -> DecodeJsonError {
        DecodeJsonError {
            code: ErrorCode::InvalidAuthor(e),
            position: pos,
        }
    }
}

impl From<(multibox::DecodeLegacyError, usize)> for DecodeJsonError {
    fn from((e, pos): (multibox::DecodeLegacyError, usize)) -> DecodeJsonError {
        DecodeJsonError {
            code: ErrorCode::InvalidPrivateContent(e),
            position: pos,
        }
    }
}

impl From<(DecodeSignatureError, usize)> for DecodeJsonError {
    fn from((e, pos): (DecodeSignatureError, usize)) -> DecodeJsonError {
        DecodeJsonError {
            code: ErrorCode::InvalidSignature(e),
            position: pos,
        }
    }
}

/// Try to parse data from the input, returning the remaining input when done.
pub fn from_legacy<'de, T>(input: &'de [u8]) -> Result<(Message<T>, &'de [u8]), DecodeJsonError>
    where T: DeserializeOwned
{
    let mut dec = MsgJsonDes::from_slice(input);

    let previous: Option<Multihash>;

    dec.expect_ws(0x7B, ErrorCode::Syntax)?; // `{`
    dec.key("previous", ErrorCode::ExpectedPrevious)?;

    match dec.peek_ws()? {
        0x6E => {
            // `n`
            dec.expect_bytes(b"null", ErrorCode::ExpectedNull)?;
            previous = None;
        }
        _ => {
            dec.expect(0x22, ErrorCode::ExpectedPrevious)?;
            previous = Some(dec.parse_chunk(Multihash::from_legacy)?);
            dec.expect(0x22, ErrorCode::Syntax)?;
        }
    }

    let author: Multikey;
    let sequence: u64;
    let swapped: bool;

    dec.expect_ws(0x2C, ErrorCode::Syntax)?; // `,`
    dec.expect_ws(0x22, ErrorCode::Syntax)?; // `"`
    match dec.peek()? {
        0x61 => {
            // `a`
            dec.expect_bytes(b"author\"", ErrorCode::ExpectedAuthor)?;
            dec.expect_ws(0x3A, ErrorCode::Syntax)?; // `:`
            dec.expect_ws(0x22, ErrorCode::Syntax)?;

            author = dec.parse_chunk(Multikey::from_legacy)?;
            dec.expect(0x22, ErrorCode::Syntax)?; // `"`

            dec.entry("sequence", ErrorCode::ExpectedSequence)?;
            let pos = dec.position();
            let seq_tmp: f64 = dec.parse_number()?;
            if seq_tmp.is_sign_negative() || seq_tmp > 9007199254740992.0 {
                return dec.fail_at_position(ErrorCode::OutOfBoundsSequence, pos);
            } else {
                sequence = seq_tmp as u64;
            }

            swapped = false;
        }

        0x73 => {
            // `s`
            dec.expect_bytes(b"sequence\"", ErrorCode::ExpectedSequence)?;
            dec.expect_ws(0x3A, ErrorCode::Syntax)?; // `:`
            let _ = dec.peek_ws()?;
            let pos = dec.position();
            let seq_tmp: f64 = dec.parse_number()?;
            if seq_tmp.is_sign_negative() || seq_tmp > 9007199254740992.0 {
                return dec.fail_at_position(ErrorCode::OutOfBoundsSequence, pos);
            } else {
                sequence = seq_tmp as u64;
            }

            dec.entry("author", ErrorCode::ExpectedAuthor)?;
            dec.expect(0x22, ErrorCode::Syntax)?;
            author = dec.parse_chunk(Multikey::from_legacy)?;
            dec.expect(0x22, ErrorCode::Syntax)?; // `"`

            swapped = true;
        }

        _ => return dec.fail(ErrorCode::ExpectedAuthorOrSequence),
    }

    dec.entry("timestamp", ErrorCode::ExpectedTimestamp)?;
    let timestamp = unsafe { LegacyF64::from_f64_unchecked(dec.parse_number()?) };

    dec.entry("hash", ErrorCode::ExpectedHash)?;
    dec.expect_bytes(b"\"sha256\"", ErrorCode::InvalidHash)?;

    let content: Content<T>;
    dec.entry("content", ErrorCode::ExpectedContent)?;

    match dec.peek_ws()? {
        0x22 => {
            // `"`
            dec.advance(1);
            content = Content::Encrypted(dec.parse_chunk(Multibox::from_legacy)?);
            dec.expect(0x22, ErrorCode::Syntax)?; // `"`
        }

        _ => {
            content = Content::Plain(dec.parse_chunk(json::from_slice_partial)?);
        }
    }

    let signature;
    dec.entry("signature", ErrorCode::ExpectedSignature)?;
    dec.expect(0x22, ErrorCode::Syntax)?;
    signature = dec.parse_chunk(|s| author.sig_from_legacy(s))?;
    dec.expect(0x22, ErrorCode::Syntax)?; // `"`

    dec.expect_ws(0x7D, ErrorCode::Syntax)?; // `}`
    dec.skip(is_ws);

    Ok((Message {
            previous,
            author,
            sequence,
            timestamp,
            content,
            swapped,
            signature,
        },
        dec.rest()))
}

// A structure that deserializes json encoded legacy messages.
struct MsgJsonDes<'de> {
    input: &'de [u8],
    position: usize,
}

fn is_ws(byte: u8) -> bool {
    byte == 0x09 || byte == 0x0A || byte == 0x0D || byte == 0x20
}
fn is_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

impl<'de> MsgJsonDes<'de> {
    // Creates a `MsgJsonDes` from a `&[u8]`.
    fn from_slice(input: &'de [u8]) -> Self {
        MsgJsonDes { input, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn slice<I: SliceIndex<[u8]>>(&self, i: I) -> &'de I::Output {
        &self.input[i]
    }

    pub fn rest(&self) -> &'de [u8] {
        self.slice(self.position..)
    }

    fn fail<T>(&self, code: ErrorCode) -> Result<T, DecodeJsonError> {
        Err(DecodeJsonError {
            code,
            position: self.position(),
        })
    }


    fn fail_at_position<T>(&self, code: ErrorCode, position: usize) -> Result<T, DecodeJsonError> {
        Err(DecodeJsonError {
            code,
            position
        })
    }

    fn parse_chunk<T, E, F>(&mut self, f: F) -> Result<T, (E, usize)>
    where
        // DecodeJsonError: From<E>,
        F: Fn(&[u8]) -> Result<(T, &[u8]), E>
    {
        let start = self.position;
        let remaining = self.rest();
        let (x, tail) = f(remaining).map_err(|e| (e, start))?;
        self.advance(remaining.len() - tail.len());

        Ok(x)
    }

    // Advance the input slice by some number of bytes.
    fn advance(&mut self, offset: usize) {
        self.position += offset;
    }

    // Consumes the next byte and returns it.
    fn next(&mut self) -> Result<u8, DecodeJsonError> {
        if let Some(c) = self.input.get(self.position) {
            self.advance(1);
            Ok(*c)
        } else {
            self.fail(ErrorCode::UnexpectedEndOfInput)
        }
    }

    // Consumes the expected byte, gives the given error if it is something else
    fn expect(&mut self, expected: u8, err: ErrorCode) -> Result<(), DecodeJsonError> {
        let pos = self.position();
        if self.next()? == expected {
            Ok(())
        } else {
            self.fail_at_position(err, pos)
        }
    }

    // Same as expect, but using a predicate.
    fn expect_pred(&mut self,
                   pred: fn(u8) -> bool,
                   err: ErrorCode)
                   -> Result<(), DecodeJsonError> {
        let pos = self.position();
        if pred(self.next()?) { Ok(()) } else { self.fail_at_position(err, pos) }
    }

    // Returns the next byte without consuming it.
    fn peek(&self) -> Result<u8, DecodeJsonError> {
        if let Some(c) = self.input.get(self.position) {
            Ok(*c)
        } else {
            self.fail(ErrorCode::UnexpectedEndOfInput)
        }
    }

    // Returns the next byte without consuming it, or signals end of input as `None`.
    fn peek_or_end(&self) -> Option<u8> {
        self.input.get(self.position).map(|b| *b)
    }

    // Skips values while the predicate returns true.
    fn skip(&mut self, pred: fn(u8) -> bool) -> () {
        loop {
            match self.peek_or_end() {
                None => return,
                Some(peeked) => {
                    if pred(peeked) {
                        self.advance(1);
                    } else {
                        return;
                    }
                }
            }
        }
    }

    fn skip_ws(&mut self) -> () {
        self.skip(is_ws)
    }

    // Consumes as much whitespace as possible, then peeks at the next non-whitespace byte.
    fn peek_ws(&mut self) -> Result<u8, DecodeJsonError> {
        self.skip_ws();
        self.peek()
    }

    fn expect_ws(&mut self, exp: u8, err: ErrorCode) -> Result<(), DecodeJsonError> {
        self.skip_ws();
        self.expect(exp, err)
    }

    fn expect_bytes(&mut self, exp: &[u8], err: ErrorCode) -> Result<(), DecodeJsonError> {
        if self.rest().starts_with(exp) {
            self.advance(exp.len());
            Ok(())
        } else {
            self.fail(err)
        }
    }

    fn key(&mut self, key: &str, err: ErrorCode) -> Result<(), DecodeJsonError> {
        self.expect_ws(0x22, err.clone())?;
        self.expect_bytes(key.as_bytes(), err.clone())?;
        self.expect_ws(0x22, err.clone())?;
        self.expect_ws(0x3A, err)?;
        Ok(self.skip_ws())
    }

    fn comma(&mut self, err: ErrorCode) -> Result<(), DecodeJsonError> {
        self.expect_ws(0x2C, err)
    }

    fn entry(&mut self, key: &str, err: ErrorCode) -> Result<(), DecodeJsonError> {
        self.comma(err.clone())?;
        self.key(key, err)
    }

    fn parse_number(&mut self) -> Result<f64, DecodeJsonError> {
        let start = self.position;

        // trailing `-`
        match self.peek() {
            Ok(0x2D) => self.advance(1),
            Ok(_) => {}
            Err(_) => return self.fail_at_position(ErrorCode::ExpectedNumber, start),
        }

        let next = self.next()?;
        match next {
            // first digit `0` must be followed by `.`
            0x30 => {}
            // first digit nonzero, may be followed by more digits until the `.`
            0x31...0x39 => self.skip(is_digit),
            _ => return self.fail_at_position(ErrorCode::ExpectedNumber, start),
        }

        // `.`, followed by many1 digits
        if let Some(0x2E) = self.peek_or_end() {
            self.advance(1);
            self.expect_pred(is_digit, ErrorCode::Digit)?;
            self.skip(is_digit);
        }

        // `e` or `E`, followed by an optional sign and many1 digits
        match self.peek_or_end() {
            Some(0x45) | Some(0x65) => {
                self.advance(1);

                // optional `+` or `-`
                if self.peek()? == 0x2B || self.peek()? == 0x2D {
                    self.advance(1);
                }

                // many1 digits
                self.expect_pred(is_digit, ErrorCode::Digit)?;
                self.skip(is_digit);
            }
            _ => {}
        }

        // done parsing the number, convert it to a rust value
        let f = strtod(unsafe {
                         std::str::from_utf8_unchecked(self.slice(start..self.position))
                     }).unwrap(); // We already checked that the input is a valid number

        if LegacyF64::is_valid(f) {
            Ok(f)
        } else {
            self.fail_at_position(ErrorCode::InvalidNumber, start)
        }
    }
}
