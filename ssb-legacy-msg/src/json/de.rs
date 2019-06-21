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

/// Everything that can go wrong when decoding a `Message` from legacy json.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeJsonError {
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
    Content(json::DecodeJsonError),
}

impl From<json::DecodeJsonError> for DecodeJsonError {
    fn from(e: json::DecodeJsonError) -> DecodeJsonError {
        DecodeJsonError::Content(e)
    }
}

impl From<multihash::DecodeLegacyError> for DecodeJsonError {
    fn from(e: multihash::DecodeLegacyError) -> DecodeJsonError {
        DecodeJsonError::InvalidPrevious(e)
    }
}

impl From<multikey::DecodeLegacyError> for DecodeJsonError {
    fn from(e: multikey::DecodeLegacyError) -> DecodeJsonError {
        DecodeJsonError::InvalidAuthor(e)
    }
}

impl From<multibox::DecodeLegacyError> for DecodeJsonError {
    fn from(e: multibox::DecodeLegacyError) -> DecodeJsonError {
        DecodeJsonError::InvalidPrivateContent(e)
    }
}

impl From<DecodeSignatureError> for DecodeJsonError {
    fn from(e: DecodeSignatureError) -> DecodeJsonError {
        DecodeJsonError::InvalidSignature(e)
    }
}

/// Try to parse data from the input, returning the remaining input when done.
pub fn from_legacy<'de, T>(input: &'de [u8]) -> Result<(Message<T>, &'de [u8]), DecodeJsonError>
    where T: DeserializeOwned
{
    let mut dec = MsgJsonDes::from_slice(input);

    let previous: Option<Multihash>;

    dec.expect_ws(0x7B, DecodeJsonError::Syntax)?; // `{`
    dec.key("previous", DecodeJsonError::ExpectedPrevious)?;

    match dec.peek_ws()? {
        0x6E => {
            // `n`
            dec.expect_bytes(b"null", DecodeJsonError::ExpectedNull)?;
            previous = None;
        }
        _ => {
            dec.expect(0x22, DecodeJsonError::ExpectedPrevious)?;
            let (tmp, tail) = Multihash::from_legacy(dec.input)?;
            dec.input = tail;
            previous = Some(tmp);
            dec.expect(0x22, DecodeJsonError::Syntax)?;
        }
    }

    let author: Multikey;
    let sequence: u64;
    let swapped: bool;

    dec.expect_ws(0x2C, DecodeJsonError::Syntax)?; // `,`
    dec.expect_ws(0x22, DecodeJsonError::Syntax)?; // `"`
    match dec.peek()? {
        0x61 => {
            // `a`
            dec.expect_bytes(b"author\"", DecodeJsonError::ExpectedAuthor)?;
            dec.expect_ws(0x3A, DecodeJsonError::Syntax)?; // `:`
            dec.expect_ws(0x22, DecodeJsonError::Syntax)?;
            let (tmp, tail) = Multikey::from_legacy(dec.input)?;
            dec.input = tail;
            author = tmp;
            dec.expect(0x22, DecodeJsonError::Syntax)?; // `"`

            dec.entry("sequence", DecodeJsonError::ExpectedSequence)?;
            let seq_tmp: f64 = dec.parse_number()?;
            if seq_tmp.is_sign_negative() || seq_tmp > 9007199254740992.0 {
                return Err(DecodeJsonError::OutOfBoundsSequence);
            } else {
                sequence = seq_tmp as u64;
            }

            swapped = false;
        }

        0x73 => {
            // `s`
            dec.expect_bytes(b"sequence\"", DecodeJsonError::ExpectedSequence)?;
            dec.expect_ws(0x3A, DecodeJsonError::Syntax)?; // `:`
            let _ = dec.peek_ws()?;
            let seq_tmp: f64 = dec.parse_number()?;
            if seq_tmp.is_sign_negative() || seq_tmp > 9007199254740992.0 {
                return Err(DecodeJsonError::OutOfBoundsSequence);
            } else {
                sequence = seq_tmp as u64;
            }

            dec.entry("author", DecodeJsonError::ExpectedAuthor)?;
            dec.expect(0x22, DecodeJsonError::Syntax)?;
            let (tmp, tail) = Multikey::from_legacy(dec.input)?;
            dec.input = tail;
            author = tmp;
            dec.expect(0x22, DecodeJsonError::Syntax)?; // `"`

            swapped = true;
        }

        _ => return Err(DecodeJsonError::ExpectedAuthorOrSequence),
    }

    dec.entry("timestamp", DecodeJsonError::ExpectedTimestamp)?;
    let timestamp = unsafe { LegacyF64::from_f64_unchecked(dec.parse_number()?) };

    dec.entry("hash", DecodeJsonError::ExpectedHash)?;
    dec.expect_bytes(b"\"sha256\"", DecodeJsonError::InvalidHash)?;

    let content: Content<T>;
    dec.entry("content", DecodeJsonError::ExpectedContent)?;

    match dec.peek_ws()? {
        0x22 => {
            // `"`
            dec.advance(1);
            let (tmp, tail) = Multibox::from_legacy(dec.input)?;
            dec.input = tail;
            content = Content::Encrypted(tmp);
            dec.expect(0x22, DecodeJsonError::Syntax)?; // `"`
        }

        _ => {
            let (tmp, remaining_input) = json::from_slice_partial(dec.input)?;
            dec.input = remaining_input;
            content = Content::Plain(tmp);
        }
    }

    let signature;
    dec.entry("signature", DecodeJsonError::ExpectedSignature)?;
    dec.expect(0x22, DecodeJsonError::Syntax)?;
    let (tmp_sig, tail) = author.sig_from_legacy(dec.input)?;
    dec.input = tail;
    signature = tmp_sig;
    dec.expect(0x22, DecodeJsonError::Syntax)?; // `"`

    dec.expect_ws(0x7D, DecodeJsonError::Syntax)?; // `}`
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
        dec.input))
}

// A structure that deserializes json encoded legacy messages.
struct MsgJsonDes<'de> {
    input: &'de [u8],
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
        MsgJsonDes { input }
    }

    // Advance the input slice by some number of bytes.
    fn advance(&mut self, offset: usize) {
        self.input = &self.input[offset..];
    }

    // Consumes the next byte and returns it.
    fn next(&mut self) -> Result<u8, DecodeJsonError> {
        match self.input.split_first() {
            Some((head, tail)) => {
                self.input = tail;
                Ok(*head)
            }
            None => Err(DecodeJsonError::UnexpectedEndOfInput),
        }
    }

    // Consumes the expected byte, gives the given error if it is something else
    fn expect(&mut self, expected: u8, err: DecodeJsonError) -> Result<(), DecodeJsonError> {
        if self.next()? == expected {
            Ok(())
        } else {
            Err(err)
        }
    }

    // Same as expect, but using a predicate.
    fn expect_pred(&mut self,
                   pred: fn(u8) -> bool,
                   err: DecodeJsonError)
                   -> Result<(), DecodeJsonError> {
        if pred(self.next()?) { Ok(()) } else { Err(err) }
    }

    // Returns the next byte without consuming it.
    fn peek(&self) -> Result<u8, DecodeJsonError> {
        match self.input.first() {
            Some(byte) => Ok(*byte),
            None => Err(DecodeJsonError::UnexpectedEndOfInput),
        }
    }

    // Returns the next byte without consuming it, or signals end of input as `None`.
    fn peek_or_end(&self) -> Option<u8> {
        self.input.first().map(|b| *b)
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

    fn expect_ws(&mut self, exp: u8, err: DecodeJsonError) -> Result<(), DecodeJsonError> {
        self.skip_ws();
        self.expect(exp, err)
    }

    fn expect_bytes(&mut self, exp: &[u8], err: DecodeJsonError) -> Result<(), DecodeJsonError> {
        if self.input.starts_with(exp) {
            self.input = &self.input[exp.len()..];
            Ok(())
        } else {
            Err(err)
        }
    }

    fn key(&mut self, key: &str, err: DecodeJsonError) -> Result<(), DecodeJsonError> {
        self.expect_ws(0x22, err.clone())?;
        self.expect_bytes(key.as_bytes(), err.clone())?;
        self.expect_ws(0x22, err.clone())?;
        self.expect_ws(0x3A, err)?;
        Ok(self.skip_ws())
    }

    fn comma(&mut self, err: DecodeJsonError) -> Result<(), DecodeJsonError> {
        self.expect_ws(0x2C, err)
    }

    fn entry(&mut self, key: &str, err: DecodeJsonError) -> Result<(), DecodeJsonError> {
        self.comma(err.clone())?;
        self.key(key, err)
    }

    fn parse_number(&mut self) -> Result<f64, DecodeJsonError> {
        let original_input = self.input;

        // trailing `-`
        match self.peek() {
            Ok(0x2D) => self.advance(1),
            Ok(_) => {}
            Err(_) => return Err(DecodeJsonError::ExpectedNumber),
        }

        let next = self.next()?;
        match next {
            // first digit `0` must be followed by `.`
            0x30 => {}
            // first digit nonzero, may be followed by more digits until the `.`
            0x31...0x39 => self.skip(is_digit),
            _ => return Err(DecodeJsonError::ExpectedNumber),
        }

        // `.`, followed by many1 digits
        if let Some(0x2E) = self.peek_or_end() {
            self.advance(1);
            self.expect_pred(is_digit, DecodeJsonError::Digit)?;
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
                self.expect_pred(is_digit, DecodeJsonError::Digit)?;
                self.skip(is_digit);
            }
            _ => {}
        }

        // done parsing the number, convert it to a rust value
        let f = strtod(unsafe {
                         std::str::from_utf8_unchecked(&original_input[..(original_input.len() -
                                                           self.input.len())])
                     }).unwrap(); // We already checked that the input is a valid number

        if LegacyF64::is_valid(f) {
            Ok(f)
        } else {
            Err(DecodeJsonError::InvalidNumber)
        }
    }
}
