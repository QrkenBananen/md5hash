#![no_std]
#![warn(
    missing_docs,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts
)]
#![deny(unsafe_code)]

//! This crate provides no_std compatible MD5 hashing without dependencies, written in safe Rust.
//!
//! The crate consists of a [`MD5Hasher`] type which takes in data using the [digest] method and then hashes it using
//! the MD5 algorithm. Once all the data has been "digested" using the [digest] method the [finish] method returns a [`MD5Digest`] type representing
//! the result of the hash.
//!
//! ## Examples
//!
//! A MD5Hasher instance can be created and [digest] can be called repeatedly for disjointed slices.
//! ```
//! use md5hash::MD5Hasher;
//!
//! let mut hasher = MD5Hasher::new();
//! hasher.digest(&"message");
//! hasher.digest(&" ");
//! hasher.digest(&"digest");           // f96b697d7cb7938d525a2f31aaf161d0
//! assert_eq!(hasher.finish().as_ref(), &[0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,
//!                                        0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0]);
//! ```
//!
//! Or the [hash] function can be used as a convenience function to hash a single slice.
//! ```
//! use md5hash::MD5Hasher;
//!
//! assert_eq!(MD5Hasher::hash(&"message digest").as_ref(), // f96b697d7cb7938d525a2f31aaf161d0
//!     &[0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,
//!       0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0]);
//! ```
//!
//! ## Security
//! MD5 is a broken hashing algorithm, and should not be used for anything that requires any kind of security.
//! It is also not recommended to be used for new systems even if security is not a concern.
//! Instead this hash should only be used for situations that requires specifically MD5, such as legacy systems.
//!
//! [finish]: MD5Hasher::finish
//! [digest]: MD5Hasher::digest
//! [hash]: MD5Hasher::hash

use core::fmt;

const PADDING: [u8; 64] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

/// The main hashing type.
///
/// It takes in a slice of [u8] bytes or any type that implements [AsRef] for a slice of [u8], using the [digest] method.
/// When all data has been inputted using the [digest] method the [finish] method returns the final hash result as a [`MD5Digest`] type.
///
/// Alternatively the [hash] function can be used as convenient way to hash a single slice.
///
/// [finish]: MD5Hasher::finish
/// [digest]: MD5Hasher::digest
/// [hash]: MD5Hasher::hash
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MD5Hasher {
    message_len: u64,
    state: [u32; 4],
    buffer: [u8; 64],
}

impl MD5Hasher {
    /// Creates a new [`MD5Hasher`] instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            message_len: 0,
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0; 64],
        }
    }

    /// Reads the input slice of bytes and hashes them once there is enough bytes.
    ///
    /// The bytes are copied into a buffer in chunks of 64 bytes, and is then hashed.
    /// If there is not 64 bytes available the copied bytes are kept until they can be hashed.
    #[inline(always)]
    pub fn digest(&mut self, bytes: &impl AsRef<[u8]>) {
        self.digest_inner(bytes.as_ref());
    }

    /// Runs the final hashing and returns the result as a [`MD5Digest`] instance.
    pub fn finish(mut self) -> MD5Digest {
        self.pad_buffer();
        self.append_length();
        self.hash_buffer();

        self.buffer.zero();

        let mut buf = [0u8; 16];
        buf.iter_mut()
            .zip(self.state.iter().flat_map(|s| s.to_le_bytes()))
            .for_each(|(buf, state)| {
                *buf = state;
            });
        MD5Digest { buf }
    }

    /// Hashes the slice and returns the result as a [`MD5Digest`].
    ///
    /// This is a convenience function equivalent to creating a MD5Hasher, calling [MD5Hasher::digest] once, then calling [MD5Hasher::finish].
    pub fn hash(bytes: &impl AsRef<[u8]>) -> MD5Digest {
        let mut hasher = MD5Hasher::new();
        hasher.digest(bytes);
        hasher.finish()
    }

    #[inline(always)]
    /// Returns how many bytes of the internal buffer has been filled.
    ///
    /// This method assumes that the buffer filled length is always related to the original message length.
    const fn buffer_fill_len(&self) -> usize {
        (self.message_len % 64) as usize
    }

    #[allow(unused_assignments)]
    #[inline(always)]
    fn hash_buffer(&mut self) {
        let mut x = U8ToU32Converter::new(&self.buffer)
            .next()
            .expect("Internal buffer always contains 64 bytes.");
        digest_buffer(x, &mut self.state);

        x.zero();
    }

    #[inline(always)]
    fn pad_buffer(&mut self) {
        match self.buffer_fill_len() {
            i @ 0..=55 => {
                self.buffer[i..56].copy_from_slice(&PADDING[..(64 - 8 - i)]);
            }

            i @ _ => {
                self.buffer[i..64].copy_from_slice(&PADDING[..(64 - i)]);
                self.hash_buffer();
                self.buffer[..56].copy_from_slice(&PADDING[1..57]);
            }
        }
    }

    #[inline(always)]
    fn append_length(&mut self) {
        self.buffer[56..].copy_from_slice(&(self.message_len << 3).to_le_bytes());
    }

    #[inline(always)]
    fn digest_inner(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let len = self.buffer_fill_len();
            if bytes.len() >= 64 && len % 64 == 0 {
                let tmp_buffer_len = bytes.len() - (bytes.len() % 64);
                let converter = U8ToU32Converter::new(&bytes[..tmp_buffer_len]);
                for buf in converter {
                    digest_buffer(buf, &mut self.state);
                }
                self.message_len = self.message_len.wrapping_add(tmp_buffer_len as u64);
                bytes = &bytes[tmp_buffer_len..];
            } else {
                let min = core::cmp::min(64 - len, bytes.len());
                self.buffer[len..(len + min)].copy_from_slice(&bytes[..min]);

                self.message_len = self.message_len.wrapping_add(min as u64);

                if self.buffer_fill_len() == 0 {
                    self.hash_buffer();
                }
                bytes = &bytes[min..];
            }
        }
    }
}

impl Default for MD5Hasher {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn digest_buffer(x: [u32; 16], state: &mut [u32; 4]) {
    let [mut a, mut b, mut c, mut d] = state;

    // Round 1
    const S11: u32 = 7;
    const S12: u32 = 12;
    const S13: u32 = 17;
    const S14: u32 = 22;

    ff(&mut a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
    ff(&mut d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
    ff(&mut c, d, a, b, x[2], S13, 0x242070db); /* 3 */
    ff(&mut b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
    ff(&mut a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
    ff(&mut d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
    ff(&mut c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
    ff(&mut b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
    ff(&mut a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
    ff(&mut d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
    ff(&mut c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    ff(&mut b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    ff(&mut a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    ff(&mut d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    ff(&mut c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    ff(&mut b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    // Round 2
    const S21: u32 = 5;
    const S22: u32 = 9;
    const S23: u32 = 14;
    const S24: u32 = 20;

    gg(&mut a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
    gg(&mut d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
    gg(&mut c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    gg(&mut b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
    gg(&mut a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
    gg(&mut d, a, b, c, x[10], S22, 0x2441453); /* 22 */
    gg(&mut c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    gg(&mut b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
    gg(&mut a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
    gg(&mut d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    gg(&mut c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
    gg(&mut b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
    gg(&mut a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    gg(&mut d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
    gg(&mut c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
    gg(&mut b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    // Round 3
    const S31: u32 = 4;
    const S32: u32 = 11;
    const S33: u32 = 16;
    const S34: u32 = 23;

    hh(&mut a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
    hh(&mut d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
    hh(&mut c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    hh(&mut b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    hh(&mut a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
    hh(&mut d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
    hh(&mut c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
    hh(&mut b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    hh(&mut a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    hh(&mut d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
    hh(&mut c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
    hh(&mut b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
    hh(&mut a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
    hh(&mut d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    hh(&mut c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    hh(&mut b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

    // Round 4
    const S41: u32 = 6;
    const S42: u32 = 10;
    const S43: u32 = 15;
    const S44: u32 = 21;

    ii(&mut a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
    ii(&mut d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
    ii(&mut c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    ii(&mut b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
    ii(&mut a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    ii(&mut d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
    ii(&mut c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    ii(&mut b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
    ii(&mut a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
    ii(&mut d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    ii(&mut c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
    ii(&mut b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    ii(&mut a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
    ii(&mut d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    ii(&mut c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
    ii(&mut b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline(always)]
fn rotate(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

#[inline(always)]
fn f(x: u32, y: u32, z: u32) -> u32 {
    // Alternative F function from https://www.zorinaq.com/papers/md5-amd64.html
    ((y ^ z) & x) ^ z
}

#[inline(always)]
fn ff(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) {
    *a = b.wrapping_add(rotate(
        a.wrapping_add(f(b, c, d)).wrapping_add(k).wrapping_add(i),
        s,
    ))
}

#[inline(always)]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & (!z))
}

#[inline(always)]
fn gg(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) {
    *a = b.wrapping_add(rotate(
        a.wrapping_add(g(b, c, d)).wrapping_add(k).wrapping_add(i),
        s,
    ))
}

#[inline(always)]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn hh(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) {
    *a = b.wrapping_add(rotate(
        a.wrapping_add(h(b, c, d)).wrapping_add(k).wrapping_add(i),
        s,
    ))
}

#[inline(always)]
fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | (!z))
}

#[inline(always)]
fn ii(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32, iv: u32) {
    *a = b.wrapping_add(rotate(
        a.wrapping_add(i(b, c, d)).wrapping_add(k).wrapping_add(iv),
        s,
    ))
}

struct U8ToU32Converter<'a> {
    bytes: &'a [u8],
}

impl<'a> U8ToU32Converter<'a> {
    #[inline(always)]
    fn new(bytes: &'a [u8]) -> Self {
        assert!(bytes.len() % 64 == 0);
        Self { bytes: bytes }
    }
}

impl<'a> Iterator for U8ToU32Converter<'a> {
    type Item = [u32; 16];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        assert!(self.bytes.len() % 64 == 0);
        if self.bytes.len() >= 64 {
            let mut x = [0u32; 16];
            x.iter_mut()
                .zip(self.bytes.chunks_exact(4))
                .for_each(|(x_inner, buffer_chunk)| {
                    *x_inner = u32::from_le_bytes([
                        buffer_chunk[0],
                        buffer_chunk[1],
                        buffer_chunk[2],
                        buffer_chunk[3],
                    ]);
                });
            self.bytes = &self.bytes[64..];
            Some(x)
        } else {
            None
        }
    }
}

/// The hash result given by the [`MD5Hasher`] type after calling the [finish] method.
///
/// This type can be turned into a `[u8; 16]` using the [`From`] trait, or can be turned into a
/// `&[u8]` using the [`AsRef`] trait.
///
/// [finish]: MD5Hasher::finish
/// [digest]: MD5Hasher::digest
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MD5Digest {
    buf: [u8; 16],
}

impl fmt::Debug for MD5Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::LowerHex for MD5Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in &self.buf {
            write!(f, "{:02x}", i)?
        }
        Ok(())
    }
}

impl fmt::UpperHex for MD5Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in &self.buf {
            write!(f, "{:02X}", i)?
        }
        Ok(())
    }
}

impl AsRef<[u8]> for MD5Digest {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl From<MD5Digest> for [u8; 16] {
    fn from(value: MD5Digest) -> Self {
        value.buf
    }
}

trait ZeroBuffer {
    fn zero(&mut self);
}

macro_rules! zerobuffer {
    ($int:ty) => {
        impl<const N: usize> ZeroBuffer for [$int; N] {
            fn zero(&mut self) {
                *self = [0; N];
            }
        }
    };
}

zerobuffer!(u8);
zerobuffer!(u32);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let inputs = [
            "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        ];

        let results = [
            [
                212u8, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126,
            ], // d41d8cd98f00b204e9800998ecf8427e
            [
                12, 193, 117, 185, 192, 241, 182, 168, 49, 195, 153, 226, 105, 119, 38, 97,
            ], // 0cc175b9c0f1b6a831c399e269772661
            [
                144, 1, 80, 152, 60, 210, 79, 176, 214, 150, 63, 125, 40, 225, 127, 114,
            ], // 900150983cd24fb0d6963f7d28e17f72
            [
                249, 107, 105, 125, 124, 183, 147, 141, 82, 90, 47, 49, 170, 241, 97, 208,
            ], // f96b697d7cb7938d525a2f31aaf161d0
            [
                195, 252, 211, 215, 97, 146, 228, 0, 125, 251, 73, 108, 202, 103, 225, 59,
            ], // c3fcd3d76192e4007dfb496cca67e13b
            [
                209, 116, 171, 152, 210, 119, 217, 245, 165, 97, 28, 44, 159, 65, 157, 159,
            ], // d174ab98d277d9f5a5611c2c9f419d9f
            [
                87, 237, 244, 162, 43, 227, 201, 85, 172, 73, 218, 46, 33, 7, 182, 122,
            ], // 57edf4a22be3c955ac49da2e2107b67a
        ];

        inputs.iter().zip(results).for_each(|(i, r)| {
            let mut hasher = MD5Hasher::new();
            hasher.digest(i);
            assert_eq!(hasher.finish().as_ref(), r);
        });
    }
}
