// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Authenticated Encryption with Associated Data (AEAD).
//!
//! See [Authenticated encryption: relations among notions and analysis of the
//! generic composition paradigm][AEAD] for an introduction to the concept of
//! AEADs.
//!
//! C analog: `GFp/aead.h`
//!
//! Go analog: [`crypto.cipher.AEAD`]
//!
//! [AEAD]: http://www-cse.ucsd.edu/~mihir/papers/oem.html
//! [`crypto.cipher.AEAD`]: https://golang.org/pkg/crypto/cipher/#AEAD

use {aes_gcm, chacha20_poly1305, constant_time, error, init, poly1305, polyfill};

pub use self::chacha20_poly1305::CHACHA20_POLY1305;
pub use self::aes_gcm::{AES_128_GCM, AES_256_GCM};

/// TODO: Add Docs and explain plaintext
pub struct OpeningContext<'a> {
    ctx: Context,
    plaintext: &'a mut [u8],
}

impl<'a> OpeningContext<'a> {
    #[inline]
    fn new(key: &OpeningKey, nonce: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(OpeningContext {
            ctx: key.0.init_ctx(nonce)?,
            plaintext: &[],
        })
    }

    #[inline]
    pub fn add_ad(&mut self, ad: &[u8]) -> Result<(), error::Unspecified> {
        self.ctx.as_ref().add_ad()
    }

    pub fn decrypt<'b: 'a>(&mut self, in_out: &'b mut [u8], shift: usize) -> Result<(), error::Unspecified> {
        self.ctx.as_ref().decrypt(in_out, shift)?;
        self.plaintext = in_out[shift..];
        Ok(())
    }

    pub fn finish(self, tag: &[u8]) -> Result<&'a mut [u8], error::Unspecified> {
        let expected_tag: [u8; MAX_TAG_LEN];
        let tag_len = self.ctx.as_ref().get_tag(&expected_tag)?
        constant_time::verify_slices_are_equal(&expected_tag[..tag_len], tag)?

        // The tags match, so we do not need to clear the plaintext.
        let plaintext = self.plaintext;
        self.plaintext = &[];
        Ok(plaintext)
    }
}

impl<'a> Drop for OpeningContext<'a> {
    fn drop(&mut self) {
        // Zero out the plaintext so that it isn't accidentally leaked or used
        // after verification fails. It would be safest if we could check the
        // tag before decrypting, but some `open` implementations interleave
        // authentication with decryption for performance.
        for b in self.plaintext {
            *b = 0;
        }
    }
}

/// A key for authenticating and decrypting (“opening”) AEAD-protected data.
///
/// C analog: `EVP_AEAD_CTX` with direction `evp_aead_open`
///
/// Go analog: [`crypto.cipher.AEAD`]
pub struct OpeningKey(Key);

impl OpeningKey {
    /// Create a new opening key.
    ///
    /// `key_bytes` must be exactly `algorithm.key_len` bytes long.
    ///
    /// C analogs: `EVP_AEAD_CTX_init_with_direction` with direction
    ///            `evp_aead_open`, `EVP_AEAD_CTX_init`.
    ///
    /// Go analog:
    ///   [`crypto.aes.NewCipher`](https://golang.org/pkg/crypto/aes/#NewCipher)
    /// + [`crypto.cipher.NewGCM`](https://golang.org/pkg/crypto/cipher/#NewGCM)
    #[inline]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(OpeningKey(Key::new(algorithm, key_bytes)?))
    }

    /// The key's AEAD algorithm.
    ///
    /// C analog: `EVP_AEAD_CTX.aead`
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.0.algorithm }
}

/// Authenticates and decrypts (“opens”) data in place.
///
/// The input may have a prefix that is `in_prefix_len` bytes long; any such
/// prefix is ignored on input and overwritten on output. The last
/// `key.algorithm().tag_len()` bytes of `ciphertext_and_tag_modified_in_place`
/// must be the tag. The part of `ciphertext_and_tag_modified_in_place` between
/// the prefix and the tag is the input ciphertext.
///
/// When `open_in_place()` returns `Ok(plaintext)`, the decrypted output is
/// `plaintext`, which is
/// `&mut ciphertext_and_tag_modified_in_place[..plaintext.len()]`. That is,
/// the output plaintext overwrites some or all of the prefix and ciphertext.
/// To put it another way, the ciphertext is shifted forward `in_prefix_len`
/// bytes and then decrypted in place. To have the output overwrite the input
/// without shifting, pass 0 as `in_prefix_len`.
///
/// When `open_in_place()` returns `Err(..)`,
/// `ciphertext_and_tag_modified_in_place` may have been overwritten in an
/// unspecified way.
///
/// The shifting feature is useful in the case where multiple packets are
/// being reassembled in place. Consider this example where the peer has sent
/// the message “Split stream reassembled in place” split into three sealed
/// packets:
///
/// ```ascii-art
///                 Packet 1                  Packet 2                 Packet 3
/// Input:  [Header][Ciphertext][Tag][Header][Ciphertext][Tag][Header][Ciphertext][Tag]
///                      |         +--------------+                        |
///               +------+   +-----+    +----------------------------------+
///               v          v          v
/// Output: [Plaintext][Plaintext][Plaintext]
///        “Split stream reassembled in place”
/// ```
///
/// Let's say the header is always 5 bytes (like TLS 1.2) and the tag is always
/// 16 bytes (as for AES-GCM and ChaCha20-Poly1305). Then for this example,
/// `in_prefix_len` would be `5` for the first packet, `(5 + 16) + 5` for the
/// second packet, and `(2 * (5 + 16)) + 5` for the third packet.
///
/// (The input/output buffer is expressed as combination of `in_prefix_len`
/// and `ciphertext_and_tag_modified_in_place` because Rust's type system
/// does not allow us to have two slices, one mutable and one immutable, that
/// reference overlapping memory.)
///
/// C analog: `EVP_AEAD_CTX_open`
///
/// Go analog: [`AEAD.Open`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn open_in_place<'a>(key: &OpeningKey, nonce: &[u8], ad: &[u8],
                         in_prefix_len: usize,
                         ciphertext_and_tag_modified_in_place: &'a mut [u8])
                         -> Result<&'a mut [u8], error::Unspecified> {
    let ctx = OpeningContext::new(key, nonce)?;
    ctx.add_ad(ad)?;

    let in_out_len = ciphertext_and_tag_modified_in_place.len().checked_sub(key.algorithm().tag_len()).ok_or(error::Unspecified)?;
    let (in_out, received_tag) = ciphertext_and_tag_modified_in_place.split_at_mut(in_out_len);

    let plaintext = ctx.decrypt(in_out, in_prefix_len)?;
    ctx.finish(received_tag)?;
    Ok(plaintext)
}

/// TODO: Add Docs
pub struct SealingContext(Context);

impl SealingContext {
    #[inline]
    pub fn new(key: &SealingKey, nonce: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(SealingContext(key.0.init_ctx()?))
    }

    #[inline]
    pub fn add_ad(&mut self, ad: &[u8]) -> Result<(), error::Unspecified> {
        self.0.as_ref().add_ad()
    }

    pub fn encrypt(&mut self, in_out: &mut [u8], shift: usize) -> Result<&[u8], error::Unspecified> {
        self.0.as_ref().encrypt(in_out, shift)?;
        Ok(in_out[shift..])
    }

    pub fn finish(self) -> Result<Tag, error::Unspecified> {
        let mut tag = Tag{[0; MAX_TAG_LEN], 0};
        tag.len = self.0.as_ref().get_tag(&tag.data)?;
        Ok(tag)
    }
}

/// A key for encrypting and signing (“sealing”) data.
///
/// C analog: `EVP_AEAD_CTX` with direction `evp_aead_seal`.
///
/// Go analog: [`AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub struct SealingKey(Key);

impl SealingKey {
    /// C analogs: `EVP_AEAD_CTX_init_with_direction` with direction
    ///            `evp_aead_seal`, `EVP_AEAD_CTX_init`.
    ///
    /// Go analog:
    ///   [`crypto.aes.NewCipher`](https://golang.org/pkg/crypto/aes/#NewCipher)
    /// + [`crypto.cipher.NewGCM`](https://golang.org/pkg/crypto/cipher/#NewGCM)
    #[inline]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(SealingKey(Key::new(algorithm, key_bytes)?))
    }

    /// The key's AEAD algorithm.
    ///
    /// C analog: `EVP_AEAD_CTX.aead`
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.0.algorithm }
}

/// Encrypts and signs (“seals”) data in place.
///
/// `nonce` must be unique for every use of the key to seal data.
///
/// The input is `in_out[..(in_out.len() - out_suffix_capacity)]`; i.e. the
/// input is the part of `in_out` that precedes the suffix. When
/// `seal_in_place()` returns `Ok(out_len)`, the encrypted and signed output is
/// `in_out[..out_len]`; i.e.  the output has been written over input and at
/// least part of the data reserved for the suffix. (The input/output buffer
/// is expressed this way because Rust's type system does not allow us to have
/// two slices, one mutable and one immutable, that reference overlapping
/// memory at the same time.)
///
/// `out_suffix_capacity` must be at least `key.algorithm().tag_len()`. See
/// also `MAX_TAG_LEN`.
///
/// `ad` is the additional authenticated data, if any.
///
/// C analog: `EVP_AEAD_CTX_seal`.
///
/// Go analog: [`AEAD.Seal`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn seal_in_place(key: &SealingKey, nonce: &[u8], ad: &[u8],
                     in_out: &mut [u8], out_suffix_capacity: usize)
                     -> Result<usize, error::Unspecified> {
    let ctx = SealingContext::new(key, nonce)?;
    ctx.add_ad(ad)?;

    let in_out_len = in_out.len().checked_sub(out_suffix_capacity).ok_or(error::Unspecified)?;
    let (in_out, tag_out) = in_out.split_at_mut(in_out_len);

    ctx.encrypt(in_out, 0)?;
    let tag_len = ctx.0.as_ref().get_tag(tag_out)?;
    Ok(in_out_len + tag_len)
}

// TODO: Explain Tag
struct Tag {
    data: [u8; MAX_TAG_LEN],
    len: usize,
}

impl AsRef<[u8]> for Tag {
    #[inline] fn as_ref(&self) -> &[u8] { self.data[:self.len] }
}

// TODO: Explain Context
enum Context {
    AesGcm(aes_gcm::Context),
    // ChaCha(chacha20_poly1305::Context),
}

trait ContextTrait {
    fn add_ad(&mut self, ad: &[u8]) -> Result<(), error::Unspecified>;
    fn encrypt(&mut self, in_out: &mut [u8]) -> Result<(), error::Unspecified>;
    fn decrypt(&mut self, in_out: &mut [u8]) -> Result<(), error::Unspecified>;
    fn get_tag(self, tag: &mut [u8]) -> Result<usize, error::Unspecified>;
}

impl AsRef<dyn ContextTrait> for Context {
    #[inline]
    fn as_ref(&self) -> &dyn ContextTrait {
        match self {
            Context::AesGcm(ctx) => ctx,
            // Context::ChaCha(ctx) => ctx,
        }
    }
}

// TODO: Explain Key
struct Key {
    key_enum: KeyEnum,
    algorithm: &'static Algorithm,
}

enum KeyEnum {
    AesGcm(aes_gcm::Key),
    // ChaCha(chacha20_poly1305::Key),
}

impl Key {
    #[inline]
    fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(Key {
            key_enum: algorithm.algorithm.init_key()?,
            algorithm: &'static Algorithm,
        })
    }
    #[inline]
    fn init_ctx(&self, nonce: &[u8]) -> Result<Context, error::Unspecified> {
        match self.key_enum {
            KeyEnum::AesGcm(key) => Context::AesGcm(key.init_ctx()?),
            // KeyEnum::ChaCha(key) => Context::ChaCha(key.init_ctx()?),
        }
    }
}

/// An AEAD Algorithm.
///
/// C analog: `EVP_AEAD`
///
/// Go analog:
///     [`crypto.cipher.AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub struct Algorithm {
    algorithm: &'static dyn AlgorithmTrait,
    key_len: usize,
    tag_len: usize,
    nonce_len: usize,
    id: AlgorithmID,
}

trait AlgorithmTrait {
    fn init_key(&self, key_bytes: &[u8]) -> Result<KeyEnum, ()>;
}

impl Algorithm {
    /// The length of the key.
    ///
    /// C analog: `EVP_AEAD_key_length`
    #[inline(always)]
    pub fn key_len(&self) -> usize { self.key_len }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    ///
    /// C analog: `EVP_AEAD_max_overhead`
    ///
    /// Go analog:
    ///   [`crypto.cipher.AEAD.Overhead`](https://golang.org/pkg/crypto/cipher/#AEAD)
    #[inline(always)]
    pub fn tag_len(&self) -> usize { self.tag_len }

    /// The length of the nonces.
    ///
    /// C analog: `EVP_AEAD_nonce_length`
    ///
    /// Go analog:
    ///   [`crypto.cipher.AEAD.NonceSize`](https://golang.org/pkg/crypto/cipher/#AEAD)
    #[inline(always)]
    pub fn nonce_len(&self) -> usize { self.nonce_len }
}

derive_debug_from_field!(Algorithm, id);

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    AES_128_GCM,
    AES_256_GCM,
    // CHACHA20_POLY1305,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool { self.id == other.id }
}

impl Eq for Algorithm {}

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = AES_128_GCM.tag_len;

/// All of our AEADs use a 32-bit block counter so the maximum input length is
/// the largest input that will not overflow the counter.
/// TODO: Make this a `const fn` when those become stable.
macro_rules! max_input_len {
    ($block_len:expr, $overhead_blocks_per_nonce:expr) => {
        (((1u64 << 32) - $overhead_blocks_per_nonce as u64) * $block_len as u64)
    }
}

pub mod chacha20_poly1305_openssh;
mod chacha20_poly1305;
mod aes_gcm;
