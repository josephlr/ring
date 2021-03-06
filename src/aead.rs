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
//! [AEAD]: http://www-cse.ucsd.edu/~mihir/papers/oem.html
//! [`crypto.cipher.AEAD`]: https://golang.org/pkg/crypto/cipher/#AEAD

use self::block::{Block, BLOCK_LEN};
use crate::{constant_time, cpu, error, hkdf, polyfill};
use core::convert::TryInto;

pub use self::{
    aes_gcm::{AES_128_GCM, AES_256_GCM},
    chacha20_poly1305::CHACHA20_POLY1305,
    nonce::{Nonce, NONCE_LEN},
};

/// A sequences of unique nonces.
///
/// A given `NonceSequence` must never return the same `Nonce` twice from
/// `advance()`.
///
/// A simple counter is a reasonable (but probably not ideal) `NonceSequence`.
///
/// Because `aead::Key::nonce_sequence_mut()` returns a mutable reference to
/// the `NonceSequence` in use, `NonceSequence` implementations should be
/// careful about how they expose mutating methods; it is generally better to
/// avoid exposing any mutating methods.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the sequence.
pub trait NonceSequence {
    /// Returns a nonce, and prevents that
    /// This may fail if "too many" nonces have been requested, where how many
    /// is too many is up to the implementation of `NonceSequence`. An
    /// implementation may that enforce a maximum number of records are
    /// sent/received under a key this way. Once `advance()` fails, it must
    /// fail for all subsequent calls.
    fn advance(&mut self) -> Result<Nonce, error::Unspecified>;
}

mod sealed {
    pub trait Role: core::fmt::Debug {
        const VALUE: Self;
    }
}

/// The role for which an AEAD key will be used.
pub trait Role: self::sealed::Role {}
impl<R: self::sealed::Role> Role for R {}

/// The key is for opening (authenticating and decrypting).
#[derive(Debug)]
pub struct Opening(());
impl self::sealed::Role for Opening {
    const VALUE: Self = Self(());
}

/// The key is for sealing (encrypting and authenticating).
#[derive(Debug)]
pub struct Sealing(());
impl self::sealed::Role for Sealing {
    const VALUE: Self = Self(());
}

/// An AEAD key with a designated role and nonce sequence.
pub struct Key<R: Role, N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
    role: R,
}

impl<R: Role, N: NonceSequence> Key<R, N> {
    /// Constructs a new `Key` from the given `UnboundKey` and `NonceSequence`.
    pub fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
            role: R::VALUE,
        }
    }

    /// The key's AEAD algorithm.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
    }
}

impl<R: Role, N: NonceSequence> core::fmt::Debug for Key<R, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Key")
            .field("algorithm", &self.algorithm())
            .field("role", &self.role)
            .finish()
    }
}

impl<N: NonceSequence> Key<Opening, N> {
    /// Authenticates and decrypts (“opens”) data in place.
    ///
    /// The input may have a prefix that is `in_prefix_len` bytes long; any such
    /// prefix is ignored on input and overwritten on output. The last
    /// `key.algorithm().tag_len()` bytes of
    /// `ciphertext_and_tag_modified_in_place` must be the tag. The part of
    /// `ciphertext_and_tag_modified_in_place` between the prefix and the
    /// tag is the input ciphertext.
    ///
    /// When `open_in_place()` returns `Ok(plaintext)`, the decrypted output is
    /// `plaintext`, which is
    /// `&mut ciphertext_and_tag_modified_in_place[..plaintext.len()]`. That is,
    /// the output plaintext overwrites some or all of the prefix and
    /// ciphertext. To put it another way, the ciphertext is shifted forward
    /// `in_prefix_len` bytes and then decrypted in place. To have the
    /// output overwrite the input without shifting, pass 0 as
    /// `in_prefix_len`.
    ///
    /// When `open_in_place()` returns `Err(..)`,
    /// `ciphertext_and_tag_modified_in_place` may have been overwritten in an
    /// unspecified way.
    ///
    /// The shifting feature is useful in the case where multiple packets are
    /// being reassembled in place. Consider this example where the peer has
    /// sent the message “Split stream reassembled in place” split into
    /// three sealed packets:
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
    /// Let's say the header is always 5 bytes (like TLS 1.2) and the tag is
    /// always 16 bytes (as for AES-GCM and ChaCha20-Poly1305). Then for
    /// this example, `in_prefix_len` would be `5` for the first packet, `(5
    /// + 16) + 5` for the second packet, and `(2 * (5 + 16)) + 5` for the
    /// third packet.
    ///
    /// (The input/output buffer is expressed as combination of `in_prefix_len`
    /// and `ciphertext_and_tag_modified_in_place` because Rust's type system
    /// does not allow us to have two slices, one mutable and one immutable,
    /// that reference overlapping memory.)
    pub fn open_in_place<'a, A: AsRef<[u8]>>(
        &mut self,
        Aad(aad): Aad<A>,
        in_prefix_len: usize,
        ciphertext_and_tag_modified_in_place: &'a mut [u8],
    ) -> Result<&'a mut [u8], error::Unspecified> {
        open_in_place_(
            &self.key,
            self.nonce_sequence.advance()?,
            Aad::from(aad.as_ref()),
            in_prefix_len,
            ciphertext_and_tag_modified_in_place,
        )
    }

    /// Allows mutable access to the `NonceSequence` used for this key.
    ///
    /// This is provided primarily for use with `NonceSequence` implementations
    /// that allow the next nonce in the sequence to be explicitly set.
    pub fn nonce_sequence_mut(&mut self) -> &mut N {
        &mut self.nonce_sequence
    }
}

fn open_in_place_<'a>(
    key: &UnboundKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_prefix_len: usize,
    ciphertext_and_tag_modified_in_place: &'a mut [u8],
) -> Result<&'a mut [u8], error::Unspecified> {
    let ciphertext_and_tag_len = ciphertext_and_tag_modified_in_place
        .len()
        .checked_sub(in_prefix_len)
        .ok_or(error::Unspecified)?;
    let ciphertext_len = ciphertext_and_tag_len
        .checked_sub(TAG_LEN)
        .ok_or(error::Unspecified)?;
    check_per_nonce_max_bytes(key.algorithm, ciphertext_len)?;
    let (in_out, received_tag) =
        ciphertext_and_tag_modified_in_place.split_at_mut(in_prefix_len + ciphertext_len);
    let Tag(calculated_tag) = (key.algorithm.open)(
        &key.inner,
        nonce,
        aad,
        in_prefix_len,
        in_out,
        key.cpu_features,
    );
    if constant_time::verify_slices_are_equal(calculated_tag.as_ref(), received_tag).is_err() {
        // Zero out the plaintext so that it isn't accidentally leaked or used
        // after verification fails. It would be safest if we could check the
        // tag before decrypting, but some `open` implementations interleave
        // authentication with decryption for performance.
        for b in &mut in_out[..ciphertext_len] {
            *b = 0;
        }
        return Err(error::Unspecified);
    }
    // `ciphertext_len` is also the plaintext length.
    Ok(&mut in_out[..ciphertext_len])
}

impl<N: NonceSequence> Key<Sealing, N> {
    /// Encrypts and signs (“seals”) data in place.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// The input is `in_out[..(in_out.len() - out_suffix_capacity)]`; i.e. the
    /// input is the part of `in_out` that precedes the suffix. When
    /// `seal_in_place()` returns `Ok(out_len)`, the encrypted and signed output
    /// is `in_out[..out_len]`; i.e.  the output has been written over input
    /// and at least part of the data reserved for the suffix. (The
    /// input/output buffer is expressed this way because Rust's type system
    /// does not allow us to have two slices, one mutable and one immutable,
    /// that reference overlapping memory at the same time.)
    ///
    /// `out_suffix_capacity` must be at least `key.algorithm().tag_len()`. See
    /// also `MAX_TAG_LEN`.
    ///
    /// `aad` is the additional authenticated data, if any.
    pub fn seal_in_place<A: AsRef<[u8]>>(
        &mut self,
        Aad(aad): Aad<A>,
        in_out: &mut [u8],
        out_suffix_capacity: usize,
    ) -> Result<usize, error::Unspecified> {
        seal_in_place_(
            &self.key,
            self.nonce_sequence.advance()?,
            Aad::from(aad.as_ref()),
            in_out,
            out_suffix_capacity,
        )
    }
}

fn seal_in_place_(
    key: &UnboundKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    out_suffix_capacity: usize,
) -> Result<usize, error::Unspecified> {
    if out_suffix_capacity < key.algorithm.tag_len() {
        return Err(error::Unspecified);
    }
    let in_out_len = in_out
        .len()
        .checked_sub(out_suffix_capacity)
        .ok_or(error::Unspecified)?;
    check_per_nonce_max_bytes(key.algorithm, in_out_len)?;
    let (in_out, tag_out) = in_out.split_at_mut(in_out_len);

    let tag_out: &mut [u8; TAG_LEN] = tag_out.try_into()?;
    let Tag(tag) = (key.algorithm.seal)(&key.inner, nonce, aad, in_out, key.cpu_features);
    tag_out.copy_from_slice(tag.as_ref());

    Ok(in_out_len + TAG_LEN)
}

/// The additionally authenticated data (AAD) for an opening or sealing
/// operation. This data is authenticated but is **not** encrypted.
#[repr(transparent)]
pub struct Aad<A: AsRef<[u8]>>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Construct the `Aad` from the given bytes.
    #[inline]
    pub fn from(aad: A) -> Self {
        Aad(aad)
    }
}

impl Aad<[u8; 0]> {
    /// Construct an empty `Aad`.
    pub fn empty() -> Self {
        Self::from([])
    }
}

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    inner: KeyInner,
    algorithm: &'static Algorithm,
    cpu_features: cpu::Features,
}

impl core::fmt::Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[allow(variant_size_differences)]
enum KeyInner {
    AesGcm(aes_gcm::Key),
    ChaCha20Poly1305(chacha20_poly1305::Key),
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    ///
    /// Fails if `key_bytes.len() != ` algorithm.key_len()`.
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        let cpu_features = cpu::features();
        Ok(Self {
            inner: (algorithm.init)(key_bytes, cpu_features)?,
            algorithm,
            cpu_features,
        })
    }

    /// The key's AEAD algorithm.
    #[inline(always)]
    fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// An AEAD Algorithm.
pub struct Algorithm {
    init: fn(key: &[u8], cpu_features: cpu::Features) -> Result<KeyInner, error::Unspecified>,

    seal: fn(
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
        cpu_features: cpu::Features,
    ) -> Tag,
    open: fn(
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_prefix_len: usize,
        in_out: &mut [u8],
        cpu_features: cpu::Features,
    ) -> Tag,

    key_len: usize,
    id: AlgorithmID,

    /// Use `max_input_len!()` to initialize this.
    // TODO: Make this `usize`.
    max_input_len: u64,
}

const fn max_input_len(block_len: usize, overhead_blocks_per_nonce: usize) -> u64 {
    // Each of our AEADs use a 32-bit block counter so the maximum is the
    // largest input that will not overflow the counter.
    ((1u64 << 32) - polyfill::u64_from_usize(overhead_blocks_per_nonce))
        * polyfill::u64_from_usize(block_len)
}

impl Algorithm {
    /// The length of the key.
    #[inline(always)]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of the nonces.
    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

derive_debug_via_id!(Algorithm);

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

/// An authentication tag.
#[must_use]
#[repr(C)]
struct Tag(Block);

const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = BLOCK_LEN;

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;

fn check_per_nonce_max_bytes(alg: &Algorithm, in_out_len: usize) -> Result<(), error::Unspecified> {
    if polyfill::u64_from_usize(in_out_len) > alg.max_input_len {
        return Err(error::Unspecified);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Direction {
    Opening { in_prefix_len: usize },
    Sealing,
}

mod aes;
mod aes_gcm;
mod block;
mod chacha;
mod chacha20_poly1305;
pub mod chacha20_poly1305_openssh;
mod gcm;
mod nonce;
mod poly1305;
pub mod quic;
mod shift;
