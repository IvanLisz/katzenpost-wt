#![cfg_attr(feature = "simd", feature(portable_simd))]
//! AEZ *\[sic!\]* v5 encryption implemented in Rust.
//!
//! # ☣️ Cryptographic hazmat ☣️
//!
//! This crate is not battle tested, nor is it audited. Its usage for critical systems is strongly
//! discouraged. It mainly exists as a learning exercise.
//!
//! # AEZ encryption
//!
//! [AEZ](https://www.cs.ucdavis.edu/~rogaway/aez/index.html) is an authenticated encryption
//! scheme. It works in two steps:
//!
//! * First, a known authentication block (a fixed number of zeroes) is appended to the message.
//! * Second, the message is enciphered with an arbitrary-length blockcipher.
//!
//! The blockcipher is tweaked with the key, the nonce and additional data.
//!
//! The [paper](https://www.cs.ucdavis.edu/~rogaway/aez/aez.pdf) explains the security concepts of
//! AEZ in more detail.
//!
//! # AEZ encryption (for laypeople)
//!
//! The security property of encryption schemes says that an adversary without key must not learn
//! the content of a message. However, the adversary might still be able to modify the message. For
//! example, in AES-CTR (or other stream ciphers), flipping a bit in the ciphertext means that the
//! same bit will be flipped in the plaintext once the message is decrypted. This allows for
//! "planned" changes.
//!
//! Authenticated encryption solves this problem by including a mechanism to detect changes. This
//! can be done for example by including a MAC, or using a mode like GCM (Galois counter mode). In
//! many cases, not only the integrity of the ciphertext can be verified, but the user can provide
//! additional data during encryption and decryption which will also have its integrity be
//! verified. This is called an *authenticated encryption with associated data* scheme, AEAD for
//! short.
//!
//! AEZ employs a nifty technique in order to realize an AEAD scheme: The core of AEZ is an
//! enciphering scheme, which in addition to "hiding" its input is also very "unpredictable" when
//! bits are flipped. Similar to a hash function, if the ciphertext is changed slightly (by
//! flipping a bit), the resulting plaintext will be unpredictably and completely different.
//!
//! With this property, authenticated encryption can be realized implicitly: The message is padded
//! with a known string before enciphering it. If, after deciphering, this known string is not
//! present, the message has been tampered with. Since the enciphering is parametrized by the key,
//! a nonce and arbitrary additional data, we can verify the integrity of associated data as well.
//!
//! # Other implementations
//!
//! As this library is a learning exercise, if you want to use AEZ in practice, it is suggested to
//! use the [`aez`](https://crates.io/crates/aez) crate which provides bindings to the C reference
//! implementation of AEZ.
//!
//! `zears` differs from `aez` in that ...
//!
//! * it works on platforms without hardware AES support, using the "soft" backend of
//!   [`aes`](https://crates.io/crates/aes).
//! * it does not inherit the limitations of the reference implementation in regards to nonce
//!   length, authentication tag length, or the maximum of one associated data item.
//!
//! `zears` is tested with test vectors generated from the reference implementation using [Nick
//! Mathewson's tool](https://github.com/nmathewson/aez_test_vectors).
//!
//! # Example usage
//!
//! The core of this crate is the [Aez] struct, which provides the high-level API. There is usually
//! not a lot more that you need:
//!
//! ```
//! # use zears::*;
//! let aez = Aez::new(b"my secret key!");
//! let cipher = aez.encrypt(b"nonce", &[b"associated data"], 16, b"message");
//! let plaintext = aez.decrypt(b"nonce", &[b"associated data"], 16, &cipher);
//! assert_eq!(plaintext.unwrap(), b"message");
//!
//! // Flipping a bit leads to decryption failure
//! let mut cipher = aez.encrypt(b"nonce", &[], 16, b"message");
//! cipher[0] ^= 0x02;
//! let plaintext = aez.decrypt(b"nonce", &[], 16, &cipher);
//! assert!(plaintext.is_none());
//!
//! // Similarly, modifying the associated data leads to failure
//! let cipher = aez.encrypt(b"nonce", &[b"foo"], 16, b"message");
//! let plaintext = aez.decrypt(b"nonce", &[b"bar"], 16, &cipher);
//! assert!(plaintext.is_none());
//! ```
//!
//! # Feature flags & compilation hints
//!
//! * Enable feature `simd` (requires nightly due to the `portable_simd` Rust feature) to speed up
//!   encryption and decryption by using SIMD instructions (if available).
//! * Use `target-cpu=native` (e.g. by setting `RUSTFLAGS=-Ctarget-cpu=native`) to make the
//!   compiler emit vectorized AES instructions (if available). This can speed up
//!   encryption/decryption at the cost of producing less portable code.
//!
//! On my machine, this produces the following results (for the `encrypt_inplace/2048` benchmark):
//!
//! | Compilation setup        | Throughput   | Speedup  |
//! |--------------------------|--------------|----------|
//! | baseline                 | 488.78 MiB/s |          |
//! | +simd                    | 967.91 MiB/s | +98.187% |
//! | target-cpu=native        | 2.0062 GiB/s | +314.67% |
//! | +simd, target-cpu=native | 3.3272 GiB/s | +592.01% |
//! | `aez` crate              | 4.8996 GiB/s |          |

use constant_time_eq::constant_time_eq;

mod accessor;
mod aesround;
mod block;

#[cfg(test)]
mod testvectors;

use accessor::BlockAccessor;
use aesround::AesRound;
use block::Block;
type Key = [u8; 48];
type Tweak<'a> = &'a [&'a [u8]];

static ZEROES: [u8; 1024] = [0; 1024];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encipher,
    Decipher,
}

/// AEZ encryption scheme.
///
/// See the [module level documentation](index.html) for more information.
pub struct Aez {
    key_i: Block,
    key_j: Block,
    key_l: Block,
    key_l_multiples: [Block; 8],
    aes: aesround::AesImpl,
}

impl Aez {
    /// Create a new AEZ instance.
    ///
    /// The key is expanded using Blake2b, according to the AEZ specification.
    ///
    /// If you provide a key of the correct length (48 bytes), no expansion is done and the key is
    /// taken as-is.
    pub fn new(key: &[u8]) -> Self {
        let key = extract(key);
        let (key_i, key_j, key_l) = split_key(&key);
        let aes = aesround::AesImpl::new(key_i, key_j, key_l);
        let key_l_multiples = [
            key_l * 0,
            key_l * 1,
            key_l * 2,
            key_l * 3,
            key_l * 4,
            key_l * 5,
            key_l * 6,
            key_l * 7,
        ];
        Aez {
            key_i,
            key_j,
            key_l,
            key_l_multiples,
            aes,
        }
    }

    /// Encrypt the given data.
    ///
    /// This is a convenience function that allocates a fresh buffer of the appropriate size and
    /// copies the data.
    ///
    /// Parameters:
    ///
    /// * `nonce` -- the nonce to use. Each nonce should only be used once, as re-using the nonce
    ///   (without changing the key) will lead to the same ciphertext being produced, potentially
    ///   making it re-identifiable.
    /// * `associated_data` -- additional data to be included in the integrity check. Note that
    ///   this data will *not* be contained in the ciphertext, but it must be provided on
    ///   decryption.
    /// * `tau` -- number of *bytes* (not bits) to use for integrity checking. A value of `tau =
    ///   16` gives 128 bits of security. Passing a value of 0 is valid and leads to no integrity
    ///   checking.
    /// * `data` -- actual data to encrypt. Can be empty, in which case the returned ciphertext
    ///   provides a "hash" that verifies the integrity of the associated data.
    ///
    /// Returns the ciphertext, which will be of length `data.len() + tau`.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        tau: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut buffer = Vec::from(data);
        self.encrypt_vec(nonce, associated_data, tau, &mut buffer);
        buffer
    }

    /// Encrypts the data in the given [`Vec`].
    ///
    /// This function extends the vector with enough space to hold `tau` bytes of authentication
    /// data. Afterwards, the vector will hold the ciphertext.
    ///
    /// If `tau == 0`, the vector will not be expanded.
    ///
    /// The parameters are the same as for [`Aez::encrypt`].
    pub fn encrypt_vec(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        tau: u32,
        data: &mut Vec<u8>,
    ) {
        data.resize(data.len() + tau as usize, 0);
        encrypt(&self, nonce, associated_data, tau, data);
    }

    /// Encrypts the data inplace.
    ///
    /// This function will overwrite the last `tau` bytes of the given buffer with the
    /// authentication block before encrypting the data.
    ///
    /// If the buffer is smaller than `tau`, this function panics.
    pub fn encrypt_inplace(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        tau: u32,
        buffer: &mut [u8],
    ) {
        assert!(buffer.len() >= tau as usize);
        let data_len = buffer.len() - tau as usize;
        append_auth(data_len, buffer);
        encrypt(&self, nonce, associated_data, tau as u32, buffer);
    }

    /// Encrypts the data in the given buffer, writing the output to the given output buffer.
    ///
    /// This function will infer `tau` from the size difference between input and output. If the
    /// output is smaller than the input, this funcion will panic.
    ///
    /// The `nonce` and `associated_data` parameters are the same as for [`Aez::encrypt`].
    pub fn encrypt_buffer(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) {
        assert!(output.len() >= input.len());
        let tau = output.len() - input.len();
        output[..input.len()].copy_from_slice(input);
        append_auth(input.len(), output);
        encrypt(&self, nonce, associated_data, tau as u32, output);
    }

    /// Decrypts the given ciphertext.
    ///
    /// This is a convenience function that returns an owned version of the plaintext. If the
    /// original buffer may be modified, you can use [`Aez::decrypt_inplace`] to save an allocation.
    ///
    /// Parameters:
    ///
    /// * `nonce`, `associated_data` and `tau` are as for [`Aez::encrypt`].
    /// * `data` -- the ciphertext to decrypt.
    ///
    /// Returns the decrypted content. If the integrity check fails, returns `None` instead. The
    /// returned vector has length `data.len() - tau`.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        tau: u32,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buffer = Vec::from(data);
        let len = match decrypt(&self, nonce, associated_data, tau, &mut buffer) {
            None => return None,
            Some(m) => m.len(),
        };
        buffer.truncate(len);
        Some(buffer)
    }

    /// Decrypt the given buffer in-place.
    ///
    /// Returns a slice to the valid plaintext subslice, or `None`.
    ///
    /// The parameters are the same as for [`Aez::decrypt`].
    pub fn decrypt_inplace<'a>(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        tau: u32,
        data: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        decrypt(&self, nonce, associated_data, tau, data)
    }
}

fn extract(key: &[u8]) -> [u8; 48] {
    if key.len() == 48 {
        key.try_into().unwrap()
    } else {
        use blake2::Digest;
        type Blake2b384 = blake2::Blake2b<blake2::digest::consts::U48>;
        let mut hasher = Blake2b384::new();
        hasher.update(key);
        hasher.finalize().into()
    }
}

fn append_auth(data_len: usize, buffer: &mut [u8]) {
    let mut total_len = data_len;
    while total_len < buffer.len() {
        let block_size = ZEROES.len().min(buffer.len() - total_len);
        buffer[total_len..total_len + block_size].copy_from_slice(&ZEROES[..block_size]);
        total_len += block_size;
    }
}

fn encrypt(aez: &Aez, nonce: &[u8], ad: &[&[u8]], tau: u32, buffer: &mut [u8]) {
    // We treat tau as bytes, but according to the spec, tau is actually in bits.
    let tau_block = Block::from_int(tau as u128 * 8);
    let tau_bytes = tau_block.bytes();
    let mut tweaks_vec;
    // We optimize for the common case of having no associated data, or having one item of
    // associated data (which is all the reference implementation supports anyway). If there's more
    // associated data, we cave in and allocate a vec.
    let tweaks = match ad.len() {
        0 => &[&tau_bytes, nonce] as &[&[u8]],
        1 => &[&tau_bytes, nonce, ad[0]],
        _ => {
            tweaks_vec = vec![&tau_bytes, nonce];
            tweaks_vec.extend(ad);
            &tweaks_vec
        }
    };
    assert!(buffer.len() >= tau as usize);
    if buffer.len() == tau as usize {
        // As aez_prf only xor's the input in, we have to clear the buffer first
        buffer.fill(0);
        aez_prf(aez, &tweaks, buffer);
    } else {
        encipher(aez, &tweaks, buffer);
    }
}

fn decrypt<'a>(
    aez: &Aez,
    nonce: &[u8],
    ad: &[&[u8]],
    tau: u32,
    ciphertext: &'a mut [u8],
) -> Option<&'a [u8]> {
    if ciphertext.len() < tau as usize {
        return None;
    }

    let tau_block = Block::from_int(tau * 8);
    let tau_bytes = tau_block.bytes();
    let mut tweaks_vec;
    let tweaks = match ad.len() {
        0 => &[&tau_bytes, nonce] as &[&[u8]],
        1 => &[&tau_bytes, nonce, ad[0]],
        _ => {
            tweaks_vec = vec![&tau_bytes, nonce];
            tweaks_vec.extend(ad);
            &tweaks_vec
        }
    };

    if ciphertext.len() == tau as usize {
        aez_prf(aez, &tweaks, ciphertext);
        if is_zeroes(&ciphertext) {
            return Some(&[]);
        } else {
            return None;
        }
    }

    decipher(aez, &tweaks, ciphertext);
    let (m, auth) = ciphertext.split_at(ciphertext.len() - tau as usize);
    assert!(auth.len() == tau as usize);

    if is_zeroes(&auth) { Some(m) } else { None }
}

fn is_zeroes(data: &[u8]) -> bool {
    let comparator = if data.len() <= ZEROES.len() {
        &ZEROES[..data.len()]
    } else {
        // We should find a way to do this without allocating a separate buffer full of zeroes, but
        // I don't want to hand-roll my constant-time-is-zeroes yet.
        &vec![0; data.len()]
    };
    constant_time_eq(data, comparator)
}

fn encipher(aez: &Aez, tweaks: Tweak, message: &mut [u8]) {
    if message.len() < 256 / 8 {
        cipher_aez_tiny(Mode::Encipher, aez, tweaks, message)
    } else {
        cipher_aez_core(Mode::Encipher, aez, tweaks, message)
    }
}

fn decipher(aez: &Aez, tweaks: Tweak, buffer: &mut [u8]) {
    if buffer.len() < 256 / 8 {
        cipher_aez_tiny(Mode::Decipher, aez, tweaks, buffer);
    } else {
        cipher_aez_core(Mode::Decipher, aez, tweaks, buffer);
    }
}

fn cipher_aez_tiny(mode: Mode, aez: &Aez, tweaks: Tweak, message: &mut [u8]) {
    let mu = message.len() * 8;
    assert!(mu < 256);
    let n = mu / 2;
    let delta = aez_hash(aez, tweaks);
    let round_count = match mu {
        8 => 24u32,
        16 => 16,
        _ if mu < 128 => 10,
        _ => 8,
    };

    if mode == Mode::Decipher && mu < 128 {
        let mut c = Block::from_slice(message);
        c = c ^ (e(0, 3, aez, delta ^ (c | Block::one())) & Block::one());
        message.copy_from_slice(&c.bytes()[..mu / 8]);
    }

    let (mut left, mut right);
    // We might end up having to split at a nibble, so manually adjust for that
    if n % 8 == 0 {
        left = Block::from_slice(&message[..n / 8]);
        right = Block::from_slice(&message[n / 8..]);
    } else {
        assert!(n % 8 == 4);
        left = Block::from_slice(&message[..n / 8 + 1]).clip(n);
        right = Block::from_slice(&message[n / 8..]) << 4;
    };

    let i = if mu >= 128 { 6 } else { 7 };

    if mode == Mode::Encipher {
        for j in 0..round_count {
            let right_ = (left ^ e(0, i, aez, delta ^ right.pad(n) ^ Block::from_int(j))).clip(n);
            (left, right) = (right, right_);
        }
    } else {
        for j in (0..round_count).rev() {
            let right_ = (left ^ e(0, i, aez, delta ^ right.pad(n) ^ Block::from_int(j))).clip(n);
            (left, right) = (right, right_);
        }
    }

    if n % 8 == 0 {
        message[..n / 8].copy_from_slice(&right.bytes()[..n / 8]);
        message[n / 8..].copy_from_slice(&left.bytes()[..n / 8]);
    } else {
        let mut index = n / 8;
        message[..index + 1].copy_from_slice(&right.bytes()[..index + 1]);
        for byte in &left.bytes()[..n / 8 + 1] {
            message[index] |= byte >> 4;
            if index < message.len() - 1 {
                message[index + 1] = (byte & 0x0f) << 4;
            }
            index += 1;
        }
    }

    if mode == Mode::Encipher && mu < 128 {
        let mut c = Block::from_slice(&message);
        c = c ^ (e(0, 3, aez, delta ^ (c | Block::one())) & Block::one());
        message.copy_from_slice(&c.bytes()[..mu / 8]);
    }
}

fn cipher_aez_core(mode: Mode, aez: &Aez, tweaks: Tweak, message: &mut [u8]) {
    assert!(message.len() >= 32);
    let delta = aez_hash(aez, tweaks);
    let mut blocks = BlockAccessor::new(message);
    let (m_u, m_v, m_x, m_y, d) = (
        blocks.m_u(),
        blocks.m_v(),
        blocks.m_x(),
        blocks.m_y(),
        blocks.m_uv_len(),
    );
    let len_v = d.saturating_sub(128);

    let mut x = Block::null();
    let mut e1_eval = E::new(1, 0, aez);
    let e0_eval = E::new(0, 0, aez);

    for (raw_mi, raw_mi_) in blocks.pairs_mut() {
        e1_eval.advance();
        let mi = Block::from(*raw_mi);
        let mi_ = Block::from(*raw_mi_);
        let wi = mi ^ e1_eval.eval(mi_);
        let xi = mi_ ^ e0_eval.eval(wi);

        wi.write_to(raw_mi);
        xi.write_to(raw_mi_);

        x = x ^ xi;
    }

    match d {
        0 => (),
        _ if d <= 127 => {
            x = x ^ e(0, 4, aez, m_u.pad(d.into()));
        }
        _ => {
            x = x ^ e(0, 4, aez, m_u);
            x = x ^ e(0, 5, aez, m_v.pad(len_v.into()));
        }
    }

    let (s_x, s_y);
    match mode {
        Mode::Encipher => {
            s_x = m_x ^ delta ^ x ^ e(0, 1, aez, m_y);
            s_y = m_y ^ e(-1, 1, aez, s_x);
        }
        Mode::Decipher => {
            s_x = m_x ^ delta ^ x ^ e(0, 2, aez, m_y);
            s_y = m_y ^ e(-1, 2, aez, s_x);
        }
    }
    let s = s_x ^ s_y;

    let mut y = Block::null();
    let mut e2_eval = E::new(2, 0, aez);
    let mut e1_eval = E::new(1, 0, aez);
    for (raw_wi, raw_xi) in blocks.pairs_mut() {
        e2_eval.advance();
        e1_eval.advance();
        let wi = Block::from(*raw_wi);
        let xi = Block::from(*raw_xi);
        let s_ = e2_eval.eval(s);
        let yi = wi ^ s_;
        let zi = xi ^ s_;
        let ci_ = yi ^ e0_eval.eval(zi);
        let ci = zi ^ e1_eval.eval(ci_);

        ci.write_to(raw_wi);
        ci_.write_to(raw_xi);

        y = y ^ yi;
    }

    let mut c_u = Block::default();
    let mut c_v = Block::default();

    match d {
        0 => (),
        _ if d <= 127 => {
            c_u = (m_u ^ e(-1, 4, aez, s)).clip(d.into());
            y = y ^ e(0, 4, aez, c_u.pad(d.into()));
        }
        _ => {
            c_u = m_u ^ e(-1, 4, aez, s);
            c_v = (m_v ^ e(-1, 5, aez, s)).clip(len_v.into());
            y = y ^ e(0, 4, aez, c_u);
            y = y ^ e(0, 5, aez, c_v.pad(len_v.into()));
        }
    }

    let (c_x, c_y);
    match mode {
        Mode::Encipher => {
            c_y = s_x ^ e(-1, 2, aez, s_y);
            c_x = s_y ^ delta ^ y ^ e(0, 2, aez, c_y);
        }
        Mode::Decipher => {
            c_y = s_x ^ e(-1, 1, aez, s_y);
            c_x = s_y ^ delta ^ y ^ e(0, 1, aez, c_y);
        }
    }

    blocks.set_m_u(c_u);
    blocks.set_m_v(c_v);
    blocks.set_m_x(c_x);
    blocks.set_m_y(c_y);
}

fn pad_to_blocks(value: &[u8]) -> impl Iterator<Item=Block> {
    value.chunks(16)
        .map(|chunk| if chunk.len() == 16 {
            Block::from_slice(chunk)
        } else {
            Block::from_slice(chunk).pad(chunk.len() * 8)
        })
}

fn aez_hash(aez: &Aez, tweaks: Tweak) -> Block {
    let mut hash = Block::null();
    for (i, tweak) in tweaks.iter().enumerate() {
        // Adjust for zero-based vs one-based indexing
        let j = i + 2 + 1;
        let mut ej = E::new(j.try_into().unwrap(), 0, aez);
        // This is somewhat implicit in the AEZ spec, but basically for an empty string we still
        // set l = 1 and then xor E_K^{j, 0}(10*). We could modify the last if branch to cover this
        // as well, but then we need to fiddle with getting an empty chunk from an empty iterator.
        if tweak.is_empty() {
            hash = hash ^ ej.eval(Block::one());
        } else if tweak.len() % 16 == 0 {
            for chunk in tweak.chunks(16) {
                ej.advance();
                hash = hash ^ ej.eval(Block::from_slice(chunk));
            }
        } else {
            let blocks = pad_to_blocks(tweak);
            for (l, chunk) in blocks.enumerate() {
                ej.advance();
                if l == tweak.len() / 16 {
                    hash = hash ^ e(j.try_into().unwrap(), 0, aez, chunk);
                } else {
                    hash = hash ^ ej.eval(chunk);
                }
            }
        }
    }
    hash
}

/// XOR's the result of aez_prf into the given buffer
fn aez_prf(aez: &Aez, tweaks: Tweak, buffer: &mut [u8]) {
    let mut index = 0u128;
    let delta = aez_hash(aez, tweaks);
    for chunk in buffer.chunks_exact_mut(16) {
        let chunk: &mut [u8; 16] = chunk.try_into().unwrap();
        let block = e(-1, 3, aez, delta ^ Block::from_int(index));
        (block ^ Block::from(*chunk)).write_to(chunk);
        index += 1;
    }
    let suffix_start = buffer.len() - buffer.len() % 16;
    let chunk = &mut buffer[suffix_start..];
    let block = e(-1, 3, aez, delta ^ Block::from_int(index));
    for (a, b) in chunk.iter_mut().zip(block.bytes().iter()) {
        *a ^= *b;
    }
}

/// Represents a computation of E_K^{j,i}.
///
/// As we usually need multiple values with a fixed j and ascending i, this struct saves the
/// temporary values and makes it much faster to compute E_K^{j, i+1}, E_K^{j, i+2}, ...
struct E<'a> {
    aez: &'a Aez,
    i: u32,
    kj_t_j: Block,
    ki_p_i: Block,
}

impl<'a> E<'a> {
    /// Create a new "suspended" computation of E_K^{j,i}.
    fn new(j: i32, i: u32, aez: &'a Aez) -> Self {
        assert!(j >= 0);
        let j: u32 = j.try_into().expect("j was negative");
        let exponent = if i % 8 == 0 { i / 8 } else { i / 8 + 1 };
        E {
            aez,
            i,
            kj_t_j: aez.key_j * j,
            ki_p_i: aez.key_i.exp(exponent),
        }
    }

    /// Complete this computation to evaluate E_K^{j,i}(block).
    fn eval(&self, block: Block) -> Block {
        let delta = self.kj_t_j ^ self.ki_p_i ^ self.aez.key_l_multiples[self.i as usize % 8];
        self.aez.aes.aes4(block ^ delta)
    }

    /// Advance this computation by going from i to i+1.
    ///
    /// Afterwards, this computation will represent E_K^{j, i+1}
    fn advance(&mut self) {
        // We need to advance ki_p_i if exponent = old_exponent + 1
        // This happens exactly when the old exponent was just a multiple of 8, because the
        // next exponent is then not a multiple anymore and will be rounded *up*.
        if self.i % 8 == 0 {
            self.ki_p_i = self.ki_p_i * 2
        };
        self.i += 1;
    }
}

/// Shorthand to get E_K^{j,i}(block)
fn e(j: i32, i: u32, aez: &Aez, block: Block) -> Block {
    if j == -1 {
        let delta = if i < 8 {
            aez.key_l_multiples[i as usize]
        } else {
            aez.key_l * i
        };
        aez.aes.aes10(block ^ delta)
    } else {
        E::new(j, i, aez).eval(block)
    }
}

fn split_key(key: &Key) -> (Block, Block, Block) {
    (
        Block::from_slice(&key[..16]),
        Block::from_slice(&key[16..32]),
        Block::from_slice(&key[32..]),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    static PLAIN: &[u8] = include_bytes!("payload.txt");

    #[test]
    fn test_extract() {
        for (a, b) in testvectors::EXTRACT_VECTORS {
            let a = hex::decode(a).unwrap();
            let b = hex::decode(b).unwrap();
            assert_eq!(extract(&a), b.as_slice());
        }
    }

    #[test]
    fn test_e() {
        for (k, j, i, a, b) in testvectors::E_VECTORS {
            let name = format!("e({j}, {i}, {k}, {a})");
            let k = hex::decode(k).unwrap();
            let aez = Aez::new(k.as_slice());
            let a = hex::decode(a).unwrap();
            let a = Block::from_slice(&a);
            let b = hex::decode(b).unwrap();
            assert_eq!(&e(*j, *i, &aez, a).bytes(), b.as_slice(), "{name}");
        }
    }

    #[test]
    fn test_aez_hash() {
        for (k, tau, tw, v) in testvectors::HASH_VECTORS {
            let name = format!("aez_hash({k}, {tau}, {tw:?})");
            let k = hex::decode(k).unwrap();
            let aez = Aez::new(k.as_slice());
            let v = hex::decode(v).unwrap();

            let mut tweaks = vec![Vec::from(Block::from_int(*tau).bytes())];
            for t in *tw {
                tweaks.push(hex::decode(t).unwrap());
            }
            let tweaks = tweaks.iter().map(Vec::as_slice).collect::<Vec<_>>();

            assert_eq!(&aez_hash(&aez, &tweaks).bytes(), v.as_slice(), "{name}");
        }
    }

    fn vec_encrypt(key: &Key, nonce: &[u8], ad: &[&[u8]], tau: u32, message: &[u8]) -> Vec<u8> {
        let aez = Aez::new(key);
        let mut v = vec![0; message.len() + tau as usize];
        v[..message.len()].copy_from_slice(message);
        encrypt(&aez, nonce, ad, tau, &mut v);
        v
    }

    fn vec_decrypt(
        key: &Key,
        nonce: &[u8],
        ad: &[&[u8]],
        tau: u32,
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let aez = Aez::new(key);
        let mut v = Vec::from(ciphertext);
        let len = match decrypt(&aez, nonce, ad, tau, &mut v) {
            None => return None,
            Some(m) => m.len(),
        };
        v.truncate(len);
        Some(v)
    }

    #[test]
    fn test_encrypt() {
        let mut failed = 0;
        let mut succ = 0;
        for (k, n, ads, tau, m, c) in testvectors::ENCRYPT_VECTORS {
            let name = format!("encrypt({k}, {n}, {ads:?}, {tau}, {m})");
            let k = hex::decode(k).unwrap();
            let k = k.as_slice().try_into().unwrap();
            let n = hex::decode(n).unwrap();

            let mut ad = Vec::new();
            for i in *ads {
                ad.push(hex::decode(i).unwrap());
            }
            let ad = ad.iter().map(Vec::as_slice).collect::<Vec<_>>();

            let m = hex::decode(m).unwrap();
            let c = hex::decode(c).unwrap();

            if &vec_encrypt(&k, &n, &ad, *tau, &m) == &c {
                println!("+ {name}");
                succ += 1;
            } else {
                println!("- {name}");
                failed += 1;
            }
        }
        println!("{succ} succeeded, {failed} failed");
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_decrypt() {
        let mut failed = 0;
        let mut succ = 0;
        for (k, n, ads, tau, m, c) in testvectors::ENCRYPT_VECTORS {
            let name = format!("decrypt({k}, {n}, {ads:?}, {tau}, {c})");
            let k = hex::decode(k).unwrap();
            let k = k.as_slice().try_into().unwrap();
            let n = hex::decode(n).unwrap();

            let mut ad = Vec::new();
            for i in *ads {
                ad.push(hex::decode(i).unwrap());
            }
            let ad = ad.iter().map(Vec::as_slice).collect::<Vec<_>>();

            let m = hex::decode(m).unwrap();
            let c = hex::decode(c).unwrap();

            if vec_decrypt(&k, &n, &ad, *tau, &c) == Some(m) {
                println!("+ {name}");
                succ += 1;
            } else {
                println!("- {name}");
                failed += 1;
            }
        }
        println!("{succ} succeeded, {failed} failed");
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let aez = Aez::new(b"foobar");
        let cipher = aez.encrypt(&[0], &[b"foobar"], 16, b"hi");
        let plain = aez.decrypt(&[0], &[b"foobar"], 16, &cipher).unwrap();
        assert_eq!(plain, b"hi");
    }

    #[test]
    fn test_encrypt_decrypt_inplace() {
        let mut buffer = Vec::from(PLAIN);
        let aez = Aez::new(b"foobar");
        aez.encrypt_inplace(&[0], &[], 16, &mut buffer);
        let plain = aez.decrypt_inplace(&[0], &[], 16, &mut buffer).unwrap();
        assert_eq!(plain, &PLAIN[..PLAIN.len() - 16]);
    }

    #[test]
    fn test_encrypt_decrypt_buffer() {
        let mut output = vec![0; PLAIN.len() + 16];
        let aez = Aez::new(b"foobar");
        aez.encrypt_buffer(&[0], &[], PLAIN, &mut output);
        let plain = aez.decrypt_inplace(&[0], &[], 16, &mut output).unwrap();
        assert_eq!(plain, PLAIN);
    }

    #[test]
    fn test_encrypt_decrypt_long() {
        let message = b"ene mene miste es rappelt in der kiste ene mene meck und du bist weg";
        let aez = Aez::new(b"foobar");
        let cipher = aez.encrypt(&[0], &[b"foobar"], 16, message);
        let plain = aez.decrypt(&[0], &[b"foobar"], 16, &cipher).unwrap();
        assert_eq!(plain, message);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let aez = Aez::new(b"jimbo");
        let hash = aez.encrypt(&[0], &[b"foobar"], 16, b"");

        assert!(aez.decrypt(&[0], &[b"foobar"], 16, &hash).is_some());
        assert!(aez.decrypt(&[0], &[b"boofar"], 16, &hash).is_none());
    }

    #[test]
    fn test_fuzzed_1() {
        let aez = Aez::new(b"");
        aez.encrypt(b"", &[], 2220241, &[0]);
    }

    #[test]
    fn test_fuzzed_2() {
        let aez = Aez::new(b"");
        aez.encrypt(b"", &[], 673261693, &[]);
    }

    #[test]
    fn test_fuzzed_3() {
        // AEZ crashes if given an empty message and empty tau
        let aez = Aez::new(&[0, 110, 109, 0]);
        let value = aez.encrypt(&[0], &[], 0, &[]);
        assert_eq!(&value, &[]);
    }
}
