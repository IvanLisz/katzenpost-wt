use super::block::Block;

#[cfg(target_arch = "x86_64")]
pub type AesImpl = x86_64::AesNi;

#[cfg(not(target_arch = "x86_64"))]
pub type AesImpl = AesSoft;

pub trait AesRound {
    fn new(key_i: Block, key_j: Block, key_l: Block) -> Self;
    fn aes4(&self, value: Block) -> Block;
    fn aes10(&self, value: Block) -> Block;
}

/// Implementation of aes4 and aes10 in software.
///
/// Always available.
///
/// Uses the `aes` crate under the hood.
pub struct AesSoft {
    key_i: aes::Block,
    key_j: aes::Block,
    key_l: aes::Block,
}

impl AesRound for AesSoft {
    fn new(key_i: Block, key_j: Block, key_l: Block) -> Self {
        Self {
            key_i: key_i.bytes().into(),
            key_j: key_j.bytes().into(),
            key_l: key_l.bytes().into(),
        }
    }

    fn aes4(&self, value: Block) -> Block {
        let mut block: aes::Block = value.bytes().into();
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &Block::null().bytes().into());
        <Block as From<[u8; 16]>>::from(block.into())
    }

    fn aes10(&self, value: Block) -> Block {
        let mut block: aes::Block = value.bytes().into();
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        <Block as From<[u8; 16]>>::from(block.into())
    }
}

// It feels silly re-implementing the native AES instruction (especially since aes does use it
// under the hood), but there is a big benefit here:
// First, we can save time by only loading the keys once as a __m128i, which makes the whole thing
// a bit faster.
// More importantly though, when using target-cpu=native, we get nicely vectorized AES instructions
// (VAESENC), which we don't get if we go through aes::hazmat::cipher_round. This is a *huge*
// speedup, which we don't want to miss.
#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    use super::*;
    use core::arch::x86_64::*;

    cpufeatures::new!(cpuid_aes, "aes");

    pub struct AesNi {
        support: cpuid_aes::InitToken,
        fallback: AesSoft,
        key_i: __m128i,
        key_j: __m128i,
        key_l: __m128i,
        null: __m128i,
    }

    #[cfg(feature = "simd")]
    fn to_simd(block: Block) -> __m128i {
        block.simd().into()
    }

    #[cfg(not(feature = "simd"))]
    fn to_simd(block: Block) -> __m128i {
        let bytes = block.bytes();
        // SAFETY: loadu can load from unaligned memory
        unsafe { _mm_loadu_si128(bytes.as_ptr() as *const _) }
    }

    #[cfg(feature = "simd")]
    fn from_simd(simd: __m128i) -> Block {
        Block::from_simd(simd.into())
    }

    #[cfg(not(feature = "simd"))]
    fn from_simd(simd: __m128i) -> Block {
        let mut bytes = [0; 16];
        // SAFETY: storeu can store to unaligned memory
        unsafe {
            _mm_storeu_si128(bytes.as_mut_ptr() as *mut _, simd);
        }
        Block::from(bytes)
    }

    impl AesRound for AesNi {
        fn new(key_i: Block, key_j: Block, key_l: Block) -> Self {
            Self {
                support: cpuid_aes::init(),
                fallback: AesSoft::new(key_i, key_j, key_l),
                key_i: to_simd(key_i),
                key_j: to_simd(key_j),
                key_l: to_simd(key_l),
                null: to_simd(Block::null()),
            }
        }

        fn aes4(&self, value: Block) -> Block {
            if !self.support.get() {
                return self.fallback.aes4(value);
            }

            // SAFETY: Nothing should go wrong when calling AESENC
            unsafe {
                let mut block = to_simd(value);
                block = _mm_aesenc_si128(block, self.key_j);
                block = _mm_aesenc_si128(block, self.key_i);
                block = _mm_aesenc_si128(block, self.key_l);
                block = _mm_aesenc_si128(block, self.null);
                from_simd(block)
            }
        }

        fn aes10(&self, value: Block) -> Block {
            if !self.support.get() {
                return self.fallback.aes10(value);
            }

            // SAFETY: Nothing should go wrong when calling AESENC
            unsafe {
                let mut block = to_simd(value);
                block = _mm_aesenc_si128(block, self.key_i);
                block = _mm_aesenc_si128(block, self.key_j);
                block = _mm_aesenc_si128(block, self.key_l);
                block = _mm_aesenc_si128(block, self.key_i);
                block = _mm_aesenc_si128(block, self.key_j);
                block = _mm_aesenc_si128(block, self.key_l);
                block = _mm_aesenc_si128(block, self.key_i);
                block = _mm_aesenc_si128(block, self.key_j);
                block = _mm_aesenc_si128(block, self.key_l);
                block = _mm_aesenc_si128(block, self.key_i);
                from_simd(block)
            }
        }
    }
}
