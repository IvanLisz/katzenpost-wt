use std::ops::{BitAnd, BitOr, BitXor, Index, IndexMut, Mul, Shl, Shr};
#[cfg(feature = "simd")]
use std::simd::prelude::*;

/// A block, the unit of work that AEZ divides the message into.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg(feature = "simd")]
pub struct Block(u8x16);

/// A block, the unit of work that AEZ divides the message into.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg(not(feature = "simd"))]
pub struct Block([u8; 16]);

impl Block {
    pub fn null() -> Block {
        Block([0; 16].into())
    }

    pub fn one() -> Block {
        Block([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into())
    }

    pub fn bytes(&self) -> [u8; 16] {
        self.0.into()
    }

    pub fn write_to(&self, output: &mut [u8; 16]) {
        #[cfg(feature = "simd")]
        self.0.copy_to_slice(output);

        #[cfg(not(feature = "simd"))]
        output.copy_from_slice(&self.0);
    }

    #[cfg(feature = "simd")]
    pub(crate) fn simd(&self) -> u8x16 {
        self.0
    }

    #[cfg(feature = "simd")]
    pub(crate) fn from_simd(value: u8x16) -> Self {
        Block(value)
    }

    /// Create a block from a slice.
    ///
    /// If the slice is too long, it will be truncated. If the slice is too short, the remaining
    /// items are set to 0.
    pub fn from_slice(value: &[u8]) -> Self {
        let len = value.len().min(16);
        let mut array = [0; 16];
        array[..len].copy_from_slice(&value[..len]);
        Block(array.into())
    }

    /// Constructs a block representing the given integer.
    ///
    /// This corresponds to [x]_128 in the paper.
    pub fn from_int<I: Into<u128>>(value: I) -> Self {
        Block(value.into().to_be_bytes().into())
    }

    pub fn to_int(&self) -> u128 {
        u128::from_be_bytes(self.0.into())
    }

    /// Pad the block to full length.
    ///
    /// The given length is the current length.
    ///
    /// This corresponds to X10* in the paper.
    pub fn pad(&self, length: usize) -> Block {
        assert!(length <= 127);
        let mut result = *self;
        result[length / 8] |= 1 << (7 - length % 8);
        result
    }

    /// Clip the block by setting all bits beyond the given length to 0.
    pub fn clip(&self, length: usize) -> Block {
        match length {
            0 => Block::default(),
            _ => Block::from_int(self.to_int() & (u128::MAX << (128 - length))),
        }
    }

    /// Computes self * 2^exponent
    ///
    /// Ensures that there's no overflow in computing 2^exponent.
    pub fn exp(&self, exponent: u32) -> Block {
        match exponent {
            _ if exponent < 32 => *self * (1 << exponent),
            _ if exponent % 2 == 0 => self.exp(exponent / 2).exp(exponent / 2),
            _ => (*self * 2).exp(exponent - 1),
        }
    }
}

impl From<[u8; 16]> for Block {
    fn from(value: [u8; 16]) -> Block {
        Block(value.into())
    }
}

impl From<&[u8; 16]> for Block {
    fn from(value: &[u8; 16]) -> Block {
        Block((*value).into())
    }
}

impl From<u128> for Block {
    fn from(value: u128) -> Block {
        Block(value.to_be_bytes().into())
    }
}

impl BitXor<Block> for Block {
    type Output = Block;
    #[cfg(feature = "simd")]
    fn bitxor(self, rhs: Block) -> Block {
        Block(self.0 ^ rhs.0)
    }

    #[cfg(not(feature = "simd"))]
    fn bitxor(self, rhs: Block) -> Block {
        // We unroll here because XOR is by far the operation that is used the most, and the
        // int-conversion/bit-operation/int-conversion way is slower (but easier to write)
        Block([
            self.0[0] ^ rhs.0[0],
            self.0[1] ^ rhs.0[1],
            self.0[2] ^ rhs.0[2],
            self.0[3] ^ rhs.0[3],
            self.0[4] ^ rhs.0[4],
            self.0[5] ^ rhs.0[5],
            self.0[6] ^ rhs.0[6],
            self.0[7] ^ rhs.0[7],
            self.0[8] ^ rhs.0[8],
            self.0[9] ^ rhs.0[9],
            self.0[10] ^ rhs.0[10],
            self.0[11] ^ rhs.0[11],
            self.0[12] ^ rhs.0[12],
            self.0[13] ^ rhs.0[13],
            self.0[14] ^ rhs.0[14],
            self.0[15] ^ rhs.0[15],
        ])
    }
}

impl Shl<u32> for Block {
    type Output = Block;
    fn shl(self, rhs: u32) -> Block {
        // We often use a shift by one, for example in the multiplication. We therefore optimize
        // for this special case.
        #[cfg(feature = "simd")]
        {
            if rhs == 1 {
                return Block((self.0 << 1) | (self.0.shift_elements_left::<1>(0) >> 7));
            }
        }
        Block::from(self.to_int() << rhs)
    }
}

impl Shr<u32> for Block {
    type Output = Block;
    fn shr(self, rhs: u32) -> Block {
        Block::from(self.to_int() >> rhs)
    }
}

impl BitAnd<Block> for Block {
    type Output = Block;
    fn bitand(self, rhs: Block) -> Block {
        #[cfg(feature = "simd")]
        {
            Block(self.0 & rhs.0)
        }

        #[cfg(not(feature = "simd"))]
        {
            Block::from(self.to_int() & rhs.to_int())
        }
    }
}

impl BitOr<Block> for Block {
    type Output = Block;
    fn bitor(self, rhs: Block) -> Block {
        #[cfg(feature = "simd")]
        {
            Block(self.0 | rhs.0)
        }

        #[cfg(not(feature = "simd"))]
        {
            Block::from(self.to_int() | rhs.to_int())
        }
    }
}

impl Index<usize> for Block {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl IndexMut<usize> for Block {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        &mut self.0[index]
    }
}

impl Mul<u32> for Block {
    type Output = Block;
    fn mul(self, rhs: u32) -> Block {
        match rhs {
            0 => Block::null(),
            1 => self,
            2 => {
                let mut result = self << 1;
                if self[0] & 0x80 != 0 {
                    result[15] ^= 0x87;
                }
                result
            }
            _ if rhs % 2 == 0 => self * 2 * (rhs / 2),
            _ => self * (rhs - 1) ^ self,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_xor() {
        assert_eq!(
            Block::from([1; 16]) ^ Block::from([2; 16]),
            Block::from([3; 16])
        );
    }

    #[test]
    fn test_pad() {
        assert_eq!(
            Block::from([0; 16]).pad(0),
            Block::from([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(
            Block::from([0; 16]).pad(1),
            Block::from([0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(
            Block::from([0; 16]).pad(8),
            Block::from([0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
    }

    #[test]
    fn test_shl() {
        assert_eq!(
            Block::from([0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) << 1,
            Block::from([0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(
            Block::from([0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) << 4,
            Block::from([0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(
            Block::from([0x0A, 0xB0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) << 4,
            Block::from([0xAB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(
            Block::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) << 8,
            Block::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
        );
    }

    #[test]
    fn test_times() {
        assert_eq!(
            Block::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) * 0,
            Block::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assert_eq!(
            Block::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) * 1,
            Block::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        );
        assert_eq!(
            Block::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) * 2,
            Block::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        );
        assert_eq!(
            Block::from([128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) * 2,
            Block::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133]),
        );
        assert_eq!(
            Block::from([129, 0, 0, 0, 0, 128, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1]) * 2,
            Block::from([2, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 133]),
        );
        assert_eq!(
            Block::from([129, 0, 0, 0, 0, 128, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1]) * 3,
            Block::from([131, 0, 0, 0, 1, 128, 0, 0, 0, 3, 0, 0, 0, 0, 0, 132]),
        );
        assert_eq!(
            Block::from([129, 0, 0, 0, 0, 128, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1]) * 4,
            Block::from([4, 0, 0, 0, 2, 0, 0, 0, 0, 4, 0, 0, 0, 0, 1, 10]),
        );
    }
}
