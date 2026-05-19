use super::block::Block;

pub struct BlockAccessor<'a> {
    data: &'a mut [u8],
    m_uv_len: usize,
    m_u_len: usize,
    m_v_len: usize,
    num_block_pairs: usize,
}

impl<'a> BlockAccessor<'a> {
    pub fn new(message: &'a mut [u8]) -> Self {
        let num_block_pairs = (message.len() - 16 - 16) / 32;
        let m_uv_len = (message.len() % 32) * 8;
        Self {
            data: message,
            m_uv_len,
            m_u_len: 128.min(m_uv_len),
            m_v_len: m_uv_len.saturating_sub(128),
            num_block_pairs,
        }
    }

    pub fn m_uv_len(&self) -> usize {
        self.m_uv_len
    }

    fn suffix_start(&self) -> usize {
        self.num_block_pairs * 32
    }

    pub fn m_u(&self) -> Block {
        let start = self.suffix_start();
        Block::from_slice(&self.data[start..start + self.m_u_len / 8])
    }

    pub fn set_m_u(&mut self, m_u: Block) {
        let start = self.suffix_start();
        self.data[start..start + self.m_u_len / 8]
            .copy_from_slice(&m_u.bytes()[..self.m_u_len / 8]);
    }

    pub fn m_v(&self) -> Block {
        let start = self.suffix_start();
        Block::from_slice(&self.data[start + self.m_u_len / 8..start + self.m_uv_len / 8])
    }

    pub fn set_m_v(&mut self, m_v: Block) {
        let start = self.suffix_start();
        self.data[start + self.m_u_len / 8..start + self.m_uv_len / 8]
            .copy_from_slice(&m_v.bytes()[..self.m_v_len / 8]);
    }

    pub fn m_x(&self) -> Block {
        let start = self.suffix_start() + self.m_uv_len / 8;
        Block::from_slice(&self.data[start..start + 16])
    }

    pub fn set_m_x(&mut self, m_x: Block) {
        let start = self.suffix_start() + self.m_uv_len / 8;
        self.data[start..start + 16].copy_from_slice(&m_x.bytes());
    }

    pub fn m_y(&self) -> Block {
        let start = self.suffix_start() + self.m_uv_len / 8;
        Block::from_slice(&self.data[start + 16..start + 32])
    }

    pub fn set_m_y(&mut self, m_y: Block) {
        let start = self.suffix_start() + self.m_uv_len / 8;
        self.data[start + 16..start + 32].copy_from_slice(&m_y.bytes());
    }

    pub fn pairs_mut<'b>(
        &'b mut self,
    ) -> impl Iterator<Item = (&'b mut [u8; 16], &'b mut [u8; 16])> {
        let stop = self.suffix_start();
        self.data[..stop]
            .chunks_exact_mut(32)
            .map(move |x| x.split_at_mut(16))
            .map(move |(x, y)| (x.try_into().unwrap(), y.try_into().unwrap()))
    }
}
