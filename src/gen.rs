use sha2::{Sha256, Digest as Sha256Digest};
use std::convert::TryInto;

#[derive(Debug)]
enum CharacterGenerationError {
    ConsumedFullWordError
}

pub struct PasswordGenerator<'a> {
    mask: u8,
    mask_size: usize,
    max_index: u8,
    seed: &'a[u8]
}

impl<'a> PasswordGenerator<'a> {
    pub fn new(seed: &[u8], max_index: u8) -> PasswordGenerator {
        let (mask, mask_size) = get_mask(max_index);
        PasswordGenerator {
            mask,
            mask_size,
            max_index,
            seed,
        }
    }

    pub fn generate_assign(&self, output: &mut [u8]) {
        let mut current_index = 0;
        let mut nonce = 0;
        let mut current_offset = 0;
        while current_index < output.len() {
            let next_word = generate_word(self.seed, nonce);
            nonce += 1;
    
            loop {
                let result = self.next_from_word(&next_word, current_offset);
                if result.is_err() {
                    break;  // consumed full word
                }
    
                let (next_offset, character) = result.unwrap();
                output[current_index] = character;
                current_offset = next_offset;
                current_index += 1;
            }
        }
    }

    /// get next character from word.
    /// 
    /// returning `next_offset` and `next_character`
    fn next_from_word(&self, word: &[u8;32], offset: usize) -> Result<(usize, u8), CharacterGenerationError> {
        let mut next_offset = 0;
        let mut next_character: u8 = 0;
        let mut found = false;
        for i in offset..word.len() {
            let (found_at, value_at) = self.next_from_single_char(word[i]);
            if !found && found_at {
                next_offset = i + 1;
                next_character = value_at;
                found = true;
            }
        }

        if found {
            return Ok((next_offset, next_character));
        }

        Err(CharacterGenerationError::ConsumedFullWordError)
    }

    /// try get next character from a single u8 char.
    fn next_from_single_char(&self, byte: u8) -> (bool, u8) {
        let mut current = byte;
        let mut found = false;
        let mut value: u8 = 0;
    
        for _ in 0..8/self.mask_size {
            current = current >> self.mask_size;
            value = current & self.mask;
            if !found && value <= self.max_index {
                found = true;
            }
        }
        
        (found, value)
    }
}

fn get_mask(max_index: u8) -> (u8, usize) {
    let mut mask: u8 = 0b_0000_0000;
    let mut count = 0;
    while (max_index >> 1) & 0b_1111_1111 > 0 {
        mask = mask << 1;
        mask |= 0x01;
        count += 1;
    }
    (mask, count)
}

fn generate_word(seed: &[u8], nonce: usize) -> [u8;32] {
    let mut hasher = Sha256::new();
    let mut data = Vec::from(seed);
    for i in 0..nonce {
        let value: u8 = (i % 256).try_into().unwrap();
        data.push(value);
    }
    hasher.update(data.as_slice());
    let hashed = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hashed[..]);
    bytes
}