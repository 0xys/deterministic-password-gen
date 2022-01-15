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
            let (found_at, value_at) = next_from_single_char(word[i], self.max_index, self.mask, self.mask_size);
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


}

/// try get next character from a single u8 char.
fn next_from_single_char(byte: u8, max_index: u8, mask: u8, mask_size: usize) -> (bool, u8) {
    let mut current = byte;
    let mut found = false;
    let mut value: u8 = 0;

    for _ in 0..8/mask_size {
        let tmp = current & mask;
        if !found && tmp <= max_index {
            found = true;
            value = tmp;
        }

        if mask_size >= 8 {
            break;
        }

        current = current >> mask_size;
    }
    
    (found, value)
}

fn get_mask(max_index: u8) -> (u8, usize) {
    let mut mask: u8 = 0b_0000_0000;
    let mut count = 0;

    if max_index == 0 {
        return (mask, count)
    }

    let mut current = max_index;
    loop {
        mask = mask << 1;
        mask |= 0x01;
        count += 1;

        current = current >> 1;
        if current & 0b_1111_1111 == 0 {
            break;
        }
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

#[test]
fn test_get_mask_trivial_case() {
    {
        let (mask, mask_size) = get_mask(0b_0000_0000);
        assert_eq!(mask, 0);
        assert_eq!(mask_size, 0);
    }

    {
        let (mask, mask_size) = get_mask(0b_0000_0001);
        assert_eq!(mask, 1);
        assert_eq!(mask_size, 1);
    }
}

#[test]
fn test_get_mask() {
    {
        let (mask, mask_size) = get_mask(0b_0000_0010);
        assert_eq!(mask, 0b_0000_0011);
        assert_eq!(mask_size, 2);
    }
    {
        let (mask, mask_size) = get_mask(0b_0000_0011);
        assert_eq!(mask, 0b_0000_0011);
        assert_eq!(mask_size, 2);
    }
    {
        let (mask, mask_size) = get_mask(0b_0000_0101);
        assert_eq!(mask, 0b_0000_0111);
        assert_eq!(mask_size, 3);
    }
    {
        let (mask, mask_size) = get_mask(0b_0001_0101);
        assert_eq!(mask, 0b_0001_1111);
        assert_eq!(mask_size, 5);
    }
    {
        let (mask, mask_size) = get_mask(0b_0101_0101);
        assert_eq!(mask, 0b_0111_1111);
        assert_eq!(mask_size, 7);
    }
    {
        let (mask, mask_size) = get_mask(0b_1101_0101);
        assert_eq!(mask, 0b_1111_1111);
        assert_eq!(mask_size, 8);
    }
}

#[test]
fn test_single_byte_2() {
    let max = 0b_10;
    let mask = 0b_11;
    let mask_size = 2;
    {
        let byte = 0b_0000_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(1, value);
    }
    {
        let byte = 0b_0000_0100;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0, value);
    }
    {
        let byte = 0b_0000_0010;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_10, value);
    }
    {
        let byte = 0b_0000_0111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(1, value);
    }
    {
        let byte = 0b_0000_0011;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0, value);
    }
    {
        let byte = 0b_0000_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0, value);
    }
    {
        let byte = 0b_0010_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_10, value);
    }
    {
        let byte = 0b_0011_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0, value);
    }
    {
        let byte = 0b_1111_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }
}

#[test]
fn test_single_byte_3(){
    let max = 0b_110;
    let mask = 0b_111;
    let mask_size = 3;
    {
        let byte = 0b_0000_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(1, value);
    }
    {
        let byte = 0b_0000_0101;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_101, value);
    }
    {
        let byte = 0b_0000_0111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0, value);
    }
    {
        let byte = 0b_0001_0111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_10, value);
    }
    {
        let byte = 0b_0001_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_11, value);
    }
    {
        let byte = 0b_0011_1011;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_011, value);
    }
    {
        let byte = 0b_0011_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }
}

#[test]
fn test_single_byte_4(){
    let max = 0b_1110;
    let mask = 0b_1111;
    let mask_size = 4;
    {
        let byte = 0b_0000_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(1, value);
    }
    {
        let byte = 0b_0000_0011;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_11, value);
    }
    {
        let byte = 0b_0000_1011;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_1011, value);
    }
    {
        let byte = 0b_0000_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0, value);
    }
    {
        let byte = 0b_0011_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_11, value);
    }
    {
        let byte = 0b_0111_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_111, value);
    }
    {
        let byte = 0b_0110_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_110, value);
    }
    {
        let byte = 0b_1111_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }
}

#[test]
fn test_single_byte_5(){
    let max = 0b_1_1110;
    let mask = 0b_1_1111;
    let mask_size = 5;
    {
        let byte = 0b_0000_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(1, value);
    }
    {
        let byte = 0b_0000_0101;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_101, value);
    }
    {
        let byte = 0b_0001_0101;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_1_0101, value);
    }
    {
        let byte = 0b_0001_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }
}

#[test]
fn test_single_byte_6(){
    let max = 0b_11_1110;
    let mask = 0b_11_1111;
    let mask_size = 6;
    {
        let byte = 0b_0000_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(1, value);
    }
    {
        let byte = 0b_0001_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_0001_0001, value);
    }
    {
        let byte = 0b_0011_0001;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_0011_0001, value);
    }
    {
        let byte = 0b_0011_0101;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(0b_0011_0101, value);
    }
    {
        let byte = 0b_0011_1111;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }
}

#[test]
fn test_single_byte_8(){
    let max = 134;
    let mask = 0b_1111_1111;
    let mask_size = 8;
    {
        let byte = 122;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(122, value);
    }
    {
        let byte = 54;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(54, value);
    }
    {
        let byte = 134;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(134, value);
    }
    {
        let byte = 135;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }

    let max = 240;
    let mask = 0b_1111_1111;
    let mask_size = 8;
    {
        let byte = 122;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(122, value);
    }
    {
        let byte = 237;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(237, value);
    }
    {
        let byte = 240;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(true, found);
        assert_eq!(240, value);
    }
    {
        let byte = 241;
        let (found, value) = next_from_single_char(byte, max, mask, mask_size);
        assert_eq!(false, found);
        assert_eq!(0, value);
    }
}