/// Variable length hex string to byte array
pub fn bts(b: &[u8]) -> String {
    let hex_chars: Vec<char> = "0123456789abcdef".chars().collect();
    let mut encoded = String::with_capacity(b.len() * 2);
    for byte in b {
        encoded.push(hex_chars[(byte >> 4) as usize]);
        encoded.push(hex_chars[(byte & 0xf) as usize]);
    }
    encoded
}

/// Hex string to fixed size byte array
pub fn stb_fixed<const LEN: usize>(s: &str) -> Option<[u8; LEN]> {
    if s.len() != LEN * 2 {
        return None;
    }

    let mut bytes = [0u8; LEN];
    let mut byte_index = 0;

    for chunk in s.as_bytes().chunks(2) {
        let mut byte = 0u8;

        for &hex_char in chunk {
            byte <<= 4;
            byte |= match hex_char {
                b'0'..=b'9' => hex_char - b'0',
                b'a'..=b'f' => 10 + hex_char - b'a',
                b'A'..=b'F' => 10 + hex_char - b'A',
                _ => return None, // Invalid character for hex representation
            };
        }

        bytes[byte_index] = byte;
        byte_index += 1;
    }

    Some(bytes)
}

/// Hex string to variable length byte array
pub fn stb(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut byte = 0u8;

    for (i, &hex_char) in s.as_bytes().iter().enumerate() {
        byte <<= 4;
        byte |= match hex_char {
            b'0'..=b'9' => hex_char - b'0',
            b'a'..=b'f' => 10 + hex_char - b'a',
            b'A'..=b'F' => 10 + hex_char - b'A',
            _ => return None, // Invalid character for hex representation
        };

        if i % 2 == 1 {
            bytes.push(byte);
            byte = 0;
        }
    }

    Some(bytes)
}
