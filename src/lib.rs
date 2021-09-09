use std::convert::TryInto;

const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b);
    let d = d ^ a;
    let d = d.rotate_left(16);

    let c = c.wrapping_add(d);
    let b = b ^ c;
    let b = b.rotate_left(12);

    let a = a.wrapping_add(b);
    let d = d ^ a;
    let d = d.rotate_left(8);

    let c = c.wrapping_add(d);
    let b = b ^ c;
    let b = b.rotate_left(7);

    (a, b, c, d)
}

fn inner_block(x: [u32; 16]) -> [u32; 16] {
    let (y0, y4, y8, y12) = quarter_round(x[0], x[4], x[8], x[12]);
    let (y1, y5, y9, y13) = quarter_round(x[1], x[5], x[9], x[13]);
    let (y2, y6, y10, y14) = quarter_round(x[2], x[6], x[10], x[14]);
    let (y3, y7, y11, y15) = quarter_round(x[3], x[7], x[11], x[15]);

    let (z0, z5, z10, z15) = quarter_round(y0, y5, y10, y15);
    let (z1, z6, z11, z12) = quarter_round(y1, y6, y11, y12);
    let (z2, z7, z8, z13) = quarter_round(y2, y7, y8, y13);
    let (z3, z4, z9, z14) = quarter_round(y3, y4, y9, y14);

    [
        z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15,
    ]
}

fn little_endian(arr: [u8; 4]) -> u32 {
    (u32::from(arr[3]) << 24)
        + (u32::from(arr[2]) << 16)
        + (u32::from(arr[1]) << 8)
        + u32::from(arr[0])
}

pub fn chacha20_block(key: [u8; 32], counter: u32, nonce: [u8; 12]) -> [u8; 64] {
    let state: [u32; 16] = [
        CONSTANTS[0],
        CONSTANTS[1],
        CONSTANTS[2],
        CONSTANTS[3],
        little_endian([key[0], key[1], key[2], key[3]]),
        little_endian([key[4], key[5], key[6], key[7]]),
        little_endian([key[8], key[9], key[10], key[11]]),
        little_endian([key[12], key[13], key[14], key[15]]),
        little_endian([key[16], key[17], key[18], key[19]]),
        little_endian([key[20], key[21], key[22], key[23]]),
        little_endian([key[24], key[25], key[26], key[27]]),
        little_endian([key[28], key[29], key[30], key[31]]),
        counter,
        little_endian([nonce[0], nonce[1], nonce[2], nonce[3]]),
        little_endian([nonce[4], nonce[5], nonce[6], nonce[7]]),
        little_endian([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    let mut working_state: [u32; 16] = [0; 16];
    working_state.copy_from_slice(&state);

    for _ in (0..10).rev() {
        working_state = inner_block(working_state);
    }

    for i in (0..16).rev() {
        working_state[i] = working_state[i].wrapping_add(state[i])
    }

    let res: Vec<u8> = working_state.iter().flat_map(|x| x.to_be_bytes()).collect();
    res.try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarter_round() {
        assert_eq!(
            quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567),
            (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
        );
    }

    #[test]
    fn test_chacha20_block() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;
        let expected: [u8; 64] = [
            0xe4, 0xe7, 0xf1, 0x10, 0x15, 0x59, 0x3b, 0xd1, 0x1f, 0xdd, 0x0f, 0x50, 0xc4, 0x71,
            0x20, 0xa3, 0xc7, 0xf4, 0xd1, 0xc7, 0x03, 0x68, 0xc0, 0x33, 0x9a, 0xaa, 0x22, 0x04,
            0x4e, 0x6c, 0xd4, 0xc3, 0x46, 0x64, 0x82, 0xd2, 0x09, 0xaa, 0x9f, 0x07, 0x05, 0xd7,
            0xc2, 0x14, 0xa2, 0x02, 0x8b, 0xd9, 0xd1, 0x9c, 0x12, 0xb5, 0xb9, 0x4e, 0x16, 0xde,
            0xe8, 0x83, 0xd0, 0xcb, 0x4e, 0x3c, 0x50, 0xa2,
        ];

        assert_eq!(chacha20_block(key, counter, nonce), expected);
    }
}
