use std::convert::{TryFrom, TryInto};

const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a + b;
    let d = d ^ a;
    let d = d << 16;

    let c = c + d;
    let b = b ^ c;
    let b = b << 12;

    let a = a + b;
    let d = d ^ a;
    let d = d << 8;

    let c = c + d;
    let b = b ^ c;
    let b = b << 7;

    (a, b, c, d)
}

fn inner_block(x: [u32; 16]) -> [u32; 16] {
    let (y0, y1, y2, y3) = quarter_round(x[0], x[4], x[8], x[12]);
    let (y4, y5, y6, y7) = quarter_round(x[1], x[5], x[9], x[13]);
    let (y8, y9, y10, y11) = quarter_round(x[2], x[6], x[10], x[14]);
    let (y12, y13, y14, y15) = quarter_round(x[3], x[7], x[11], x[15]);

    let (z0, z1, z2, z3) = quarter_round(y0, y5, y10, y15);
    let (z4, z5, z6, z7) = quarter_round(y1, y6, y11, y12);
    let (z8, z9, z10, z11) = quarter_round(y2, y7, y8, y13);
    let (z12, z13, z14, z15) = quarter_round(y3, y4, y9, y14);

    [
        z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15,
    ]
}

fn little_endian(slice: [u8; 4]) -> u32 {
    ((slice[3] as u32) << 24)
        + ((slice[2] as u32) << 16)
        + ((slice[1] as u32) << 8)
        + (slice[0] as u32)
}

pub fn chacha20_block(key: [u8; 32], counter: u32, nonce: [u8; 12]) -> [u8; 128] {
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
        working_state[i] =
            TryFrom::try_from((u64::from(working_state[i]) + u64::from(state[i])) % 0x100000000u64)
                .unwrap();
    }

    let res: Vec<u8> = working_state.iter().flat_map(|x| x.to_be_bytes()).collect();
    res.try_into().unwrap()
}
