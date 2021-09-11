use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Zero;
use std::convert::TryInto;

lazy_static! {
    static ref P: BigUint = (BigUint::from_bytes_le(&[1u8]) << 130) - 5u8;
}

pub fn poly1305_mac(msg: &[u8], key: [u8; 32]) -> [u8; 16] {
    let r: [u8; 16] = key[0..16]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let r = BigUint::from_bytes_be(&clamp(r));
    let s = BigUint::from_bytes_le(&key[16..32]);
    let a: BigUint = msg.chunks(16).into_iter().fold(Zero::zero(), |acc, c| {
        let mut b = c.to_vec();
        b.push(1u8);
        let block = BigUint::from_bytes_le(b.as_slice());

        (acc + block) * r.clone() % P.clone()
    });

    let mut res: Vec<u8> = (a + s).to_bytes_le();
    res.resize(16, 0);
    res.try_into().unwrap()
}

fn clamp(r: [u8; 16]) -> [u8; 16] {
    let mask = [
        0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff,
        0xff,
    ];

    r.iter()
        .zip(mask.iter())
        .map(|x| x.0 & x.1)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly1305_mac() {
        // https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg: &[u8] = &[
            0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20,
            0x46, 0x6f, 0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
            0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
        ];
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        assert_eq!(poly1305_mac(msg, key), expected);
    }
}
