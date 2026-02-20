use std::hash;

fn main(msg: [u8; 1], expected: pub [u8; 32]) {
    let digest = hash::blake2s(msg);
    assert(digest == expected);
}
