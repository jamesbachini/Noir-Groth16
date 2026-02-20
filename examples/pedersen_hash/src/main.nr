use std::hash;

fn main(x: Field, y: Field, expected: pub Field) {
    let digest = hash::pedersen_hash([x, y]);
    assert(digest == expected);
}
