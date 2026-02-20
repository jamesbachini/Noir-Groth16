use std::hash;

fn main(input: [Field; 4], expected: pub Field) {
    let state = hash::poseidon2_permutation(input, 4);
    assert(state[0] == expected);
}
