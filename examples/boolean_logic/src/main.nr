fn main(p: bool, q: bool, expected_and: pub bool, expected_or: pub bool, expected_xor: pub bool) {
    assert((p & q) == expected_and);
    assert((p | q) == expected_or);
    assert((p ^ q) == expected_xor);
}
