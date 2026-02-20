fn main(a: u8, b: u8, expected_and: pub u8, expected_xor: pub u8) {
    let anded = a & b;
    let xored = a ^ b;

    assert(anded == expected_and);
    assert(xored == expected_xor);
}
