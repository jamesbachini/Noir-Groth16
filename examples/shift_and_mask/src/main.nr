fn main(x: u16, y: u16, expected: pub u16) {
    let mixed = ((x << 3) ^ (y >> 2)) & 0xff;
    assert(mixed == expected);
}
