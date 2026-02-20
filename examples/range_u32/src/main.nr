fn main(x: u32, y: u32, limit: pub u32) {
    assert(x < limit);
    assert(y < limit);

    let sum = x + y;
    assert(sum < limit * 2);
}
