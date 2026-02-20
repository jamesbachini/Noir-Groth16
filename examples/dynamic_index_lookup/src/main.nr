fn main(data: [Field; 4], idx: u32, expected: pub Field) {
    assert(idx < 4);
    let selected = data[idx];
    assert(selected == expected);
}
