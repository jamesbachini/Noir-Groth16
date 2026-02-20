fn main(values: [Field; 4], expected: pub Field) {
    let mut acc = 0 as Field;
    for i in 0..4 {
        acc += values[i];
    }
    assert(acc == expected);
}
