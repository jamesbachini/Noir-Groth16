fn main(values: [u32; 5], count: u32, expected: pub u32) {
    assert(count <= 5);

    let mut acc: u32 = 0;
    for i in 0..5 {
        if i as u32 < count {
            acc += values[i];
        }
    }

    assert(acc == expected);
}
