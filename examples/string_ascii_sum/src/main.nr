fn main(msg: str<5>, expected: pub Field) {
    let bytes = msg.as_bytes();
    let mut acc = 0 as Field;

    for i in 0..5 {
        acc += bytes[i] as Field;
    }

    assert(acc == expected);
}
