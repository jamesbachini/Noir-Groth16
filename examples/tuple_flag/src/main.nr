fn main(input: (Field, Field, bool), expected: pub Field) {
    let (a, b, flag) = input;

    let mut out = a + b;
    if flag {
        out += 1;
    }

    assert(out == expected);
}
