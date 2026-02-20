fn double(x: Field) -> Field {
    x + x
}

fn mix(a: Field, b: Field) -> Field {
    let t = double(a);
    t * b + 3
}

fn main(a: Field, b: pub Field, expected: pub Field) {
    let result = mix(a, b);
    assert(result == expected);
}
