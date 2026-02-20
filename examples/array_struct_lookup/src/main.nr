struct Entry {
    balance: u32,
    active: bool,
}

fn main(entries: [Entry; 3], idx: u32, expected: pub u32) {
    assert(idx < 3);
    let entry = entries[idx];
    assert(entry.active);
    assert(entry.balance == expected);
}
