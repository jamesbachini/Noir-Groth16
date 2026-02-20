struct Account {
    balance: u32,
}

fn debit(account: &mut Account, amount: u32) {
    account.balance -= amount;
}

fn credit(account: &mut Account, amount: u32) {
    account.balance += amount;
}

fn main(start: u32, spend: pub u32) {
    assert(start >= spend);

    let mut buyer = Account { balance: start };
    let mut seller = Account { balance: start };

    debit(&mut buyer, spend);
    credit(&mut seller, spend);

    assert(buyer.balance == start - spend);
    assert(seller.balance == start + spend);
}
