use std::hash::sha256;

// ---- Types ----
type Hash32 = [u8; 32];
type Sig64   = [u8; 64];

const MERKLE_DEPTH: usize = 16;

// ---- Structs ----
struct PaymentMessage {
    amount: u32,
    expiry: u32,
    recipient: Hash32,
}

// ---- Hash Helpers ----
fn u32_to_be_bytes(x: u32) -> [u8; 4] {
    [
        (x >> 24) as u8,
        (x >> 16) as u8,
        (x >>  8) as u8,
        (x >>  0) as u8,
    ]
}

fn tagged_hash_2x32(tag: [u8; 4], a: Hash32, b: Hash32) -> Hash32 {
    let mut buf: [u8; 68] = [0; 68];
    for i in 0..4 { buf[i] = tag[i]; }
    for i in 0..32 { buf[4 + i] = a[i]; }
    for i in 0..32 { buf[36 + i] = b[i]; }
    sha256(buf)
}

// ---- Signature Commitment / Nullifier ----
fn commit_signature(sig: Sig64, nonce: Hash32) -> Hash32 {
    let mut buf: [u8; 100] = [0; 100];
    let tag: [u8; 4] = *b"SIGC";
    for i in 0..4 { buf[i] = tag[i]; }
    for i in 0..32 { buf[4 + i] = nonce[i]; }
    for i in 0..64 { buf[36 + i] = sig[i]; }
    sha256(buf)
}

fn make_nullifier(sig_commitment: Hash32, context: Hash32) -> Hash32 {
    tagged_hash_2x32(*b"NULL", sig_commitment, context)
}

// ---- Message Hashing ----
fn hash_payment_message(m: PaymentMessage) -> Hash32 {
    let mut buf: [u8; 44] = [0; 44];
    let tag: [u8; 4] = *b"PAYM";
    for i in 0..4 { buf[i] = tag[i]; }

    let amt = u32_to_be_bytes(m.amount);
    let exp = u32_to_be_bytes(m.expiry);

    for i in 0..4 { buf[4 + i] = amt[i]; }
    for i in 0..4 { buf[8 + i] = exp[i]; }
    for i in 0..32 { buf[12 + i] = m.recipient[i]; }

    sha256(buf)
}

// ---- Merkle Proof Helpers ----
fn hash_pair(left: Hash32, right: Hash32) -> Hash32 {
    tagged_hash_2x32(*b"NODE", left, right)
}

fn verify_merkle_membership(
    root: Hash32,
    leaf: Hash32,
    siblings: [Hash32; MERKLE_DEPTH],
    index_bits: [bool; MERKLE_DEPTH],
) -> bool {
    let mut acc = leaf;
    for i in 0..MERKLE_DEPTH {
        let (l, r) = if index_bits[i] {
            (siblings[i], acc)
        } else {
            (acc, siblings[i])
        };
        acc = hash_pair(l, r);
    }
    acc == root
}

fn pubkey_leaf(pub_key_x: [u8;32], pub_key_y: [u8;32]) -> Hash32 {
    let mut buf: [u8; 68] = [0; 68];
    let tag: [u8;4] = *b"PKY0";
    for i in 0..4 { buf[i] = tag[i]; }
    for i in 0..32 { buf[4 + i] = pub_key_x[i]; }
    for i in 0..32 { buf[36 + i] = pub_key_y[i]; }
    sha256(buf)
}

// ---- Main Circuit ----
fn main(
    // Public
    msg_hash: Hash32,
    pub_key_x: [u8;32],
    pub_key_y: [u8;32],
    sig_commitment: Hash32,
    allowlist_root: Hash32,
    nullifier: Hash32,
    amount: u32,

    // Private
    sig: Sig64,
    nonce: Hash32,
    recipient: Hash32,
    expiry: u32,
    context: Hash32,
    merkle_siblings: [Hash32; MERKLE_DEPTH],
    merkle_index_bits: [bool; MERKLE_DEPTH],
) {
    assert(amount > 0);
    assert(amount <= 1_000_000u32);
    assert(expiry > 0);

    let m = PaymentMessage { amount, expiry, recipient };
    let recomputed = hash_payment_message(m);
    assert(recomputed == msg_hash);

    let valid_sig = std::ecdsa_secp256k1::verify_signature(
        pub_key_x,
        pub_key_y,
        sig,
        msg_hash,
    );
    assert(valid_sig);

    let got_commit = commit_signature(sig, nonce);
    assert(got_commit == sig_commitment);

    let got_null = make_nullifier(sig_commitment, context);
    assert(got_null == nullifier);

    let leaf = pubkey_leaf(pub_key_x, pub_key_y);
    let in_allowlist = verify_merkle_membership(
        allowlist_root,
        leaf,
        merkle_siblings,
        merkle_index_bits,
    );
    assert(in_allowlist);
}