// Host reference for the PBKDF2 probe: the same entropy -> mnemonic -> seed("") through the same crate.
fn main() {
    let m = sphincs_tz_bip39::Mnemonic::from_entropy(b"c10-autoresearch bip39 entropy!!");
    println!("{}", hex::encode(m.to_seed("")));
}
