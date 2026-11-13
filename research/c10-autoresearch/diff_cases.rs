// Shared case generator for the differential (host reference on pristine master vs the research tree).
// Deterministic: case i derives key, message, opt_rand (Some or None) and shuffle seed from SHA-256("c10-diff" ‖ i).
fn case_bytes(i: u32, label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"c10-diff");
    h.update(i.to_le_bytes());
    h.update(label);
    h.finalize().into()
}
pub struct Case { pub sk_seed: [u8; 32], pub pk_seed: [u8; 16], pub msg: [u8; 32], pub opt_rand: Option<[u8; 16]>, pub shuffle: [u8; 32] }
pub fn case(i: u32, key_every: u32) -> Case {
    let k = i / key_every; // several messages per key
    let pk = case_bytes(k, b"pk");
    let r = case_bytes(i, b"rand");
    Case {
        sk_seed: case_bytes(k, b"sk"),
        pk_seed: pk[..16].try_into().unwrap(),
        msg: case_bytes(i, b"msg"),
        opt_rand: if i % 3 == 2 { None } else { Some(r[..16].try_into().unwrap()) },
        shuffle: case_bytes(i, b"shuffle"),
    }
}
