//! Run with debug assertions both enabled and disabled, including lean_extract.
//! Host/software-backend behavior only; this does not execute the secure wrapper.
use sphincs_c10::{verify, SigningKey};

#[test]
fn generated_key_and_caller_supplied_wrong_root() {
    let sk_seed = [0x35; 32];
    let pk_seed = [0x91; 16];
    let msg = [0x73; 32];
    let random = [0x28; 16];
    let key = SigningKey::keygen(sk_seed, pk_seed);
    for opt in [None, Some(&random)] {
        let sig = key.sign(&msg, opt);
        assert!(verify(key.pk_seed(), key.pk_root(), &msg, &sig));
        let mut changed_msg = msg;
        changed_msg[0] ^= 1;
        assert!(!verify(key.pk_seed(), key.pk_root(), &changed_msg, &sig));
        // Receipt compares all 4008 bytes between the four build configurations.
        println!("VALID {} {}", opt.is_some(), hex::encode(sig));

        let mut wrong_root = *key.pk_root();
        wrong_root[0] ^= 1;
        let wrong_key = SigningKey::from_parts(sk_seed, pk_seed, wrong_root);
        let result = std::panic::catch_unwind(|| wrong_key.sign(&msg, opt));
        if cfg!(debug_assertions) {
            let panic = result.expect_err("checked signer must detect root mismatch");
            let message = panic.downcast_ref::<String>().map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied()).unwrap_or("");
            assert!(message.contains("Signing self-verification failed: root mismatch"),
                    "unexpected checked failure: {message}");
        } else {
            let sig = result.expect("release caller has no debug root guard");
            assert!(!verify(&pk_seed, &wrong_root, &msg, &sig));
            println!("WRONG_ROOT {} {}", opt.is_some(), hex::encode(sig));
        }
    }
}
