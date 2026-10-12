// Host-only source adapter. No production source is edited.
use std::{env,fs,path::PathBuf};
fn main() {
    let base=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let tool=if base.ends_with("native") {base.parent().unwrap().to_path_buf()} else {base};
    let source=tool.join("../../../../secure/src/crypto.rs");
    println!("cargo:rerun-if-changed={}",source.display());
    println!("cargo:rerun-if-changed={}",tool.join("generate.rs").display());
    let all=fs::read_to_string(source).unwrap();
    fn part<'a>(s:&'a str,start:&str,end:&str)->&'a str {
        assert_eq!(s.matches(start).count(),1,"ambiguous source boundary");
        assert_eq!(s.matches(end).count(),1,"ambiguous source boundary");
        let a=s.find(start).unwrap();let b=s.find(end).unwrap();assert!(a<b);&s[a..b]
    }
    let body=part(&all,"const CFI_STEP_RATE_LIMIT:","/// Build the `(first_half, second_half)`").to_string()
       +part(&all,"pub fn c10_sign_verified_with_progress(","\n/// Provision a `WalletStore` backend");
    let output=PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let imports="use crate::sphincs_c10;\nuse crate::zeroize::Zeroize;\n";
    fs::write(output.join("native.rs"),format!("{imports}{body}")).unwrap();
    let mut lifted=body;
    let edits:&[(&str,&str,usize)]=&[
        ("progress: (fn(u8), fn(u8)),","progress: ((), ()),\n    effects: &mut crate::Effects,",3),
        ("        progress,\n","        progress,\n        effects,\n",2),
        ("use subtle::ConstantTimeEq;","use crate::subtle::ConstantTimeEq;",1),
        ("crate::sign_rate::signs_this_session()","crate::sign_rate::signs_this_session(effects)",4),
        ("crate::sign_rate::pre_sign()","crate::sign_rate::pre_sign(effects)",1),
        ("crate::sign_rate::pre_sign_forced(rate_receipt, request_digest)","crate::sign_rate::pre_sign_forced(effects, rate_receipt, request_digest)",1),
        ("crate::fi::CfiCounter::new()","crate::fi::CfiCounter::new(effects)",1),
        ("crate::fi::check_true_into_sentinel(||","crate::fi::check_true_into_sentinel(effects, ||",2),
        ("cfi.bump(","cfi.bump(effects, ",7),
        ("crate::rng_strong::fill(&mut","crate::rng_strong::fill(effects, &mut",3),
        (".zeroize()",".zeroize(effects)",14),
        ("crate::fi::zeroize_barrier()","crate::fi::zeroize_barrier(effects)",9),
        ("crate::fi::wait_random()","crate::fi::wait_random(effects)",2),
        ("sk.sign_with_shuffle(msg_hash","sk.sign_with_shuffle(effects, msg_hash",2),
        (".ct_eq(&sig_b[..])",".ct_eq(effects, &sig_b[..])",1),
        ("crate::nsc::zeroize_sensitive_state()","crate::nsc::zeroize_sensitive_state(effects)",3),
        ("sphincs_c10::verify(sk.pk_seed()","sphincs_c10::verify(effects, sk.pk_seed()",1),
        ("cfi.check_into_sentinel(CFI_EXPECTED)","cfi.check_into_sentinel(effects, CFI_EXPECTED)",1),
    ];
    for (before,after,count) in edits {
        assert_eq!(lifted.matches(before).count(),*count,"source adapter pattern drift: {before}");
        lifted=lifted.replace(before,after);
    }
    fs::write(output.join("production.rs"),format!("{imports}{lifted}")).unwrap();
}
