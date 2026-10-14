//! Execute the unchanged production-cfg source against scripted dependencies,
//! and compare its result and call sequence with the state-threaded source.
#![allow(dead_code)]
#[cfg(test)]
compile_error!("This check must execute the production cfg, never cfg(test)");
use secure_wrapper_model as model;
use std::cell::RefCell;
thread_local! { static WORLD: RefCell<Option<model::Effects>> = const { RefCell::new(None) }; }
fn effect<T>(f: impl FnOnce(&mut model::Effects) -> T) -> T {
    WORLD.with(|world| f(world.borrow_mut().as_mut().expect("installed fixture")))
}
pub mod fi {
    pub use super::model::fi::OK_SENTINEL;
    pub struct CfiCounter(super::model::fi::CfiCounter);
    impl CfiCounter {
        pub const INIT_VALUE: u32 = super::model::fi::CfiCounter::INIT_VALUE;
        pub fn new() -> Self { Self(super::effect(super::model::fi::CfiCounter::new)) }
        pub fn bump(&mut self, magic:u32) { super::effect(|e| self.0.bump(e,magic)); }
        pub fn check_into_sentinel(&self, expected:u32)->u32 {
            super::effect(|e| self.0.check_into_sentinel(e,expected))
        }
    }
    pub fn check_true_into_sentinel<F:FnMut()->bool>(cond:F)->u32 {
        super::effect(|e| super::model::fi::check_true_into_sentinel(e,cond))
    }
    pub fn zeroize_barrier() { super::effect(super::model::fi::zeroize_barrier); }
    pub fn wait_random() { super::effect(super::model::fi::wait_random); }
    pub fn delay_source_failed()->bool { super::effect(super::model::fi::delay_source_failed) }
}
#[macro_export]
macro_rules! cfi_expected {
    ($($step:expr),+ $(,)?) => { $crate::fi::CfiCounter::INIT_VALUE $(.wrapping_add($step))+ };
}
pub mod sign_rate {
    pub use super::model::sign_rate::ForcedRateReceipt;
    pub fn signs_this_session()->u32 {super::effect(super::model::sign_rate::signs_this_session)}
    pub fn pre_sign()->Result<(),()> {super::effect(super::model::sign_rate::pre_sign)}
    pub fn pre_sign_forced(r:&ForcedRateReceipt,d:&[u8;32])->Result<(),()> {
        super::effect(|e|super::model::sign_rate::pre_sign_forced(e,r,d))
    }
}
pub mod rng_strong {
    pub fn fill<const N:usize>(buf:&mut [u8;N])->Result<(),()> {
        super::effect(|e|super::model::rng_strong::fill(e,buf))
    }
}
pub mod nsc {
    pub fn zeroize_sensitive_state() {super::effect(super::model::nsc::zeroize_sensitive_state);}
}
pub mod zeroize {
    pub trait Zeroize {fn zeroize(&mut self);}
    impl<const N:usize> Zeroize for [u8;N] {
        fn zeroize(&mut self) {
            super::effect(|e|super::model::zeroize::Zeroize::zeroize(self,e));
        }
    }
}
extern crate self as subtle;
pub use model_subtle::ConstantTimeEq;
pub mod model_subtle {
    pub trait ConstantTimeEq {fn ct_eq(&self,other:&Self)->bool;}
    impl ConstantTimeEq for [u8] {
        fn ct_eq(&self,other:&Self)->bool {
            super::effect(|e|super::model::subtle::ConstantTimeEq::ct_eq(self,e,other))
        }
    }
}
pub mod sphincs_c10 {
    pub use super::model::sphincs_c10::{params,shuffle};
    pub struct SigningKey(pub super::model::sphincs_c10::SigningKey);
    impl SigningKey {
        pub fn pk_seed(&self)->&[u8;16] {self.0.pk_seed()}
        pub fn pk_root(&self)->&[u8;16] {self.0.pk_root()}
        pub fn sign_with_shuffle(&self,msg:&[u8;32],opt:Option<&[u8;16]>,shuffle:&shuffle::ShuffleSeed,_progress:fn(u8))->[u8;4008] {
            super::effect(|e| self.0.sign_with_shuffle(e,msg,opt,shuffle,()))
        }
    }
    pub fn verify(seed:&[u8;16],root:&[u8;16],msg:&[u8;32],sig:&[u8;4008])->bool {
        super::effect(|e|super::model::sphincs_c10::verify(e,seed,root,msg,sig))
    }
}
mod original { include!(concat!(env!("OUT_DIR"),"/native.rs")); }

fn fixture(bits:u32)->model::Effects {
    let b=|n:u32| bits & (1u32<<n) != 0u32;
    let mut other=[0x91;4008]; if !b(9) {other[4007]^=1;}
    model::Effects {
        rate_before:u32::MAX, rate_after:if b(1) {0} else {1}, rate_ok:b(0),
        rate_sentinel:if b(2) {fi::OK_SENTINEL} else {0xdead_beef},
        verify_sentinel:if b(11) {fi::OK_SENTINEL} else {0xdead_beef},
        cfi_sentinel:if b(12) {fi::OK_SENTINEL} else {0xdead_beef},
        delay_failed:!b(13),
        random:[if b(4) {0x31} else {0};16],
        shuffle_a:[if b(7) {0x52} else {0};32],
        shuffle_b:[if b(8) {0x73} else {0};32],
        fill_ok:[b(3),b(5),b(6)],sig_a:[0x91;4008],sig_b:other,verify:b(10),
        fills:0,signs:0,checks:0,trace:[0;32],trace_len:0,sign_calls:Vec::new(),verify_calls:Vec::new(),wipes:Vec::new(),
    }
}
fn check(initial:model::Effects,expected_ok:bool,expected_relock:bool) {
    let key=model::sphincs_c10::SigningKey {sk_seed:[1;32],pk_seed:[2;16],pk_root:[3;16]};
    let expected=initial.clone();
    let mut lifted=initial.clone();
    let lifted_result=model::c10_sign_verified_with_progress(&key,&[4;32],((),()),&mut lifted);
    WORLD.with(|cell|*cell.borrow_mut()=Some(initial));
    let native_result=original::c10_sign_verified_with_progress(&sphincs_c10::SigningKey(key),&[4;32],(|_|{},|_|{}));
    let native=WORLD.with(|cell|cell.borrow_mut().take().unwrap());
    assert_eq!(native_result,lifted_result,"source transformation changed returned bytes or refusal");
    assert_eq!(native,lifted,"source transformation changed effect order or data");
    assert_eq!(native_result.is_ok(),expected_ok,"wrong independent release outcome");
    assert_eq!(native.trace[..native.trace_len].contains(&14),expected_relock,"wrong relock classification");
    for (i,call) in native.sign_calls.iter().enumerate() {
        assert_eq!(call.key,[1;32]); assert_eq!(call.seed,[2;16]); assert_eq!(call.root,[3;16]);
        assert_eq!(call.msg,[4;32]); assert_eq!(call.opt,Some(expected.random));
        assert_eq!(call.shuffle,if i==0 {expected.shuffle_a} else {expected.shuffle_b});
    }
    for call in &native.verify_calls {
        assert_eq!(call.seed,[2;16]); assert_eq!(call.root,[3;16]);
        assert_eq!(call.msg,[4;32]); assert_eq!(call.sig,expected.sig_a);
    }
    if native.fills>0 {
        assert_eq!(native.wipes.last(),Some(&expected.random.to_vec()),"last wipe must clear OptRand");
        assert_eq!(native.trace[native.trace_len-1],7,"cleanup barrier must be last");
    }
    if expected_relock {assert_eq!(&native.trace[native.trace_len-3..native.trace_len],&[14,6,7]);}
    if expected_ok {
        assert_eq!(native_result.unwrap(),native.sig_a);assert_eq!(native.signs,2);assert_eq!(native.fills,3);
        assert!(!expected.delay_failed);
        assert_eq!(&native.trace[native.trace_len-3..native.trace_len],&[15,6,7]);
    }
    if native.trace[..native.trace_len].contains(&15) {
        assert_eq!(native_result.is_err(),expected.delay_failed,"delay failure must refuse release");
        assert!(!expected_relock,"delay-source refusal must not relock");
        assert_eq!(&native.trace[native.trace_len-3..native.trace_len],&[15,6,7]);
    }
}
fn main() {
    const ALL:u32=(1<<14)-1;
    const FAULT_GUARDS:u32=(1<<13)-1;
    for bits in 0..=ALL {
        let ready=bits & ((1<<9)-1) == (1<<9)-1;
        check(fixture(bits),bits==ALL,ready && bits & FAULT_GUARDS != FAULT_GUARDS);
    }
    for i in 0..4008 {
        let mut f=fixture(ALL);f.sig_b[i]^=1;check(f,false,true);
    }
    // A single contributing byte anywhere in each entropy buffer must suffice.
    for index in 0..32 {
        let mut f=fixture(ALL);f.random=[0;16];f.random[index%16]=1;
        f.shuffle_a=[0;32];f.shuffle_a[index]=2;f.shuffle_b=[0;32];f.shuffle_b[31-index]=4;
        check(f,true,false);
    }
    println!("PASS: 16384 guard combinations, 4008 mismatch positions, 32 sparse-entropy cases; production cfg; native/lifted result and effect equality");
}
