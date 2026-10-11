#![allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effects {
    pub rate_before: u32,
    pub rate_after: u32,
    pub rate_ok: bool,
    pub rate_sentinel: u32,
    pub verify_sentinel: u32,
    pub cfi_sentinel: u32,
    pub random: [u8; 16],
    pub shuffle_a: [u8; 32],
    pub shuffle_b: [u8; 32],
    pub fill_ok: [bool; 3],
    pub sig_a: [u8; 4008],
    pub sig_b: [u8; 4008],
    pub verify: bool,
    pub fills: usize,
    pub signs: usize,
    pub checks: usize,
    pub trace: [u32; 32],
    pub trace_len: usize,
    pub sign_calls: Vec<SignCall>,
    pub verify_calls: Vec<VerifyCall>,
    pub wipes: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignCall {
    pub key: [u8;32], pub seed: [u8;16], pub root: [u8;16], pub msg: [u8;32],
    pub opt: Option<[u8;16]>, pub shuffle: [u8;32], pub output: [u8;4008],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyCall {
    pub seed: [u8;16], pub root: [u8;16], pub msg: [u8;32], pub sig: [u8;4008],
}
pub fn event(e: &mut Effects, tag: u32) {
    e.trace[e.trace_len] = tag;
    e.trace_len += 1;
}
pub mod fi {
    use super::{Effects,event};
    pub const OK_SENTINEL: u32 = 0xA5A5_A5A5;
    pub struct CfiCounter { pub accum: u32 }
    impl CfiCounter {
        pub const INIT_VALUE: u32 = 0x1357_2468;
        pub fn new(e: &mut Effects) -> Self { event(e, 1); Self { accum: Self::INIT_VALUE } }
        pub fn bump(&mut self, e: &mut Effects, magic: u32) { event(e, magic); self.accum=self.accum.wrapping_add(magic); }
        pub fn check_into_sentinel(&self,e: &mut Effects,expected:u32)->u32 {
            event(e, 13);
            if self.accum==expected {e.cfi_sentinel} else {0}
        }
    }
    pub fn check_true_into_sentinel<F: FnMut()->bool>(e:&mut Effects,mut cond:F)->u32 {
        let tag=if e.checks==0 {2} else {12}; event(e,tag);
        let answer=if e.checks==0 {e.rate_sentinel} else {e.verify_sentinel}; e.checks+=1;
        if cond() {answer} else {0}
    }
    pub fn zeroize_barrier(e:&mut Effects) {event(e,7);}
    pub fn wait_random(e:&mut Effects) {event(e,9);}
}
#[macro_export]
macro_rules! cfi_expected {
    ($($step:expr),+ $(,)?) => { $crate::fi::CfiCounter::INIT_VALUE $(.wrapping_add($step))+ };
}
pub mod sign_rate {
    use super::{Effects,event};
    pub struct ForcedRateReceipt;
    pub fn signs_this_session(e:&mut Effects)->u32 {event(e,20);if e.trace_len==1 {e.rate_before} else {e.rate_after}}
    pub fn pre_sign(e:&mut Effects)->Result<(),()> {event(e,21);if e.rate_ok {Ok(())} else {Err(())}}
    pub fn pre_sign_forced(e:&mut Effects,_r:&ForcedRateReceipt,_d:&[u8;32])->Result<(),()> {pre_sign(e)}
}
pub mod rng_strong {
    use super::{Effects,event};
    pub fn fill<const N:usize>(e:&mut Effects,buf:&mut [u8;N])->Result<(),()> {
        event(e,3+e.fills as u32);
        for i in 0..N {buf[i]=if e.fills==0 {e.random[i]} else if e.fills==1 {e.shuffle_a[i]} else {e.shuffle_b[i]};}
        let ok=e.fill_ok[e.fills]; e.fills+=1;
        if ok {Ok(())} else {Err(())}
    }
}
pub mod nsc {
    pub fn zeroize_sensitive_state(e:&mut super::Effects) {super::event(e,14);}
}
pub mod zeroize {
    pub trait Zeroize {fn zeroize(&mut self,e:&mut super::Effects);}
    impl<const N:usize> Zeroize for [u8;N] {
        fn zeroize(&mut self,e:&mut super::Effects) {super::event(e,6);e.wipes.push(self.to_vec());*self=[0;N];}
    }
}
pub mod subtle {
    pub trait ConstantTimeEq {fn ct_eq(&self,e:&mut super::Effects,other:&Self)->bool;}
    impl ConstantTimeEq for [u8] {
        fn ct_eq(&self,e:&mut super::Effects,other:&Self)->bool {super::event(e,10);self==other}
    }
}
pub mod sphincs_c10 {
    pub mod params {pub const SIGNATURE_LEN:usize=4008;pub const N:usize=16;}
    pub mod shuffle {pub struct ShuffleSeed(pub [u8;32]);}
    pub struct SigningKey {pub sk_seed:[u8;32],pub pk_seed:[u8;16],pub pk_root:[u8;16]}
    impl SigningKey {
        pub fn sign_with_shuffle(&self,e:&mut super::Effects,msg:&[u8;32],opt:Option<&[u8;16]>,shuffle:&shuffle::ShuffleSeed,_progress:())->[u8;4008] {
            super::event(e,8);let sig=if e.signs==0 {e.sig_a} else {e.sig_b};e.signs+=1;
            e.sign_calls.push(super::SignCall {key:self.sk_seed,seed:self.pk_seed,root:self.pk_root,
                msg:*msg,opt:opt.copied(),shuffle:shuffle.0,output:sig});sig
        }
        pub fn pk_seed(&self)->&[u8;16] {&self.pk_seed}
        pub fn pk_root(&self)->&[u8;16] {&self.pk_root}
    }
    pub fn verify(e:&mut super::Effects,seed:&[u8;16],root:&[u8;16],msg:&[u8;32],sig:&[u8;4008])->bool {
        super::event(e,11);e.verify_calls.push(super::VerifyCall {seed:*seed,root:*root,msg:*msg,sig:*sig});e.verify
    }
}
pub mod production {
    include!(concat!(env!("OUT_DIR"), "/production.rs"));
}
pub use production::c10_sign_verified_with_progress;

