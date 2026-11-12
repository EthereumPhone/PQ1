// Fixed evaluator inputs, shared verbatim by the host golden generator and the kit bench
// (both `include!` this file). Changing anything here invalidates every row of results.tsv.
pub const SK_SEED: [u8; 32] = *b"c10-autoresearch fixed sk_seed!!";
pub const PK_SEED: [u8; 16] = *b"c10-ar pk_seed!!";
pub const OPT_RAND: [u8; 16] = *b"c10-ar opt_rand!";
pub const SHUFFLE_A: [u8; 32] = *b"c10-autoresearch shuffle seed A!";
pub const SHUFFLE_B: [u8; 32] = *b"c10-autoresearch shuffle seed B!";
pub const MSG0: [u8; 32] = *b"c10-autoresearch message zero..!";
pub const MSG1: [u8; 32] = *b"c10-autoresearch message one...!";
