(* Each admitted wrapper attempt includes up to TWO complete signing calls
   and ONE internal verification, including attempts that refuse to release. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid.
require import RawSigner RawSignerCost.
(* Abstract query-bearing schedule of the sequential secure wrapper.
   Environmental rate/entropy/sentinel/delay gates are explicit booleans, not
   a model of their hardware implementations. Other dependencies have separate
   cost obligations. This is not a cross-language whole-program refinement. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner.

module RawWrapper (O : PrefixOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, valid, result;
    Shared.calls <- 0; result <- None;
    if (ready) {
      first <@ RawSigner(O).sign(seed,root,random,message,shuffle_a);
      if (first <> None) {
        second <@ RawSigner(O).sign(seed,root,random,message,shuffle_b);
        if (second <> None /\ first = second) {
          valid <@ RawSigner(O).verify(seed,root,message,oget first);
          if (valid /\ final_guard) { result <- first; }
        }
      }
    }
    return result;
  }
}.


op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+771.
op wrapper_public_budget : int = 2*(3*signing_budget+364892)+771.

(* These identities expose the two-sign/one-verify charge to consumers and
   make a changed charge fail before an expensive solver fallback. *)


