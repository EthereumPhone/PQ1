require import RawWrapper.
(* Abstract query-bearing schedule of the sequential secure wrapper.
   Environmental rate/entropy/sentinel/delay gates are explicit booleans, not
   a model of their hardware implementations. Other dependencies have separate
   cost obligations. This is not a cross-language whole-program refinement. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner.

module ControlWrapper (O : PrefixOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, valid, result;
    result <- None;
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

lemma wrapper_comparison (O <: PrefixOracle) :
  equiv [ControlWrapper(O).sign ~ RawWrapper(O).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; sp 1 1; if; first by auto.
  + by sim; auto.
  by auto.
qed.
