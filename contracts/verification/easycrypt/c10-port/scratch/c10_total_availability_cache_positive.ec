require import AllCore List Distr DList DBool FMap C10Randomizer.
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10Randomizer.
import RField RealOrder.
require import C10RawOracle MemoRejectCompletion.

module ControlledTotalAvailability = {
  var history : (raw_input,digest) fmap
  var calls : int
  var draws : int
  proc init() : unit = {
    history <- empty; calls <- 0; draws <- 0;
  }
  proc hash(x : raw_input) : digest = {
    var y : digest;
    calls <- calls + 1;
    if (x \notin history) {
      y <$ full_digest;
      history.[x] <- y;
      draws <- draws + 1;
    }
    return oget history.[x];
  }
}.

lemma checked accept xs : uniq xs =>
  ehoare[ControlledTotalAvailability.hash : (memo_reject_completion accept ControlledTotalAvailability.history xs)%xr ==>
    (memo_reject_completion accept ControlledTotalAvailability.history xs)%xr].
proof.
  move=> hu; proc; wp; skip => &hr.
  case (x{hr} \in ControlledTotalAvailability.history{hr}) => hx; first by [].
  rewrite /= (memo_reject_completion_step accept ControlledTotalAvailability.history{hr} xs x{hr} hu hx).
  by [].
qed.
