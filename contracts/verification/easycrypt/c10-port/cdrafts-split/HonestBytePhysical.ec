(* A complete-context secret-prefix charge for honest serialized correctness. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import HonestByteContext HonestByteCost.
import RealOrder.

lemma physical_honest_byte_error &m :
  Pr[RealGame(HonestByteError).run() @ &m : res] <=
    honest_byte_public_budget%r * (1%r/2%r)^256.
proof.
  have hb : hoare [HonestByteError(Independent).run : Independent.queries=[] ==>
    size Independent.queries<=honest_byte_public_budget].
  + conseq (honest_byte_public_cost 0); smt().
  have h := physical_to_independent HonestByteError honest_byte_public_budget &m _ _ hb.
  + move=> O hh hd; exact (honest_byte_context_lossless O hh hd).
  + rewrite honest_byte_budget_value; smt().
  move: h; rewrite (independent_honest_byte_error_zero &m) /=; smt().
qed.

lemma physical_honest_byte_error_concrete &m :
  Pr[RealGame(HonestByteError).run() @ &m : res] <= 30520798%r * (1%r/2%r)^256.
proof. have h := physical_honest_byte_error &m; move: h; rewrite honest_byte_budget_value; smt(). qed.
