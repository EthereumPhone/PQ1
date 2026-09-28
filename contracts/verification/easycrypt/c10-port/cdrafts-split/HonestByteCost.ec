(* All public calls in honest keygen/sign/encode/decode/verify are charged. *)
require import AllCore List.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RawSigner RawSignerCost.
require import HonestByteContext.

op honest_byte_public_budget = 3*signing_budget+520798.

lemma honest_byte_public_cost q0 :
  hoare [HonestByteError(Independent).run : size Independent.queries=q0 ==>
    q0<=size Independent.queries<=q0+honest_byte_public_budget].
proof.
  proc; seq 1 : (q0<=size Independent.queries<=q0+155135).
  + call (root_public_cost q0); auto; smt().
  seq 1 : (q0<=size Independent.queries<=q0+3*signing_budget+520027).
  + exists* Independent.queries; elim* => qs.
    call (signer_sign_public_cost (size qs)); auto; smt().
  sp 2; if; last by auto; rewrite /honest_byte_public_budget; smt().
  exists* Independent.queries; elim* => qs.
  call (signer_verify_public_cost (size qs)); auto; rewrite /honest_byte_public_budget; smt().
qed.

lemma honest_byte_budget_value : honest_byte_public_budget=30520798.
proof. by rewrite /honest_byte_public_budget /signing_budget. qed.
