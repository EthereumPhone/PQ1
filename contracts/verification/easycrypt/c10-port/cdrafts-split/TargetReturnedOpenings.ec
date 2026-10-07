(* Returned-coordinate membership survives later memoized public queries. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains RawKeygen RawForest RawSigner.
require import PersistentGrind ExposureLog ExposureCoverage ReturnedPrivateInputs.
require import TargetForestOpenings TargetSignerOpenings.

lemma returned_input_extends h0 h seed root entries key :
  extends h0 h => returned_private_input h0 seed root entries key =>
  returned_private_input h seed root entries key.
proof. rewrite /extends /returned_private_input /logged_digest; smt(). qed.

lemma signature_opening_returned h seed root message signature input entries :
  signature_opens_input h seed root message signature input =>
  returned_private_input h seed root (rcons entries (message,signature)) input.
proof.
  rewrite /signature_opens_input /forest_opens_input /returned_private_input /logged_digest.
  move=> [d [hd [tree [ht hi]]]]; exists d tree; split; last smt().
  exists message signature; smt(mem_rcons).
qed.

lemma returned_input_rcons h seed root entries entry key :
  returned_private_input h seed root entries key =>
  returned_private_input h seed root (rcons entries entry) key.
proof. rewrite /returned_private_input /logged_digest; smt(mem_rcons). qed.
