(* Semantic negative control: this false claim must be rejected. *)
require import AllCore List C10Counter.
lemma wrong_cardinality : size enum = 10000000.
proof. rewrite cardinality. trivial. qed.
