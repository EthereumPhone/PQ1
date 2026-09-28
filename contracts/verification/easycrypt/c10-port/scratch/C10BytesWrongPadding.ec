(* Semantic negative control: this false claim must be rejected. *)
require import AllCore List C10Bytes.
lemma wrong_padding (node : bool list) (c : C10Counter.counter) :
  size node = 128 => size (payload node c) = 63.
proof. move=> hn; rewrite payload_size 1:hn. trivial. qed.
