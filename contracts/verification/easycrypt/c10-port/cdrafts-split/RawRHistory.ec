(* A fresh 128-bit R can revisit an arbitrary prior raw-query history.
   The charge counts every prior raw input; no history-independence premise. *)
require import AllCore List Distr DList.
require import C10RawOracle C10Bytes C10HashDomains C10Randomizer C10RawGrind.

op raw_r (x : raw_input) = bytes_to_bits (take 16 (drop 64 x)).

lemma raw_r_recovers seed root message r :
  size seed = 32 => size root = 32 => size r = 128 =>
  raw_r (hmsg_input seed root (bits_to_bytes r ++ nseq 16 0) message) = r.
proof.
  move=> hs hr hR.
  have hb : size (bits_to_bytes r) = 16 by rewrite bits_to_bytes_size hR.
  by rewrite /raw_r /hmsg_input -!catA !drop_cat hs hr hb /= drop0
    take_cat hb /= take0 cats0 bits_bytes_roundtrip 1:hR 1://.
qed.

lemma hmsg_prior_history seed root message (queries : raw_input list) :
  size seed = 32 => size root = 32 =>
  mu randomizer (fun r => hmsg_input seed root (bits_to_bytes r ++ nseq 16 0) message \in queries)
    <= (size queries)%r * (1%r/2%r)^128.
proof.
  move=> hs hr.
  have hb := randomizer_history_bound (map raw_r queries).
  rewrite size_map in hb.
  have he : mu randomizer (fun r =>
      hmsg_input seed root (bits_to_bytes r ++ nseq 16 0) message \in queries)
    <= mu randomizer (mem (map raw_r queries)).
  + apply mu_le => r hR hx.
    have hsize : size r = 128 by move: hR; rewrite /randomizer supp_dlist /=; smt().
    apply/mapP; exists (hmsg_input seed root (bits_to_bytes r ++ nseq 16 0) message).
    by split => //; rewrite raw_r_recovers.
  smt().
qed.

lemma fresh_derived_hmsg_prior_history seed root message (queries : raw_input list) :
  size seed = 32 => size root = 32 =>
  mu full_digest (fun rd => hmsg_input seed root (compact_r rd ++ nseq 16 0) message \in queries)
    <= (size queries)%r * (1%r/2%r)^128.
proof.
  move=> hs hr.
  have hb := hmsg_prior_history seed root message queries hs hr.
  rewrite -truncate_uniform dmapE /compact_r /(\o) in hb.
  exact hb.
qed.
