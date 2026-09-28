(* External next-batch research. No connection to the complete scheme yet. *)
require import AllCore List Distr DList DBool StdOrder IntDiv.
require import C10Bytes C10Randomizer C10RawOracle.
import RField RealOrder.

op prefix_hit (key : bool list) (queries : raw_input list) =
  has (fun x => take 32 x = bits_to_bytes key) queries.

lemma full_digest_atom_bound (r : bool list) :
  mu1 full_digest r <= (1%r / 2%r)^256.
proof.
  case (size r = 256) => hs.
  + by rewrite /full_digest -hs bool_word_mass.
  have hn : !(r \in full_digest).
  + rewrite /full_digest supp_dlist 1:// /=; smt().
  rewrite supportPn in hn.
  by rewrite hn; apply expr_ge0; smt().
qed.

lemma prefix_candidate key x : size key = 256 =>
  take 32 x = bits_to_bytes key => bytes_to_bits (take 32 x) = key.
proof.
  move=> hk ->; apply bits_bytes_roundtrip; by rewrite hk.
qed.

lemma fixed_prefix_list (queries : raw_input list) :
  mu full_digest (fun key => prefix_hit key queries) <=
    (size queries)%r * (1%r/2%r)^256.
proof.
  have hm := mu_mem_le_mu1 full_digest (map (fun x => bytes_to_bits (take 32 x)) queries)
    ((1%r/2%r)^256) full_digest_atom_bound.
  rewrite size_map in hm.
  have hsub : mu full_digest (fun key => prefix_hit key queries) <=
    mu full_digest (mem (map (fun x => bytes_to_bits (take 32 x)) queries)).
  + apply mu_le => key hk.
    rewrite /prefix_hit => /hasP [x [hx he]].
    apply mapP; exists x; split => //.
    apply eq_sym; apply (prefix_candidate key x) => //.
    by move: hk; rewrite /full_digest supp_dlist /=; smt().
  exact (ler_trans _ _ _ hsub hm).
qed.
