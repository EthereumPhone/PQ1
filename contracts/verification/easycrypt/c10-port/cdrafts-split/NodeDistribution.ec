(* Exact ideal node projection and mass bound; no SHA-256 assumption. *)
require import AllCore List Distr DList DBool IntDiv StdOrder.
require import C10RawOracle C10Bytes C10Randomizer RawKeygen.
import RField RealOrder.

lemma node_preimage d x : size d=256 => node d=x => truncate_r d=bytes_to_bits x.
proof.
  move=> hd hx; have hn := node_exact d hd.
  have ht : size (truncate_r d)=128 by rewrite /truncate_r size_drop 1:// hd.
  have he : bytes_to_bits (bits_to_bytes (truncate_r d))=truncate_r d
    by apply bits_bytes_roundtrip; rewrite ht.
  move: hn hx; rewrite /C10RawGrind.compact_r; smt().
qed.

lemma node_draw_distribution :
  dmap full_digest node = dmap randomizer bits_to_bytes.
proof.
  rewrite -truncate_uniform dmap_comp.
  apply eq_dmap_in => d hd.
  rewrite /(\o); have hs : size d=256 by move: hd; rewrite /full_digest supp_dlist /=; smt().
  by rewrite (node_exact d hs) /C10RawGrind.compact_r.
qed.

lemma node_history_mass (nodes : raw_input list) :
  mu full_digest (fun d => mem nodes (node d)) <= (size nodes)%r*(1%r/2%r)^128.
proof.
  have hm := randomizer_history_bound (map bytes_to_bits nodes).
  rewrite size_map -truncate_uniform dmapE /(\o) in hm.
  have hsub : mu full_digest (fun d => mem nodes (node d)) <=
    mu full_digest (fun d => mem (map bytes_to_bits nodes) (truncate_r d)).
  + apply mu_le => d hd hn.
    apply mapP; exists (node d); split; first exact hn.
    have hs : size d=256 by move: hd; rewrite /full_digest supp_dlist /=; smt().
    smt(node_preimage).
  exact (ler_trans _ _ _ hsub hm).
qed.

lemma node_atom_mass x :
  mu full_digest (fun d => node d=x) <= (1%r/2%r)^128.
proof. have h := node_history_mass [x]; move: h; rewrite /=; smt(). qed.
