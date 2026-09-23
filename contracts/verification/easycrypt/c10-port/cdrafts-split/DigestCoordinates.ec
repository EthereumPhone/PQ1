(* External Q research: exact replay of all C10 digest coordinates requires
   equality of the first 161 bits. This is not multi-signature coverage. *)
require import AllCore List IntDiv BitEncoding FMap.
require import C10RawOracle RawForest C10RawGrind AuditComplete.
import BS2Int.

lemma chunk_injective (a b : bool list) offset width :
  0 <= offset => 0 <= width => offset + width <= size a =>
  offset + width <= size b =>
  bs2int (take width (drop offset a)) = bs2int (take width (drop offset b)) =>
  take width (drop offset a) = take width (drop offset b).
proof.
  move=> ho hw ha hb he.
  have hsa : size (take width (drop offset a)) = width by rewrite size_take 1:hw size_drop 1:ho; smt().
  have hsb : size (take width (drop offset b)) = width by rewrite size_take 1:hw size_drop 1:ho; smt().
  have hka := bs2intK (take width (drop offset a)).
  have hkb := bs2intK (take width (drop offset b)).
  smt().
qed.

op accepted_coordinates_unique (h : (raw_input,digest) fmap) =
  forall x y u v, h.[x] = Some u => h.[y] = Some v =>
    size u = 256 => size v = 256 => accept_digest u => accept_digest v =>
    (forall t, 0 <= t < 12 => forest_index u t = forest_index v t) =>
    hypertree_index u = hypertree_index v => x = y.

lemma chunk_nth (a b : bool list) offset width i :
  0 <= offset => offset <= i < offset + width =>
  take width (drop offset a) = take width (drop offset b) =>
  nth false a i = nth false b i.
proof.
  move=> ho hi he.
  have hn : nth false (take width (drop offset a)) (i-offset) =
    nth false (take width (drop offset b)) (i-offset) by rewrite he.
  move: hn; rewrite !nth_take 1,2,3,4:/# !nth_drop 1,2,3,4:/#; smt().
qed.

lemma accepted_coordinates_prefix (a b : bool list) :
  size a = 256 => size b = 256 =>
  (forall t, 0 <= t < 12 => forest_index a t = forest_index b t) =>
  take 11 (drop 132 a) = nseq 11 false =>
  take 11 (drop 132 b) = nseq 11 false =>
  hypertree_index a = hypertree_index b =>
  take 161 a = take 161 b.
proof.
  rewrite /forest_index /hypertree_index => ha hb hf hza hzb ht.
  apply (eq_from_nth false).
  + rewrite !size_take 1,2:/#; smt().
  move=> i hi.
  have hir : 0 <= i < 161 by move: hi; rewrite size_take 1:/# ha; smt().
  rewrite !nth_take 1,2,3,4:/#.
  case (i < 132) => hlow.
  + have ht0 : 0 <= i %/ 11 < 12 by smt(divz_ge0 ltz_divLR).
    have hc : take 11 (drop (11*(i%/11)) a) = take 11 (drop (11*(i%/11)) b).
    - apply chunk_injective; smt().
    apply (chunk_nth a b (11*(i%/11)) 11 i); smt(divz_eq modz_ge0 ltz_pmod).
  case (i < 143) => hmid.
  + apply (chunk_nth a b 132 11 i); smt().
  have hc : take 18 (drop 143 a) = take 18 (drop 143 b).
  + apply chunk_injective; smt().
  apply (chunk_nth a b 143 18 i); smt().
qed.

lemma prefix_unique_coordinates h :
  prefixes_unique 161 h => accepted_coordinates_unique h.
proof.
  rewrite /prefixes_unique /accepted_coordinates_unique /accept_digest.
  move=> hp x y u v hx hy hu hv hau hav hf ht.
  have he := accepted_coordinates_prefix u v hu hv hf hau hav ht.
  smt().
qed.
