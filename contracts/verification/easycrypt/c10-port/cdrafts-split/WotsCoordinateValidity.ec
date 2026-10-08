(* Every coordinate in the exact finite universe satisfies the chain encoding bounds. *)
require import AllCore List IntDiv.
require import WotsCoordinateUniverse ObservedValueOpening.

op valid_wots_coordinate (c : wots_coordinate) = valid_chain_address c.`1 c.`2 c.`3 c.`4 /\ 0<=c.`5<7.
lemma wots_keys_valid (key : int * int * int) :
  mem wots_keys key => 0<=key.`1<2 /\ 0<=key.`2<512 /\ 0<=key.`3<512.
proof.
  rewrite /wots_keys mem_cat; move=> [hb|ht].
  + move: hb; rewrite mapP; move=> [n [hn ->]]; move: hn; rewrite mem_range /=;
      smt(divz_ge0 ltz_divLR modz_ge0 ltz_pmod).
  move: ht; rewrite mapP; move=> [n [hn ->]]; move: hn; rewrite mem_range /=; smt().
qed.
lemma key_cuts_valid key c :
  mem (key_cuts key) c =>
  (c.`1,c.`2,c.`3)=key /\ 0<=c.`4<43 /\ 0<=c.`5<7.
proof.
  rewrite /key_cuts -flattenP; move=> [row [/mapP [i [hi ->]] /mapP [cut [hc ->]]]].
  move: hi hc; rewrite !mem_range /=; smt().
qed.
lemma wots_coordinates_valid c : mem wots_coordinates c => valid_wots_coordinate c.
proof.
  rewrite /wots_coordinates -flattenP; move=> [row [/mapP [key [hk ->]] hc]].
  have hv:=wots_keys_valid key hk; have hc':=key_cuts_valid key c hc.
  rewrite /valid_wots_coordinate /valid_chain_address; smt().
qed.
